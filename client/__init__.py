#!/usr/bin/env python
# -*- encoding: utf-8 -*-
from __future__ import print_function

import argparse
import base64
import getpass
import json
import os
import platform
import select
import sys
import traceback
from socket import gaierror

try:
    from httplib import HTTPConnection, HTTPSConnection  # Py<=3
    from urllib import urlencode
    from socket import error as ConnectionError
    input = raw_input
except ImportError:
    from http.client import HTTPConnection, HTTPSConnection # Py>=3
    from urllib.parse import urlencode


_DEBUG = False
_CACHED_ATTR = '_cache'
__VERSION__ = '0.8.0'
GET, POST, PUT = 'GET', 'POST', 'PUT'

_ANONYMOUS_USER_AGENT = 'anonymous'
_HOST_ENV_VALUE = 'NOTEIT_HOST'
_TOKEN_PATH = os.path.expanduser('~/.noteit/noteit.tkn')
_TOKEN_ENV_VALUE = 'NOTEIT_TOKEN'
_CONF_LINK = 'https://raw.githubusercontent.com/Krukov/noteit/master/.conf.json'
_USER_AGENT_HEADER = 'User-Agent'
_AUTH_HEADER = 'Authorization'
_TOKEN_HEADER = 'Authorization'
_URLS_MAP = {
    'create_note': '/',
    'drop_tokens': '/drop_tokens',
    'get_token': '/get_token',
    'get_notes': '/',
    'get_note': '/{i}',
    'report': '/report',
}


class AuthenticationError(Exception):
    """Error raising at wrong password """
    pass


class ServerError(Exception):
    """Error if server is retunr 50x status"""
    pass


def cached_function(func):
    """Decorator that chache function result at first call and return cached result other calls """

    def _func(*args, **kwargs):
        if hasattr(func, _CACHED_ATTR) and getattr(func, _CACHED_ATTR) is not None and not _DEBUG:
            return getattr(func, _CACHED_ATTR)
        result = func(*args, **kwargs)
        setattr(func, _CACHED_ATTR, result)
        return result
    return _func


def display(out, stdout=sys.stdout):
    stdout.write('>' + '\n>'.join(out.splitlines()) + '\n')


@cached_function
def get_version():
    """Return version of client"""
    return __VERSION__


def get_notes():
    """Return user's notes as string"""
    notes, status = do_request(_URLS_MAP['get_notes'])
    if status == 200:
        return notes
    elif status == 204:
        return "You haven't notes"
    raise Exception('Error at get_notes method: {} {}'.format(status, notes))


def get_note(number):
    """Return user note of given number (number in [1..5])"""
    note, status = do_request(_URLS_MAP['get_note'].format(i=number))
    if status == 200:
        return note
    elif status == 404:
        return "No note with given number"
    raise Exception('Error at get_note method: {} {}'.format(status, note))


def get_last_note():
    """Return last saved note"""
    return get_note(1)


def create_note(note):
    """Make request for saving note"""
    _, status = do_request(_URLS_MAP['get_notes'], method=POST, data={'note': note})
    if status == 201:
        return 'Note saved'
    raise Exception('Error at create_note method: {} {}'.format(status, _))


def report(tb):
    """Make traceback and etc. to server""" 
    data = {'traceback': tb}
    try:
        _, status = do_request(_URLS_MAP['report'], method=POST, data=data)
    except Exception:
        data = urlencode(data).encode('ascii')
        conn = _get_connection()
        try:
            headers = _get_headers()
        except Exception:
            headers = {}
        headers.update({"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"})
        conn.request(POST, _URLS_MAP['report'], body=data, headers=headers)
        status = conn.getresponse().status

    if status in range(200, 204):
        return 'Thanks you for reporting...'
    return 'Error: can not report error'


def drop_tokens():
    """Make request to recreate user's tokens"""
    _, status = do_request(_URLS_MAP['drop_tokens'], method=POST)
    if status == 202:
        return 'Tokens are dropped'
    raise Exception('Error at drop_token method: {} {}'.format(status, _))


def _get_token():
    """Send request to get token and return it at success"""
    token, status = do_request(_URLS_MAP['get_token'], method=POST)
    if status == 201:
        return token


def _get_from_stdin(text):
    """communication with stdin"""
    return input(text)


def registration(question_location):
    """Asks user for answer the question at given location and send result """
    prompt = "If you are not registered yet, answer the question '{0}': ".format(do_request(question_location)[0])
    answer = _get_from_stdin(prompt)
    response, status = do_request(question_location, POST, {'answer': answer})
    if status == 202:
        return True
    return False


def retry(response):
    """Retry last response"""
    return do_request(response._attrs[0], *response._attrs[1], **response._attrs[2])


@cached_function
def _get_password():
    """Return password from argument or asks user for it"""
    return get_options().password or getpass.getpass('Input your password: ')


@cached_function
def _get_user():
    """Return user from argument or asks user for it"""
    return get_options().user or _get_from_stdin('Input username: ')


def _get_credentials():
    """Return username and password"""
    return _get_user(), _get_password()


def _get_user_agent():
    """Return User-Agent for request header"""
    if get_options().anon:
        return _ANONYMOUS_USER_AGENT
    return _generate_user_agent_with_info()


@cached_function
def _generate_user_agent_with_info():
    """Generete User-Agent with enveroupment info"""
    return '; '.join([
        platform.platform(),
        platform.python_implementation(),
        platform.python_version(),
        'VERSION: {}'.format(get_version()),
    ])


@cached_function
def _get_token_from_system():
    """Return tocken from file"""
    if _TOKEN_ENV_VALUE in os.environ:
        return os.environ.get(_TOKEN_ENV_VALUE)
    if os.path.isfile(_TOKEN_PATH):
        with open(_TOKEN_PATH) as _file:
            return _file.read().strip()


def _save_token(token):
    """Save tocken to file"""
    if not os.path.exists(os.path.dirname(_TOKEN_PATH)):
        os.makedirs(os.path.dirname(_TOKEN_PATH))
    with open(_TOKEN_PATH, 'w') as token_file:
        token_file.write(token)
    return True


def _delete_token():
    """Delete file with token"""
    if os.path.exists(_TOKEN_PATH):
        os.remove(_TOKEN_PATH)


def _get_encoding_basic_credentials():
    """Return value of header for Basic Authentication"""
    return b'basic ' + base64.b64encode(':'.join(_get_credentials()).encode('ascii'))


def _get_headers():
    """Return dict of headers for request"""
    headers = {
        _USER_AGENT_HEADER: _get_user_agent(),
    }
    if not get_options().user and not get_options().ignore and _get_token_from_system():
        headers[_TOKEN_HEADER] = b'token ' + _get_token_from_system().encode('ascii')
    else:
        headers[_AUTH_HEADER] = _get_encoding_basic_credentials()
    return headers


def do_request(path, *args, **kwargs):
    """Make request and handle response"""
    kwargs.setdefault('headers', {}).update(_get_headers())
    response = _make_request(path, *args, **kwargs)
    response._attrs = path, args, kwargs
    return _response_handler(response)


def _response_handler(response):
    """Handle response status"""
    if response.status in [401, ]:
        raise AuthenticationError
    elif response.status > 500:
        raise ServerError
    elif response.status in [301, 302, 303, 307]:
        if registration(response.getheader('Location')):
            return retry(response)
        raise AuthenticationError
    return response.read().decode('ascii'), response.status


@cached_function
def _get_connection():
    """Create and return conection with host"""
    host = get_options().host
    if host.startswith('https://'):
        host = host[8:]
        connection = HTTPSConnection
    else:
        connection = HTTPConnection
        host = host.replace('http://', '')
    return connection(host)


def _make_request(url, method=GET, data=None, headers=None):
    """Generate request and send it"""
    headers = headers or {}
    method = method.upper()
    conn = _get_connection()
    if data:
        data = urlencode(data).encode('ascii')
        if method == GET:
            url = '?'.join([url, data or ''])

    if method in [POST]:
        headers.update({"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"})
    conn.request(method, url, body=data, headers=headers)
    return conn.getresponse()


@cached_function
def _get_host():
    host = os.environ.get('NOTEIT_HOST')
    if not host:
        try:
            conn = HTTPSConnection(_CONF_LINK.split('/', 3)[2])
            conn.request(GET, _CONF_LINK)
            request = conn.getresponse()
            conf_from_git = request.read().decode('ascii')
            host = json.loads(conf_from_git)['host']
        except gaierror:
            sys.exit("Noteit require internet connection")
        except Exception:
            sys.exit("Something went wrong, we will fix it as soon as possible")
    return host


def _get_from_pipe():
    try:
        is_in_pipe = select.select([sys.stdin], [], [], 0.0)[0]
    except select.error:
        return
    else:
        return sys.stdin.read() if is_in_pipe else None


def get_options_parser():
    """Arguments deffinition"""
    parser = argparse.ArgumentParser(description='Tool for creating notes', prog='noteit')
    
    parser.add_argument('--version', action='version', version='%(prog)s ' + get_version(),
                        help='displays the current version of %(prog)s and exit')

    parser.add_argument('note', metavar='NOTE', type=str, nargs='*', default=_get_from_pipe(),
                        help='New Note')
    parser.add_argument('-c', '--create', type=str, nargs='*', help='Create note')

    parser.add_argument('-u', '--user', help='username', type=str)
    parser.add_argument('-p', '--password', help='password', type=str)
    parser.add_argument('--host', default=_get_host(), help='host (default: %s)' % _get_host(), type=str)

    parser.add_argument('-a', '--all', help='display all notes',
                        action='store_true')
    parser.add_argument('-l', '--last', help='display only last note',
                        action='store_true')
    parser.add_argument('-n', '--num-note', help='display only note with given number', type=int)
    parser.add_argument('-d', '--drop-tokens', help='make all you tokens invalid',
                        action='store_true')

    parser.add_argument('--do-not-save', help='disable to save token locally',
                        action='store_true')
    parser.add_argument('-i', '--ignore', help='if set, client will skip local token',
                        action='store_true')

    parser.add_argument('--anon', help='do not add OS and other info to agent header',
                        action='store_true')
    parser.add_argument('-r', '--report', help='report error', action='store_true')

    return parser


@cached_function
def get_options():
    """Return parsed arguments"""
    return get_options_parser().parse_args()


def main():
    """Main"""
    options = get_options()
    try:
        
        if options.drop_tokens:
            display(drop_tokens())
            _delete_token()

        if not options.do_not_save:
            token = _get_token()
            if token:
                _save_token(token)

        if options.note or options.create:
            note = options.note or options.create
            display(create_note(' '.join(note) if isinstance(note, (list, tuple)) else note))
        
        if options.all:
            display(get_notes())
        elif options.num_note:
            display(get_note(options.num_note))
        elif options.last:
            display(get_last_note())
        elif not (options.note or options.create):
            display(get_notes())

    except KeyboardInterrupt:
        display('\n')
    except AuthenticationError:
        display('Error at authentication. Maybe given username is busy')
    except ServerError:
        display('Sorry we have got server error. Please, try again later')
    except ConnectionError:
        display('Something wrong with connection, check your internet or try again later')
    except Exception:
        if _DEBUG:
            raise
        if not options.report:
            sys.exit('Something went wrong! You can sent report to us with "-r" option')
        print(report(traceback.format_exc()))


if __name__ == '__main__':
    main()
