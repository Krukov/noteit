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
    from http.client import HTTPConnection, HTTPSConnection  # Py>=3
    from urllib.parse import urlencode


_DEBUG = False
_CACHED_ATTR = '_cache'
_PASS_CACHE_KWARG = 'not_cached'
__VERSION__ = '0.8.11'
GET, POST, PUT = 'GET', 'POST', 'PUT'

_ANONYMOUS_USER_AGENT = 'anonymous'
_HOST_ENV_VALUE = 'NOTEIT_HOST'
_TOKEN_PATH = os.path.expanduser('~/.noteit/noteit.tkn')
_TOKEN_ENV_VALUE = 'NOTEIT_TOKEN'
_CONF_LINK = 'https://raw.githubusercontent.com/Krukov/noteit/stable/.conf.json'
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
        force = kwargs.pop(_PASS_CACHE_KWARG, False)
        if not hasattr(func, _CACHED_ATTR) or force or _is_debug():
            result = func(*args, **kwargs)
            if result is not None:
                setattr(func, _CACHED_ATTR, result)
            return result
        return getattr(func, _CACHED_ATTR)
    return _func


def display(out, stdout=sys.stdout):
    stdout.write(out + '\n')


def get_notes():
    """Return user's notes as string"""
    notes, status = do_request(_URLS_MAP['get_notes'])
    if status == 200:
        return '>' + '\n>'.join(notes.splitlines())
    elif status == 204:
        return "You do not have notes"
    raise Exception('Error at get_notes method: {} {}'.format(status, notes))


def get_note(number):
    """Return user note of given number (number in [1..5])"""
    note, status = do_request(_URLS_MAP['get_note'].format(i=number))
    if status == 200:
        return note
    elif status == 404:
        return "No note with requested number"
    raise Exception('Error at get_note method: {} {}'.format(status, note))


def get_note_by_alias(alias):
    """Return user note of given number (number in [1..5])"""
    note, status = do_request(_URLS_MAP['get_notes'], data={'alias': alias})
    if status == 200:
        return note
    elif status == 404:
        return "No note with requested alias"
    raise Exception('Error at get_note_by_alias method: {} {}'.format(status, note))


def get_last_note():
    """Return last saved note"""
    return get_note(1)


def create_note(note, alias=None):
    """Make request for saving note"""
    data = {'note': note}
    if alias:
        data['alias'] = alias
    _, status = do_request(_URLS_MAP['get_notes'], method=POST, data=data)
    if status == 201:
        return 'Saved'
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
        return 'Thank you for reporting...'
    return 'Error: can not be reported'


def drop_tokens():
    """Make request to recreate user's tokens"""
    _, status = do_request(_URLS_MAP['drop_tokens'], method=POST)
    if status == 202:
        return 'Tokens are deleted'
    raise Exception('Error at drop_token method: {} {}'.format(status, _))


def _get_token():
    """Send request to get token and return it at success"""
    token, status = do_request(_URLS_MAP['get_token'], method=POST)
    if status == 201:
        return token


def registration(question_location):
    """Asks user for answer the question at given location and send result """
    prompt = "If you are not registered yet, please answer the question '{0}': ".format(do_request(question_location)[0])
    answer = _get_from_stdin(prompt)
    response, status = do_request(question_location, POST, {'answer': answer})
    if status == 202:
        return True
    return False


# END API METHODS

@cached_function
def get_version():
    """Return version of client"""
    return __VERSION__


def do_request(path, *args, **kwargs):
    """Make request and handle response"""
    kwargs.setdefault('headers', {}).update(_get_headers())
    response = _make_request(path, *args, **kwargs)
    response._attrs = path, args, kwargs  # for retrying
    return _response_handler(response)


def retry(response):
    """Retry last response"""
    return do_request(response._attrs[0], *response._attrs[1], **response._attrs[2])


def _response_handler(response):
    """Handle response status"""
    response_body = response.read().decode('ascii')
    response.close()
    if response.status in [401, ]:
        raise AuthenticationError
    elif response.status > 500:
        raise ServerError
    elif response.status in [301, 302, 303, 307] and response._method != POST:
        if registration(response.getheader('Location')):
            return retry(response)
        raise AuthenticationError
    return response_body, response.status


@cached_function
def _get_connection():
    """Create and return conection with host"""
    host = _get_host()
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
            url = '?'.join([url, data.decode('ascii') or ''])

    if method in [POST]:
        headers.update({"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"})
    conn.request(method, url, body=data, headers=headers)

    return conn.getresponse()


@cached_function
def _get_host():
    """Return notiit backend host"""
    host = get_options().host or os.environ.get('NOTEIT_HOST')
    if not host:
        if _is_debug():
            return 'localhost:8000'
        #  Get host from .conf file from repo
        try:
            conn = HTTPSConnection(_CONF_LINK.split('/', 3)[2])
            conn.request(GET, _CONF_LINK)
            request = conn.getresponse()
            conf_from_git = request.read().decode('ascii')
            host = json.loads(conf_from_git)['host']
        except gaierror:
            sys.exit("Noteit requires internet connection")
    return host


def _get_password():
    """Return password from argument or asks user for it"""
    return get_options().password or getpass.getpass('Input your password: ')


def _get_user():
    """Return user from argument or asks user for it"""
    return get_options().user or _get_from_stdin('Input username: ')


@cached_function
def _get_credentials():
    """Return username and password"""
    return _get_user(), _get_password()


@cached_function
def _get_user_agent():
    """Return User-Agent for request header"""
    if get_options().anon:
        return _ANONYMOUS_USER_AGENT
    return _generate_user_agent_with_info()


def _generate_user_agent_with_info():
    """Generete User-Agent with enveroupment info"""
    return '; '.join([
        platform.platform(),
        platform.python_implementation(),
        platform.python_version(),
        'VERSION: {}'.format(get_version()),
    ])


def _get_token_from_system():
    """Return token from file"""
    if _TOKEN_ENV_VALUE in os.environ:
        return os.environ.get(_TOKEN_ENV_VALUE)
    if os.path.isfile(_TOKEN_PATH):
        with open(_TOKEN_PATH) as _file:
            return _file.read().strip()


def _save_token(token):
    """Save token to file"""
    if not os.path.exists(os.path.dirname(_TOKEN_PATH)):
        os.makedirs(os.path.dirname(_TOKEN_PATH))
    with open(_TOKEN_PATH, 'w') as token_file:
        token_file.write(token)
    return True


def _delete_token():
    """Delete file with token"""
    if os.path.exists(_TOKEN_PATH):
        os.remove(_TOKEN_PATH)


@cached_function
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


def _get_from_stdin(text):
    """communication with stdin"""
    return input(text)


def _get_from_pipe():
    """Read stdin if pipe is open | """
    try:
        is_in_pipe = select.select([sys.stdin], [], [], 0.0)[0]
    except select.error:
        return
    else:
        return sys.stdin.read() if is_in_pipe else None


def _is_debug():
    if _DEBUG:
        return True
    return '--debug' in sys.argv


def get_options_parser():
    """Arguments definition"""
    parser = argparse.ArgumentParser(description='Tool for creating notes', prog='noteit')
    
    parser.add_argument('--version', action='version', version='%(prog)s ' + get_version(),
                        help='displays the current version of %(prog)s and exit')
    parser.add_argument('--debug', action='store_true', help=argparse.SUPPRESS)

    parser.add_argument('note', metavar='NOTE', nargs='*', default=_get_from_pipe(),
                        help='new note')
    parser.add_argument('-c', '--create', nargs='*', help='create a note')

    parser.add_argument('-u', '--user', help='username')
    parser.add_argument('-p', '--password', help='password')
    parser.add_argument('--host', help=argparse.SUPPRESS)

    parser.add_argument('--all', help='display all notes',
                        action='store_true')
    parser.add_argument('-l', '--last', help='display last note',
                        action='store_true')
    parser.add_argument('-n', '--num-note', help='display note with given number', type=int)
    parser.add_argument('-a', '--alias', help='set alias for note / display note with given alias')

    parser.add_argument('-d', '--drop-tokens', help='make all you tokens invalid',
                        action='store_true')

    parser.add_argument('--do-not-save', help='disable savings token locally',
                        action='store_true')
    parser.add_argument('-i', '--ignore', help='if set, tool will ignore local token',
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
        if options.drop_tokens and _get_token_from_system():
            try:
                display(drop_tokens())
            except (AuthenticationError, ServerError, ConnectionError):
                pass
            _delete_token()

        elif options.note or options.create:
            note = options.note or options.create
            note = ' '.join(note) if isinstance(note, (list, tuple)) else note
            alias = options.alias
            display(create_note(note, alias))
        
        elif options.alias:
            display(get_note_by_alias(alias=options.alias))
        elif options.all:
            display(get_notes())
        elif options.num_note:
            display(get_note(options.num_note))
        elif options.last:
            display(get_last_note())
        elif not (options.note or options.create):
            display(get_notes())

    except KeyboardInterrupt:
        sys.exit('\n')
    except AuthenticationError:
        sys.exit('Error in authentication. Username maybe occupied')
    except ServerError:
        sys.exit('Sorry there is server error. Please, try again later')
    except ConnectionError:
        sys.exit('Something wrong with connection, check your internet connection or try again later')
    except Exception:
        if _is_debug():
            raise
        if not options.report:
            sys.exit('Something went wrong! You can sent report to us with "-r" option')
        print(report(traceback.format_exc()))

    if not options.do_not_save and not _get_token_from_system() and not options.drop_tokens:
        token = _get_token()
        if token:
            _save_token(token)


if __name__ == '__main__':
    main()
