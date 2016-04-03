#!/usr/bin/env python
# -*- encoding: utf-8 -*-
from __future__ import print_function

import argparse
import base64
import getpass
import json
import os
import platform
import hashlib
import select
import string
import sys
import traceback
from itertools import cycle
from socket import gaierror
from binascii import Error as AsciiError

try:
    from httplib import HTTPConnection, HTTPSConnection  # Py<3
    from urllib import urlencode, quote
    from socket import error as ConnectionError
    input = raw_input

    from itertools import izip
    zip = izip

    def base64encode(message):
        return base64.urlsafe_b64encode(message)

    def base64decode(message):
        return base64.urlsafe_b64decode(message.encode()).decode('utf-8')

except ImportError:
    from http.client import HTTPConnection, HTTPSConnection  # Py>=3
    from urllib.parse import urlencode, quote

    def base64encode(message):
        return base64.urlsafe_b64encode(message.encode()).decode()

    def base64decode(message):
        return base64.urlsafe_b64decode(message).decode()


_DEBUG = False
_CACHED_ATTR = '_cache'
_PASS_CACHE_KWARG = 'not_cached'
__VERSION__ = '0.17.1'

GET, POST, PUT, DELETE = 'GET', 'POST', 'PUT', 'DELETE'
ALPHA = string.ascii_letters + string.digits + '=_-'

_TIMEOUT = 5
_ANONYMOUS_USER_AGENT = 'anonymous'
_HOST_ENV_VALUE = 'NOTEIT_HOST'
_PATH = os.path.expanduser('~/.noteit/')
_TOKEN_PATH = os.path.join(_PATH, 'noteit.tkn')
_KEY_PATH = os.path.join(_PATH, 'enc')
_CACHE_PATH = os.path.join(_PATH, '_notes')

_TOKEN_ENV_VALUE = 'NOTEIT_TOKEN'
_CONF_LINK = 'https://raw.githubusercontent.com/Krukov/noteit/stable/.conf.json'
_USER_AGENT_HEADER = 'User-Agent'
_CONTENT_TYPE_HEADER = 'Content-type'
_AUTH_HEADER = 'Authorization'
_TOKEN_HEADER = 'Authorization'
_URLS_MAP = {
    'create_note': '/notes',
    'drop_tokens': '/drop_tokens',
    'get_token': '/get_token',
    'get_notes': '/notes',
    'get_notebook': u'/notebook/{i}',
    'get_note': u'/notes/{i}',
    'report': '/report',
}
_SUCCESS = range(200, 206)

_DECRYPT_ERROR_MSG = "'Error - can't decrypt note"
_TEMPLATE = u' {alias:^20} {text:<80}'
_TEMPLATE_N = u' {notebook:^12} {alias:^13} {text:<80}'
_TEMPLATE_NA = u' {notebook:^20} {alias:^13}'
_TEMPLATE_A = u'✓ {alias}'
_CROP = 77


class AuthenticationError(Exception):
    """Error raising at wrong password """
    pass


class ServerError(Exception):
    """Error if server is return 50x status"""
    pass


def cached_function(func):
    """Decorator that cache function result at first call and return cached result other calls """

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


def get_notes(all=False, notebook=None, quiet=False):
    """Return user's notes as string"""
    url = _URLS_MAP['get_notes']
    template = _TEMPLATE if not quiet else _TEMPLATE_A
    data = None
    if notebook:
        data = {'notebook': notebook}
    elif all:
        template = _TEMPLATE_N if not quiet else _TEMPLATE_NA
        data = {'all': True}

    try:
        notes, status = do_request(url, data=data)
    except (ConnectionError, ServerError, gaierror):
        notes = _get_notes_from_cache(notebook)
        status = 200
        if notes is None:
            raise
        elif not notes:
            status = 204

    if status == 200:
        _cache_notes(notes, notebook)
        out = template.replace(u'<', u'^').format(text='NOTE', alias='ALIAS', notebook='NOTEBOOK') + '\n' * 2
        out = '' if quiet else out
        for note in json.loads(notes):
            text = _decrypt_note(note['text']).replace(u'\n', u' ')
            note['text'] = text[:_CROP] + (u'...' if len(text) > _CROP else'')
            note['notebook'] = note.get('notebook') or ''
            out += template.format(**note)
            out += '\n'
        return out[:-1]
    elif status == 204:
        if notebook:
            return "You do not have notes in the '{0}' notebook".format(notebook)
        return "You do not have notes"
    raise Exception('Error at get_notes method: {0} {1}'.format(status, notes))


def get_note(number_or_alias):
    """Return user note of given number (number in [1..5]) or alias"""
    try:
        note, status = do_request(_URLS_MAP['get_note'].format(i=number_or_alias))
    except (ConnectionError, ServerError, gaierror):
        note = _get_note_from_cache(number_or_alias)
        status = 200
        if note is None:
            raise
        elif not note:
            status = 204

    if status in _SUCCESS:
        note = json.loads(note)['text']
        result = _decrypt_note(note)
        if result.startswith(_DECRYPT_ERROR_MSG):
            try:
                result = _decrypt(note, _get_key_from_stdin())
            except:
                pass
        return result
    elif status == 404:
        return "No note with requested alias"
    raise Exception(u'Error at get_note method: {} {}'.format(status, note))


def delete_note(number_or_alias):
    """Delete/remove user note of given number (number in [1..5]) or alias"""
    url = _URLS_MAP['get_note'].format(i=number_or_alias)
    _, status = do_request(url, method=DELETE)
    if status in _SUCCESS:
        return "Note deleted"
    elif status == 404:
        return "No note with requested alias"
    raise Exception(u'Error at delete_note method: {0} {1}'.format(status, number_or_alias))


def get_last_note():
    """Return last saved note"""
    notes, status = do_request(_URLS_MAP['get_notes'])
    if status in _SUCCESS:
        return _decrypt_note(json.loads(notes)[0]['text'])


def create_note(note, alias=None, notebook=None):
    """Make request for saving note"""
    data = {'text': _encrypt_note(note)}
    if alias:
        data['alias'] = alias
    if notebook:
        data['_notebook'] = notebook
    responce, status = do_request(_URLS_MAP['get_notes'], method=POST, data=data)
    if status in _SUCCESS:
        return 'Saved'
    elif status in [406, 409]:
        return json.loads(responce)['error']
    raise Exception(u'Error at create_note method: {0} {1}'.format(status, responce))


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

    if status in _SUCCESS:
        display('Thank you for reporting...')
    else:
        display('Error: can not be reported')


def drop_tokens():
    """Make request to recreate user's tokens"""
    _, status = do_request(_URLS_MAP['drop_tokens'], method=POST)
    if status in _SUCCESS:
        return 'Tokens are deleted'
    raise Exception(u'Error at drop_token method: {0} {1}'.format(status, _))


def _get_token():
    """Send request to get token and return it at success"""
    token, status = do_request(_URLS_MAP['get_token'], method=POST)
    if status in _SUCCESS:
        return json.loads(token)['token']
    else:
        if get_options().report:
            report(u'Error at token getting {0} ({1})'.format(token, status))
        else:
            sys.stderr.write('Can not get token, to report problem run with --report option\n')


def registration(question_location):
    """Asks user for answer the question at given location and send result """
    prompt = u"If you are not registered yet, please answer the question '{0}': ".format(do_request(question_location)[0])
    answer = _get_from_stdin(prompt)
    response, status = do_request(question_location, POST, {'answer': answer})
    if status in _SUCCESS:
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
    """Create and return connection with host"""
    host = _get_host()
    if host.startswith('https://'):
        host = host[8:]
        connection = HTTPSConnection
    else:
        connection = HTTPConnection
        host = host.replace('http://', '')
    return connection(host, timeout=_TIMEOUT)


def _make_request(url, method=GET, data=None, headers=None):
    """Generate request and send it"""
    headers = headers or {}
    method = method.upper()
    conn = _get_connection()
    if data:
        data = urlencode(data).encode('ascii')
        if method == GET:
            url = '?'.join([url, data.decode('ascii') or ''])
            data = None

    if method in [POST]:
        headers.update({"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"})
    conn.request(method, url, body=data, headers=headers)

    return conn.getresponse()


@cached_function
def _get_host():
    """Return noteit backend host"""
    host = get_options().host or os.environ.get('NOTEIT_HOST')
    if not host:
        #  Get host from .conf file from repo
        conn = HTTPSConnection(_CONF_LINK.split('/', 3)[2])
        conn.request(GET, _CONF_LINK)
        request = conn.getresponse()
        conf_from_git = request.read().decode('ascii')
        host = json.loads(conf_from_git)['host']
        if host.endswith('/'):
            host = host[:-1]
    if not os.environ.get('NOTEIT_HOST'):
        os.environ['NOTEIT_HOST'] = host
    return host


@cached_function
def _get_password():
    """Return password from argument or asks user for it"""
    return get_options().password or getpass.getpass('Input your password: ')


@cached_function
def _get_user():
    """Return user from argument or asks user for it"""
    return get_options().user or _get_from_stdin('Input username: ')


def _get_key_from_stdin():
    return getpass.getpass('Input encryption key: ')


@cached_function
def _get_key():
    """Return key to encode/decode from argument or from local"""
    key = get_options().key
    if key:
        return _get_key_from_stdin
     
    if not get_options().user and os.path.isfile(_KEY_PATH):
        with open(_KEY_PATH) as key_file:
            return key_file.read()
    return _get_secret_hash()


def _md5(message):
    md5 = hashlib.md5()
    md5.update(message.encode())
    return md5.hexdigest()


@cached_function
def _get_secret_hash():
    return _md5(_md5(_get_user() + _get_password()))


def _save_key():
    password = _get_secret_hash()
    _save_file_or_ignore(_KEY_PATH, password)


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
    """Generete User-Agent with environment info"""
    return ' '.join([
        '{0}/{1}'.format('Noteit', get_version()),
        '{i[0]}-{i[1]}/{i[2]}-{i[5]}'.format(i=platform.uname()),
        '{0}/{1}'.format(platform.python_implementation(), platform.python_version()),
    ])


@cached_function
def _get_token_from_system():
    """Return token from file"""
    if _TOKEN_ENV_VALUE in os.environ:
        return os.environ.get(_TOKEN_ENV_VALUE)
    if get_options().token:
        return get_options().token
    if os.path.isfile(_TOKEN_PATH):
        with open(_TOKEN_PATH) as _file:
            return _file.read().strip()


def _save_token(token):
    """Save token to file"""
    _save_file_or_ignore(_TOKEN_PATH, token)


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
        _CONTENT_TYPE_HEADER: 'application/json'
    }
    if not get_options().user and not get_options().ignore and _get_token_from_system():
        headers[_TOKEN_HEADER] = b'token ' + _get_token_from_system().encode('ascii')
    else:
        headers[_AUTH_HEADER] = _get_encoding_basic_credentials()
        _save_key()
    return headers


def _get_from_stdin(text):
    """communication with stdin"""
    return input(text)


def _get_from_pipe():
    """Read stdin if pipe is open | """
    try:
        is_in_pipe = select.select([sys.stdin], [], [], 0.0)[0]
    except (select.error, TypeError):
        return
    else:
        return sys.stdin.read() if is_in_pipe else None


def _is_debug():
    if _DEBUG:
        return True
    return '--debug' in sys.argv


def _cache_notes(notes, notebook):
    """Save notes in local file"""
    path = _CACHE_PATH
    if notebook:
        path += '.' + notebook
    _save_file_or_ignore(path, notes)


def _get_notes_from_cache(notebook):
    path = _CACHE_PATH
    if notebook:
        path += '.' + notebook
    if not os.path.isfile(path):
        return
    with open(path) as _file:
        return _file.read()


def _get_note_from_cache(alias):
    if not os.path.isfile(_CACHE_PATH):
        return
    with open(_CACHE_PATH) as _file:
        notes = dict((item['alias'], item['text']) for item in json.loads(_file.read()))
    note = notes.get(alias, None)
    if note:
        return json.dumps({'text': note})


def _save_file_or_ignore(path, content):
    if not os.path.isdir(os.path.dirname(path)):
        os.makedirs(os.path.dirname(path))
    if get_options().do_not_save:
        return
    with open(path, 'w') as _file:
        _file.write(content)


def _format_alias(alias):
    return quote(alias, safe='')


def _encrypt(message, key):
    """Encrypt message with b64encoding and {} alg"""
    message = base64encode(message)
    crypted = ''
    for pair in zip(message, cycle(key)):
        total = ALPHA.index(pair[0]) + ALPHA.index(pair[1])
        crypted += ALPHA[total % len(ALPHA)]
    return base64encode(crypted)


def _encrypt_note(note):
    if not note or get_options().do_not_encrypt or not _get_key():
        return note
    return _encrypt(note, _get_key())


def _decrypt(message, key):
    """Decrypt message with b64decoding and {} alg"""
    message = base64decode(message)
    decrypted = ''
    for pair in zip(message, cycle(key)):
        total = ALPHA.index(pair[0]) - ALPHA.index(pair[1])
        decrypted += ALPHA[total % len(ALPHA)]
    return base64decode(decrypted)


def _decrypt_note(note):
    if not note or get_options().do_not_encrypt or not _get_key():
        return note
    try:
        return _decrypt(note, _get_key())
    except (UnicodeDecodeError, TypeError, AsciiError, ValueError, AttributeError):
        return '{0}: {1}'.format(_DECRYPT_ERROR_MSG, note)


def get_options_parser():
    """Arguments definition"""
    parser = argparse.ArgumentParser(description='Tool for creating notes', prog='noteit')

    parser.add_argument('--version', action='version', version='%(prog)s ' + get_version(),
                        help='displays the current version of %(prog)s and exit')
    parser.add_argument('--debug', action='store_true', help=argparse.SUPPRESS)

    parser.add_argument('note', metavar='NOTE', nargs='*', default=_get_from_pipe(),
                        help='new note')

    parser.add_argument('-u', '--user', help='username')
    parser.add_argument('-p', '--password', help='password')
    parser.add_argument('--host', help=argparse.SUPPRESS)

    parser.add_argument('-q', '--quiet', help='only display aliases', action='store_true')
    parser.add_argument('--all', help='display all notes', action='store_true')
    parser.add_argument('-l', '--last', help='display last note', action='store_true')
    parser.add_argument('-a', '--alias', help='set alias for note / display note with given alias')
    parser.add_argument('-n', '--notebook', help='set notebook for note / display notes with given notebook')

    parser.add_argument('-d', '--delete', help='delete note', action='store_true')
    parser.add_argument('-o', '--overwrite', help='overwrite note', action='store_true')

    parser.add_argument('--drop-tokens', help='make all you tokens invalid',
                        action='store_true')
    parser.add_argument('--token', help='for manual setting token')

    parser.add_argument('--do-not-save', help='disable savings any data locally',
                        action='store_true')
    parser.add_argument('-i', '--ignore', help='if set, tool will ignore local token',
                        action='store_true')
    parser.add_argument('--do-not-encrypt', help='disable encrypting/decrypting notes',
                        action='store_true')
    parser.add_argument('-k', '--key', help='key to encrypting/decrypting notes (default is password base)',
                        action='store_true')

    parser.add_argument('--anon', help='do not add OS and other info to user-agent header',
                        action='store_true')
    parser.add_argument('-r', '--report', help=argparse.SUPPRESS, action='store_true')

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
            try:
                display(drop_tokens())
            except (AuthenticationError, ServerError, ConnectionError):
                pass
            if os.path.isfile(_TOKEN_PATH):
                _delete_token()

        elif options.note:
            note = ' '.join(options.note) if isinstance(options.note, (list, tuple)) else options.note
            alias = options.alias
            if options.overwrite:
                try:
                    delete_note(_format_alias(alias))
                except:
                    pass
            display(create_note(note, alias, options.notebook))

        elif options.alias is not None:
            if options.delete:
                display(delete_note(_format_alias(options.alias)))
            else:
                display(get_note(_format_alias(options.alias)))
        elif options.last:
            display(get_last_note())
        else:
            display(get_notes(all=options.all, notebook=options.notebook, quiet=options.quiet))

    except KeyboardInterrupt:
        sys.exit('\n')
    except AuthenticationError:
        sys.exit('Error in authentication. Username maybe occupied')
    except ServerError:
        sys.exit('Sorry there is server error. Please, try again later')
    except (ConnectionError, gaierror):
        sys.exit('Something wrong with connection, check your internet connection or try again later')
    except Exception:
        if _is_debug():
            raise
        if not options.report:
            sys.exit('Something went wrong! You can sent report to us with "-r" option')
        report(traceback.format_exc())

    if not options.do_not_save and (options.user or (not _get_token_from_system() and not options.drop_tokens)):
        token = _get_token()
        if token:
            _save_token(token)


if __name__ == '__main__':
    main()
