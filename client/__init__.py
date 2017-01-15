#!/usr/bin/env python
# -*- encoding: utf-8 -*-
from __future__ import print_function, unicode_literals

import argparse
import base64
import getpass
import json
import os
import platform
import hashlib
import logging
import select
import sys
import time
import traceback
from collections import namedtuple
from datetime import datetime
from itertools import cycle
from socket import gaierror
from binascii import Error as AsciiError

PY = 2
try:
    # Python 2
    from httplib import HTTPConnection, HTTPSConnection
    from urllib import urlencode
    from urlparse import urlparse
    from socket import error as ConnectionError
    input = raw_input
    chr = unichr

    from itertools import izip
    zip = izip

    def base64encode(message):
        return base64.urlsafe_b64encode(message)

    def base64decode(message):
        return base64.urlsafe_b64decode(message.encode()).decode('utf-8')

except ImportError:
    # Python 3
    PY = 3
    from http.client import HTTPConnection, HTTPSConnection
    from urllib.parse import urlencode, urlparse

    def base64encode(message):
        if isinstance(message, type(b'')):
            message = message.decode()
        return base64.urlsafe_b64encode(message.encode()).decode()

    def base64decode(message):
        return base64.urlsafe_b64decode(message).decode()


Note = namedtuple('Note', ['alias', 'notebook', 'date', 'public'])
SORTING = {
    'date': lambda x: x.date,
    'alias': lambda x: x.alias,
    'default': lambda x: [x.notebook, x.alias],
}
_DEBUG = False
_CACHED_ATTR = '_cache'
_PASS_CACHE_KWARG = 'not_cached'
__VERSION__ = '1.1.0'

_PATH = os.path.expanduser('~/.noteit/')
_TOKEN_PATH = os.path.join(_PATH, 'noteit.v2.tkn')
_CACHE_PATH = os.path.join(_PATH, '.cache')
_TOKEN_ENV_VALUE = 'GIST_TOKEN'

GET, POST, PUT, PATCH, DELETE = 'GET', 'POST', 'PUT', 'PATCH', 'DELETE'
_USER_AGENT_HEADER = 'User-Agent'
_ACCEPT_HEADER = 'Accept'
_APPLICATION_JSON = 'application/json'
_AUTH_HEADER = 'Authorization'
_TOKEN_HEADER = 'Authorization'
_CONTENT_TYPE_HEADER = 'Content-type'
_SUCCESS = range(200, 206)
_API_URL = 'https://api.github.com{path}'
_SCOPE = 'gist'
_TIMEOUT = 10
_ANONYMOUS_USER_AGENT = 'anonymous'
_URL_MAP = {
    'gists': '/gists/{id}',
    'user_gists': '/users/{user}/gists/{id}',
    'token': '/authorizations/{id}',
}

_REPORT_GIST = 'noteit.report'
_GIST_NAME_PREFIX = 'noteit'
_GIST_FILENAME = '{alias}.{type}'
_REPORT_TOKEN = 'woLCrMKhw5nCvcK8wrDCoX_Cj8KFwqDCsHbCjsOMwo_CsnlswrB9wrHCm8KPwqjChGnCj8KMwp_Cn8KPwobCmsOJwr3Dn8Kowp_CisKMecKhwrrCrMKXwpXCkMKMesKlwq53wqBw'
_TYPES = _TEXT_TYPE, _FILE_TYPE, _ENCRYPT_TYPE = ['text', 'file', 'entext']

_DECRYPT_ERROR_MSG = u"Error - can't decrypt note"
_TEMPLATE = u' {n.alias:^35} {n.date:^20} {n.public:^6}'
_TEMPLATE_N = u' {n.notebook:^12} ' + _TEMPLATE
_TRUE = u'\u2713'
_YES = [u'yes', u'y', u'poehali']
_FORMAT = _DATE_FORMAT = '%d-%m-%y %H:%M'
_CREDENTIALS_WARNING = u'''
WARNING: Noteit uses the GitHub Gist as store for notes!
Noteit does not store your password or login.
Noteit does not use your credentials for taking something from your GitHub account, except some of your Gists.
Noteit creates the Personal token containing access only to gists, encrypt and save them locally.
Input username and password for your github account or use --anon option:
'''
_ANON_INTRODUCTION = u'''At 'anonymous' mode your notes saved at the overall github account, so everybody have access to them.
Noteit asks for your name just to separate the general account to some namespace, so you can use any username.
We recommend use '--anon' option with '-u' option to skip prompt and '-k' option to encrypt your notes.
'''

if sys.getdefaultencoding().lower() != 'utf-8':
    _TRUE = '*'
logging.captureWarnings(True)


class AuthenticationError(Exception):
    """Error raising at wrong password """
    pass


class ServerError(Exception):
    """Error if server is return 50x status"""
    pass


class DecryptError(Exception):
    """Error if can't decrypt note"""
    pass


class NotFoundError(Exception):
    """Error if can't decrypt note"""
    pass


class UpdateRequiredError(Exception):
    """Error at wrong version"""
    pass


def cached_function(func):
    """Decorator that cache function result at first call and return cached result other calls """
    def _func(*args, **kwargs):
        force = kwargs.pop(_PASS_CACHE_KWARG, False)
        _cache_name = _CACHED_ATTR + _md5(json.dumps({'k': kwargs, 'a': args}))
        if not hasattr(func, _cache_name) or force or _is_debug():
            result = func(*args, **kwargs)
            if result is not None:
                setattr(func, _cache_name, result)
            return result
        return getattr(func, _cache_name)
    return _func


def get_notes(all=False, notebook=None, public=False, user=''):
    """Return user's notes as string"""

    objects = get_gist_manager()

    for gist in objects.noteit_gists(user):
        meta = gist.description.split('.')[2 if user else 1:]
        if len(meta) > 2:
            continue
        _notebook, _rule = meta if len(meta) == 2 else (None, meta[0])
        if user and gist.description.split('.')[1] != user:
            continue
        if not all:
            if public and _rule != 'public':
                continue
            if _notebook != notebook:
                continue
        for _file in gist.files:
            alias, _, updated = _parse_file_name(_file.name)
            yield Note(alias, _notebook or '__main__', updated, _TRUE if gist.public else '')


def get_note(alias, notebook=None, public=False, user=''):
    """Return user note of given alias"""
    _f = _get_gistfile_with_alias(alias, notebook=notebook, public=public, user=user)
    if _f is None:
        raise NotFoundError('Note not found')
    if _parse_file_name(_f.name)[1] == _ENCRYPT_TYPE or get_options().key:
        return _decrypt(_f.full_content, _get_key())
    return _f.full_content


def delete_note(alias, notebook=None, public=False, user=''):
    """Delete/remove user note of given alias"""
    _f = _get_gistfile_with_alias(alias, notebook=notebook, public=public, user=user)
    if _f is None:
        raise NotFoundError('Note not found')
    return _f.delete()


def get_last_note(notebook=None, public=False, user=''):
    """Return last saved note"""
    gist = _get_gist_by_name(_get_gist_name(notebook, public, user=user))
    now = datetime.utcnow()
    last_f = sorted(gist.files, key=lambda _f: _parse_file_name(_f.name)[-1] or now)
    if not last_f:
        raise NotFoundError('Note not found')
    if _parse_file_name(last_f[0].name)[1] == _ENCRYPT_TYPE:
        return _decrypt(last_f[0].full_content, _get_key())
    return last_f[0].full_content


def delete_notebook(notebook, public=False, user=''):
    _g = _get_gist_by_name(_get_gist_name(notebook, public, user=user))
    if _g is None:
        raise NotFoundError('Notebook not found')
    return _g.delete()


def create_note(note, alias=None, notebook=None, public=False, type=_TEXT_TYPE, user=''):
    """Make note"""
    if type == _ENCRYPT_TYPE:
        note = _encrypt(note, _get_key())
    gist_name = _get_gist_name(notebook, public, user=user)
    gist = _get_gist_by_name(gist_name)
    if gist:
        for _f in gist.files:
            if _parse_file_name(_f.name)[0] != alias:
                continue
            overwrite = input('Note with given alias already exists, Do you wanna overwrite it? ') in _YES
            if not overwrite:
                return
            _f.content = note
            _f.rename(_get_name_for_file(alias, type))
            _f.save()
            return note
    else:
        gist = Gist(get_gist_manager(), public=public, description=gist_name)
    gist.add_file(_get_name_for_file(alias, type), note)
    gist.save()
    return note


def report(tb):
    """Make traceback and etc. to server"""
    _g = Gist(manager=_get_spec_manager(), description=(get_options().user or 'unknown') + '.' + str(time.time()))
    _g.public = False
    _g.add_file('tb', tb)
    _g.add_file('info', _gen_info())
    _g.save()

# END API METHODS
# GIST COMMUNICATION


class GistManager:

    def __init__(self, user=None, password=None, token=None):
        self.__user, self.__password = user, password
        self.__token = token

    @staticmethod
    def _build_url(name, **kwargs):
        kwargs.setdefault('id', '')
        url = _URL_MAP[name].format(**kwargs)
        if url.endswith('/'):
            return url[:-1]
        return url

    @property
    def token(self):
        if self.__token is None:
            self.__token = self._get_token()
            if self.__token:
                self.__password = None
        return self.__token

    def _get_token(self):
        _date = _get_auth_data()
        responce = self._request(self._build_url('token'), POST, _date)
        if 'token' in responce:
            return responce['token']
        if 'errors' in responce and responce['errors'][0]['code'] == 'already_exists':
            for auth in self._request(self._build_url('token')):
                if auth['note'] == _date['note'] and auth['fingerprint'] == _date['fingerprint']:
                    self._request(self._build_url('token', id=auth['id']), DELETE)
                    return self._request(self._build_url('token'), POST, _date)['token']

    def _get_headers(self):
        headers = {}
        if self.__password:
            headers[_AUTH_HEADER] = _get_encoding_basic_credentials(self.__user, self.__password)
        elif self.__token:
            headers[_TOKEN_HEADER] = b'token ' + self.token.encode('ascii')
        return headers

    def _request(self, path, method=GET, data=None):
        url = _API_URL.format(path=path)
        if method in [DELETE]:
            return _do_request(url, method, data, headers=self._get_headers())
        return json.loads(_do_request(url, method, data, headers=self._get_headers()))

    @property
    def list(self):
        return list(self.iter)

    @property
    def iter(self):
        if self.__password or self.__token:
            return (Gist(manager=self, **_g) for _g in self._request(self._build_url('gists')))
        return (Gist(manager=self, **_g) for _g in self._request(self._build_url('user_gists', user=self.__user)))

    def noteit_gists(self, user=''):
        return (_g for _g in self.iter if _g.description.startswith(_GIST_NAME_PREFIX + '.' + user))

    def get(self, id):
        if self.__password or self.__token:
            return Gist(manager=self, **self._request(self._build_url('gists', id=id)))
        for _g in self.iter:
            if str(_g.id) == str(id):
                return _g

    def create(self, description, files, public=False):
        data = {'description': description, 'files': files, 'public': public}
        return Gist(manager=self, **self._request(self._build_url('gists'), POST, data=data))

    def update(self, id, description, files):
        data = {'description': description, 'files': files}
        return Gist(self._request(self._build_url('gists', id=id), PATCH, data=data))

    def delete(self, id):
        self._request(self._build_url('gists', id=id), DELETE)


class _ProxyProperty(object):

    def __init__(self, name, default=None):
        self.name, self._default = name, default

    def __get__(self, instance, owner):
        if not instance:
            return self
        return instance._data.get(self.name, self._default() if self._default else None)

    def __set__(self, instance, value):
        if not instance:
            return
        instance._data[self.name] = value
        instance._edited = True


class Gist(object):

    def __init__(self, manager, **kwargs):
        self._manager, self._data = manager, kwargs
        self._data.setdefault('public', False)
        self.files = [GistFile(name, self, **_f) for name, _f in self._files.items()]

    id = _ProxyProperty('id')
    description = _ProxyProperty('description')
    public = _ProxyProperty('public')
    _files = _ProxyProperty('files', lambda: {})
    _created = _ProxyProperty('created_at')

    @property
    def _files_dict(self):
        return dict([(f.name, f.as_dict()) for f in self.files])

    @property
    def _edited_files_dict(self):
        return dict([(f.name, f.as_dict()) for f in self.files if f._edited])

    def add_file(self, name, content):
        _f = self.get_file(name, GistFile)
        if _f.content:
            raise ValueError('File with name {0} already exists'.format(name))
        _f.content = content
        self.files.append(_f)

    def edit_file(self, name, content):
        self.get_file(name).content = content

    def get_file(self, name, default=None):
        for _f in self.files:
            if _f.name == name:
                return _f
        if default is not None:
            return default(name=name, gist=self) if callable(default) else default
        raise ValueError('No file with name {0}'.format(name))

    def get_file_content(self, name):
        return self.get_file(name).full_content

    def save(self):
        if self.id:
            return self._manager.update(self.id, self.description, self._edited_files_dict)
        return self._manager.create(self.description, self._files_dict, public=self.public)

    def delete(self):
        self._manager.delete(self.id)


class GistFile(object):
    def __init__(self, name, gist=None, **kwargs):
        self.__name, self._data = name, kwargs
        self._edited = self._delited = False
        self.__gist = gist
        self._new_name = None

    truncated = property(lambda self: self._data.get('truncated'))
    content = _ProxyProperty('content')
    raw_url = _ProxyProperty('raw_url')

    @property
    def name(self):
        return self.__name

    def rename(self, value):
        self._new_name = value

    def as_dict(self):
        if self._delited:
            return
        out = {}
        if self._new_name:
            out['filename'] = self._new_name
        if self._edited:
            out['content'] = self.content
        return out

    def delete(self):
        self._edited = True
        self._delited = True
        if self.__gist:
            self.save()

    @property
    def full_content(self):
        if self.truncated or not self.content:
            return _do_request(self.raw_url)
        return self.content

    def save(self):
        self.__gist.save()


def _get_auth_data():
    return {'scopes': [_SCOPE], 'note': 'Noteit', 'fingerprint': platform.system() + '-' + platform.node()}


def _get_gistfile_with_alias(alias, notebook=None, public=False, user=''):
    gist = _get_gist_by_name(_get_gist_name(notebook, public, user=user))
    if gist is None:
        raise NotFoundError('Gist not found')
    for _f in gist.files:
        if _parse_file_name(_f.name)[0] == alias:
            return _f


def _get_gist_name(notebook=None, public=False, user=''):
    name = '.'.join([_GIST_NAME_PREFIX, user, notebook or '', 'public' if public else 'private'])
    return name.replace('..', '.').replace('..', '.')


def _get_gist_by_name(name):
    for _g in get_gist_manager().noteit_gists():
        if _g.description == name:
            return _g


def _get_name_for_file(alias, type):
    return '{0}#{1}.{2}'.format(alias, type, int(time.time() * 1000000))


def _parse_file_name(name):
    alias, meta = name.split('#')
    try:
        type, updated = meta.split('.')
        updated = datetime.utcfromtimestamp(int(updated) / 1000000.0)
    except ValueError:
        type, updated = meta, 0
    return alias, type, updated


def _do_request(url, *args, **kwargs):
    """Make request and handle response"""
    kwargs.setdefault('headers', {}).update(_get_default_headers())
    response = _make_request(url, *args, **kwargs)
    resp = _response_handler(response)
    return resp


def _response_handler(response):
    """Handle response status"""
    response_body = response.read().decode('utf-8')
    if response.status in [401, ]:
        raise AuthenticationError
    elif response.status > 500:
        raise ServerError
    elif response.status in [301, 302, 303, 307] and response._method != POST:
        raise AuthenticationError
    return response_body


@cached_function
def _get_connection(host):
    """Create and return connection with host"""
    return HTTPSConnection(host, timeout=_TIMEOUT)


def _make_request(url, method=GET, data=None, headers=None):
    """Generate request and send it"""
    headers = headers or {}
    method = method.upper()
    conn = _get_connection(urlparse(url).hostname)
    if data:
        data = json.dumps(data).encode('ascii')
        if method == GET:
            url = '?'.join([url, data.decode('ascii') or ''])
            data = None

    if method in [POST, PUT, PATCH]:
        headers.update({_CONTENT_TYPE_HEADER: "application/x-www-form-urlencoded"})
    conn.request(method, url, body=data, headers=headers)
    return conn.getresponse()


@cached_function
def _get_user_agent():
    """Return User-Agent for request header"""
    if get_options().anon:
        return _ANONYMOUS_USER_AGENT
    return _generate_user_agent_with_info()


def _generate_user_agent_with_info():
    """Generate User-Agent with environment info"""
    return ' '.join([
        u'{0}/{1}'.format('Noteit', get_version()),
    ])


def _get_encoding_basic_credentials(user, password=''):
    """Return value of header for Basic Authentication"""
    return b'Basic ' + base64.b64encode('{0}:{1}'.format(user, password).encode('ascii'))


def _get_default_headers():
    """Return dict of headers for request"""
    return {
        _ACCEPT_HEADER: _APPLICATION_JSON,
        _USER_AGENT_HEADER: _get_user_agent(),
        _CONTENT_TYPE_HEADER: _APPLICATION_JSON,
    }

# END GIST COMMUNICATIONS


@cached_function
def get_gist_manager():
    if get_options().anon:
        return _get_spec_manager()
    if get_options().public and get_options().user:
        return GistManager(user=get_options().user)
    token = _get_token_from_system()
    if token:
        return GistManager(token=token)
    if not get_options().user:
        print(_CREDENTIALS_WARNING)
    first = GistManager(_get_user(), _get_password())
    if first.token:
        _save_token(first.token)
    return first


def _get_spec_manager():
    manager = GistManager(token=_decrypt(_REPORT_TOKEN, get_version().replace('.', '_')))
    try:
        manager.list
    except AuthenticationError:
        raise UpdateRequiredError()
    return manager


@cached_function
def _get_password():
    """Return password from argument or asks user for it"""
    return get_options().password or getpass.getpass(u'Input your password: ')


@cached_function
def _get_user():
    """Return user from argument or asks user for it"""
    return get_options().user or input(u'Input username: ')


@cached_function
def _get_key():
    """Return key to encode/decode from argument or from local"""
    return getpass.getpass(u'Input encryption key: ')


def _md5(message):
    md5 = hashlib.md5()
    md5.update(message.encode())
    return md5.hexdigest()


def _double_md5(message):
    return _md5(_md5(message))


def _get_token_from_system():
    """Return token from file"""
    if _TOKEN_ENV_VALUE in os.environ:
        return os.environ.get(_TOKEN_ENV_VALUE)
    if get_options().token:
        return get_options().token
    return _get_saved_token()


def _save_token(token):
    """Save token to file"""
    _save_file_or_ignore(_TOKEN_PATH, _encrypt(token, platform.node()))


def _get_saved_token():
    if os.path.isfile(_TOKEN_PATH):
        with open(_TOKEN_PATH) as _file:
            encrypt_token = _file.read().strip()
            return _decrypt(encrypt_token, platform.node())


def _delete_token():
    """Delete file with token"""
    if os.path.exists(_TOKEN_PATH):
        os.remove(_TOKEN_PATH)


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
    return u'--debug' in sys.argv


@cached_function
def get_version():
    """Return version of client"""
    return __VERSION__


def _save_file_or_ignore(path, content):
    if get_options().do_not_save:
        return
    if not os.path.isdir(os.path.dirname(path)):
        os.makedirs(os.path.dirname(path))
    with open(path, 'w') as _file:
        _file.write(content)


def _format_alias(alias):
    return alias


def _encrypt(message, key):
    """Encrypt message with b64encoding and {} alg"""
    message = base64encode(message)
    crypted = ''
    for pair in zip(message, cycle(_double_md5(key))):
        crypted += chr((ord(pair[0]) + ord(pair[1])) % 256)
    return base64encode(crypted.encode('utf-8'))


def _decrypt(message, key):
    try:
        return __decrypt(message, key)
    except (UnicodeDecodeError, TypeError, AsciiError, ValueError, AttributeError):
        raise DecryptError


def __decrypt(message, key):
    """Decrypt message with b64decoding and {} alg"""
    message = base64decode(message)
    decrypted = ''
    for pair in zip(message, cycle(_double_md5(key))):
        decrypted += chr((ord(pair[0]) - ord(pair[1])) % 256)
    return base64decode(decrypted.encode('utf-8'))


def _gen_info():
    return ' '.join([
        u'{0}/{1}'.format('Noteit', get_version()),
        u'{i[0]}-{i[1]}/{i[2]}-{i[5]}'.format(i=platform.uname()),
        u'{0}/{1}'.format(platform.python_implementation(), platform.python_version()),
    ])


def get_options_parser():
    """Arguments definition"""
    parser = argparse.ArgumentParser(description='Tool for creating notes in your gists', prog='noteit')

    parser.add_argument('note', metavar='NOTE', nargs='*', default=_get_from_pipe(), help='new note')

    parser.add_argument('-u', '--user', help='username')
    parser.add_argument('--password', help='password')
    parser.add_argument('-t', '--token', help='token')
    parser.add_argument('--anon', help='for users without accounts', action='store_true')

    parser.add_argument('-n', '--notebook', help='set notebook for note / display notes with given notebook')
    parser.add_argument('-k', '--key', help='key to encrypting/decrypting notes', action='store_true')

    parser.add_argument('-p', '--public', help='Public notes', action='store_true')
    parser.add_argument('-s', '--sort', help='Sort type for notes',
                        choices=list(SORTING.keys()) + ['n' + k for k in SORTING.keys()] + ['-'], default='default')
    parser.add_argument('--all', help='display all notes', action='store_true')

    parser.add_argument('-l', '--last', help='display last note', action='store_true')
    parser.add_argument('-a', '--alias', help='set alias for note / display note with given alias')
    parser.add_argument('-d', '--delete', help='delete note/notebook', action='store_true')

    parser.add_argument('--do-not-save', help='disable savings any data locally', action='store_true')

    parser.add_argument('-r', '--report', help=argparse.SUPPRESS, action='store_true')
    parser.add_argument('--debug', action='store_true', help=argparse.SUPPRESS)

    parser.add_argument('--version', action='version', version='%(prog)s ' + get_version(),
                        help='displays the current version of %(prog)s and exit')

    return parser


@cached_function
def get_options():
    """Return parsed arguments"""
    return get_options_parser().parse_args()


def main(retry=True):
    """Main"""
    options = get_options()
    user = ''
    if options.user or options.token or options.anon:
        retry = False
    try:
        if options.anon:
            if not options.user:
                print(_ANON_INTRODUCTION)
            user = _get_user().decode('utf-8') if PY == 2 else _get_user()
        alias = options.alias.decode('utf-8') if PY == 2 and options.alias else options.alias
        notebook = options.notebook.decode('utf-8') if PY == 2 and options.notebook else options.notebook
        if options.note:
            if not alias:
                sys.exit('You must specify alias with option -a ')
            if PY == 2:
                note = u' '.join([w.decode('utf-8') for w in options.note]) if isinstance(options.note, (list, tuple)) \
                    else options.note.decode('utf-8')
            else:
                note = u' '.join([w for w in options.note]) if isinstance(options.note, (list, tuple)) \
                    else options.note
            res = create_note(note, alias, notebook, options.public,
                              _TEXT_TYPE if not options.key else _ENCRYPT_TYPE, user)
            if res:
                print('Saved')
            else:
                print('Canceled')
        elif alias is not None:
            if options.delete and input(u'Are you really want to delete note? ') in _YES:
                delete_note(_format_alias(alias), notebook, options.public, user)
                print(u'Note "{0}"" deleted'.format(alias))
            else:
                print(get_note(_format_alias(alias), notebook, options.public, user))
        elif options.last:
            print(get_last_note(notebook, options.public, user))
        elif options.delete and notebook:
            if input(u'Are you really want to delete all notes in notebook "{0}"?'
                     u' '.format(options.notebook)) not in _YES:
                print(u'Canceled')
            else:
                delete_notebook(options.notebook, options.public, user)
                print('Notebook "{0}" deleted'.format(notebook))
        else:
            template = _TEMPLATE
            if options.all:
                template = _TEMPLATE_N
            print(template.replace(u'<', u'^').format(n=Note('ALIAS', 'NOTEBOOK', 'UPDATED', 'PUBLIC')))
            notes = get_notes(all=options.all, notebook=notebook, public=options.public, user=user)
            key, reverse = '-default' if options.sort == '-' else options.sort, False
            if key.startswith('n'):
                key, reverse = key[1:], True
            for note in sorted(notes, key=SORTING[key], reverse=reverse):
                note = Note(note.alias, note.notebook, note.date.strftime(_FORMAT), note.public)
                print(template.format(n=note))

    except KeyboardInterrupt:
        sys.exit('\n')
    except AuthenticationError:
        if retry:
            _delete_token()
            main(retry=False)

        sys.exit(u'Error in authentication')
    except ServerError:
        sys.exit(u'Sorry there is server error. Please, try again later')
    except NotFoundError as e:
        sys.exit(str(e))
    except DecryptError:
        sys.exit('Decrypt Error')
    except UpdateRequiredError:
        sys.exit('Please, update noteit with "pip install -U noteit"')
    except (ConnectionError, gaierror):
        sys.exit(u'Something wrong with connection, check your internet connection or try again later')
    except Exception:
        if _is_debug():
            raise
        if not options.report:
            sys.exit(u'Something went wrong! You can sent report to us with "-r" option')
        report(traceback.format_exc())


if __name__ == '__main__':
    main()
