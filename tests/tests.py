
import os

from unittest import TestCase

import mock
from client import Gist, GistFile, cached_function


class TestsGistApi(TestCase):

    def setUp(self):
        self.user = os.environ.get('GIST_USER')
        self.password = os.environ.get('GIST_PASSWORD')

    def test_getting_gists_list(self):
        pass


class TestGistObject(TestCase):

    def setUp(self):
        self._manager = mock.Mock()

    def test_properties(self):
        data = {
            "url": "https://api.github.com/gists/aa5a315d61ae9438b18d",
            "commits_url": "https://api.github.com/gists/aa5a315d61ae9438b18d/commits",
            "id": "aa5a315d61ae9438b18d",
            "description": "description of gist",
            "public": True,
            "files": {
                "ring.erl": {
                    "size": 932,
                    "raw_url": "https://gist.githubusercontent.com/raw/365370/8c4d2d43d178df44f4c03a7f2ac0ff512853564e/ring.erl",
                    "type": "text/plain",
                    "truncated": False,
                    "language": "Erlang",
                    "content": "contents of gist"
                }
            },
            "truncated": False,
            "html_url": "https://gist.github.com/aa5a315d61ae9438b18d",
            "git_pull_url": "https://gist.github.com/aa5a315d61ae9438b18d.git",
            "git_push_url": "https://gist.github.com/aa5a315d61ae9438b18d.git",
            "created_at": "2010-04-14T02:15:15Z",
            "updated_at": "2011-06-20T11:34:15Z"
        }
        gist = Gist(manager=self._manager, **data)

        self.assertEqual(gist.description, "description of gist")
        self.assertEqual(gist.public, True)
        self.assertEqual(gist._created, "2010-04-14T02:15:15Z")

    def test_files_methods(self):
        data = {
            "url": "https://api.github.com/gists/aa5a315d61ae9438b18d",
            "commits_url": "https://api.github.com/gists/aa5a315d61ae9438b18d/commits",
            "id": "aa5a315d61ae9438b18d",
            "description": "description of gist",
            "public": True,
            "files": {
                "ring.erl": {
                    "size": 932,
                    "raw_url": "https://gist.githubusercontent.com/raw/365370/8c4d2d43d178df44f4c03a7f2ac0ff512853564e/ring.erl",
                    "type": "text/plain",
                    "truncated": False,
                    "language": "Erlang",
                    "content": "contents of gist"
                }
            },
            "truncated": False,
            "html_url": "https://gist.github.com/aa5a315d61ae9438b18d",
            "git_pull_url": "https://gist.github.com/aa5a315d61ae9438b18d.git",
            "git_push_url": "https://gist.github.com/aa5a315d61ae9438b18d.git",
            "created_at": "2010-04-14T02:15:15Z",
            "updated_at": "2011-06-20T11:34:15Z"
        }
        gist = Gist(manager=self._manager, **data)
        self.assertEqual(gist._files_dict, {'ring.erl': {'content': 'contents of gist'}})
        self.assertEqual(gist._edited_files_dict, {})

        gist.edit_file('ring.erl', 'new')
        self.assertEqual(gist._files_dict, {'ring.erl': {'content': 'new'}})
        self.assertEqual(gist._edited_files_dict, {'ring.erl': {'content': 'new'}})
        self.assertEqual(gist.get_file_content('ring.erl'), 'new')

        gist.add_file('test.txt', 'test')
        self.assertEqual(gist._files_dict, {'ring.erl': {'content': 'new'}, 'test.txt': {'content': 'test'}})
        self.assertEqual(gist._edited_files_dict, {'ring.erl': {'content': 'new'}, 'test.txt': {'content': 'test'}})

        with self.assertRaises(ValueError):
            gist.add_file('test.txt', 'test')

    @mock.patch('client._do_request', mock.Mock(return_value='from row'))
    def test_getting_file_content(self, m=None):
        data = {
            "url": "https://api.github.com/gists/aa5a315d61ae9438b18d",
            "commits_url": "https://api.github.com/gists/aa5a315d61ae9438b18d/commits",
            "id": "aa5a315d61ae9438b18d",
            "description": "description of gist",
            "public": True,
            "files": {
                "ring.erl": {
                    "size": 932,
                    "raw_url": "https://gist.githubusercontent.com/raw/365370/8c4d2d43d178df44f4c03a7f2ac0ff512853564e/ring.erl",
                    "type": "text/plain",
                    "truncated": False,
                    "language": "Erlang",
                    "content": "contents of gist"
                },
                "other.ring.erl": {
                    "size": 932,
                    "raw_url": "https://gist.githubusercontent.com/raw/365370/8c4d2d43d178df44f4c03a7f2ac0ff512853564e/ring.erl",
                    "type": "text/plain",
                    "truncated": True,
                    "language": "Erlang",
                    "content": "contents of gist"
                }

            },
            "truncated": False,
            "html_url": "https://gist.github.com/aa5a315d61ae9438b18d",
            "git_pull_url": "https://gist.github.com/aa5a315d61ae9438b18d.git",
            "git_push_url": "https://gist.github.com/aa5a315d61ae9438b18d.git",
            "created_at": "2010-04-14T02:15:15Z",
            "updated_at": "2011-06-20T11:34:15Z"
        }

        gist = Gist(self._manager, **data)

        self.assertEqual(gist.get_file_content('ring.erl'), 'contents of gist')
        self.assertEqual(gist.get_file_content('other.ring.erl'), 'from row')

    def test_save_method(self):
        self._manager.create = mock.Mock(return_value=None)
        gist = Gist(self._manager)
        gist.description = 'New'
        gist.add_file('test.ft', 'new file')
        gist.save()

        self._manager.create.assert_called_once_with('New', {'test.ft': {'content': 'new file'}}, public=False)

        data = {
            "id": "id",
            "description": "description of gist",
            "public": True,
            "files": {},
            "truncated": False,
        }
        self._manager.update = mock.Mock(return_value=None)
        gist = Gist(manager=self._manager, **data)
        gist.description = 'New'
        gist.add_file('test.ft', 'new file')
        gist.save()
        self._manager.update.assert_called_once_with('id', 'New', {'test.ft': {'content': 'new file'}})


class TestsGistFileObject(TestCase):

    def test_properties(self):
        URL = "https://gist.githubusercontent.com/raw/365370/8c4d2d43d178df44f4c03a7f2ac0ff512853564e/ring.erl"
        data = {
            "size": 932,
            "raw_url": URL,
            "type": "text/plain",
            "language": "Erlang",
            "truncated": False,
            "content": "contents of gist"
        }
        target = GistFile(name='filename', **data)

        self.assertEqual(target.truncated, False)
        self.assertEqual(target.content, "contents of gist")
        self.assertEqual(target.raw_url, URL)

    def test_as_dict_method(self):
        data = {
            "size": 932,
            "language": "Erlang",
            "truncated": False,
            "content": "contents of gist"
        }
        target = GistFile(name='filename', **data)

        self.assertEqual(target.as_dict(), {'content': "contents of gist"})

        target.delete()
        self.assertEqual(target.as_dict(), None)



class TestCacheDecor(TestCase):

    def test_simple(self):
        m = mock.Mock(return_value=10)
        func = cached_function(lambda: m())

        self.assertEqual(func(), 10)
        self.assertEqual(m.call_count, 1)
        self.assertEqual(func(), 10)
        self.assertEqual(m.call_count, 1)

    def test_params(self):
        m = mock.Mock(return_value=10)
        func = cached_function(lambda x=1: m() * x)

        self.assertEqual(func(x=1), 10)
        self.assertEqual(m.call_count, 1)
        self.assertEqual(func(x=1), 10)
        self.assertEqual(func(x=1), 10)
        self.assertEqual(m.call_count, 1)

        self.assertEqual(func(2), 20)
        self.assertEqual(m.call_count, 2)
        self.assertEqual(func(x=1), 10)
        self.assertEqual(m.call_count, 2)
        self.assertEqual(func(10), 100)
        self.assertEqual(m.call_count, 3)
