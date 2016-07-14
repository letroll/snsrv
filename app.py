#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2015-2016 Samuel Walladge
# Distributed under the terms of the GNU General Public License version 3.
# main application file

import tornado.ioloop
from urllib.parse import parse_qs
from tornado.web import Application, url
from tornado.escape import json_decode

import json
import re
import base64

import database
import config as cfg
import utils
from basehanders import ApiHandler, BaseHandler

invalid_tag_chars = re.compile(r'[,\s]')

class notes_handler(ApiHandler):
    """handles specific notes requests"""

    def get(self, key=None, version=None):
        """return the note by key"""
        if not key:
            return self.send_error(400, reason='no key')

        if version is not None:
            try:
                version = int(version)
            except:
                return self.send_error(400, reason='invalid version type')

        note = self.db.get_note(self.user, key, version)
        if not note:
            return self.send_error(404, reason='bookmark not found')

        self.send_data(note)

    def post(self, key=None):
        """create or update a note"""
        now = utils.now()

        # get the posted data
        data = {}
        try:
            data = json_decode(self.request.body)
        except json.JSONDecodeError as e:
            return self.send_error(400, reason='invalid json data (line {}, col {})'.format(e.lineno, e.colno))

        safe_data = {}

        # deleted status
        deleted = data.get('deleted', None)
        if deleted is not None:
            try:
                deleted = int(deleted)
                assert(deleted == 1 or deleted == 0)
            except:
                return self.send_error(400, reason='invalid deleted value')
        safe_data['deleted'] = deleted

        # modifydate
        modify = data.get('modifydate', None)
        if modify is not None:
            try:
                modify = float(modify)
                # TODO: should enforce modify/create dates before current
                # server time (utc)?
                # assert(modify >= 0 and modify <= now)
                assert(modify >= 0)
            except:
                return self.send_error(400, reason='invalid modifydate')
        safe_data['modify'] = modify

        # createdate
        create = data.get('createdate', None)
        if create is not None:
            try:
                create = float(create)
                # assert(create >= 0 and create <= now)
                assert(create >= 0)
            except:
                return self.send_error(400, reason='invalid createdate')
        safe_data['create'] = create

        # version
        version = data.get('version', None)
        if version is not None:
            try:
                version = int(version)
                assert(version > 0)
            except:
                return self.send_error(400, reason='invalid version')
        safe_data['version'] = version

        # systemtags
        systemtags = data.get('systemtags', None)
        if systemtags is not None:
            try:
                assert(isinstance(systemtags, list))
                for tag in systemtags:
                    assert(tag in ('markdown', 'list', 'pinned', 'unread'))
            except:
                return self.send_error(401, reason='invalid systemtags')
        safe_data['systemtags'] = systemtags

        # tags
        tags = data.get('tags', None)
        if tags is not None:
            try:
                assert(isinstance(tags, list))
                for tag in tags:
                    assert(isinstance(tag, str) and invalid_tag_chars.search(tag) is None)
            except:
                return self.send_error(401, reason='invalid tags')
        safe_data['tags'] = tags

        # the content
        content = data.get('content', None)
        if content is not None:
            try:
                assert(isinstance(content, str))
                # TODO: max-len restriction
            except:
                return self.send_error(400, reason='invalid content')
        else:
            # if new note, needs content
            if key is None:
                return self.send_error(400, reason='no content')
        safe_data['content'] = content

        # now actually create or update a note
        note = None
        if key is None:
            note = self.db.create_note(self.user, safe_data)
        else:
            old_note_object = self.db.get_note_object(self.user, key)
            if not old_note_object:
                return self.send_error(404, reason='note not found')
            note = self.db.update_note(self.user, old_note_object, safe_data)

        if note:
            return self.send_data(note)
        return self.send_error(500, reason='unable to create/update note')


    def delete(self, key=None):
        """delete a note if exists"""
        note = self.db.get_note_object(self.user, key)
        if not note:
            return self.send_error(404, reason='note not found')

        # check if note in trashcan
        if note.deleted == 0:
            return self.send_error(400, reason='note not in trash')


        ok = self.db.delete_note(self.user, note)
        if not ok:
            return self.send_error(500, reason='error deleting note from database')


class tags_handler(ApiHandler):
    """handles requests for tag operations"""

    def get(self, tagname):
        tag = self.db.get_tag(self.user, tagname)
        if tag:
            self.send_data(tag)
        else:
            self.send_error(404, reason='tag not found')

    def post(self, tagname):
        """rename a tag (merge with existing if already tag with new name"""

        tag = self.db.get_tag_object(self.user, tagname)
        if not tag:
            return self.send_error(404, reason='tag not found')

        # get the tag data
        try:
            data = json_decode(self.request.body)
        except json.JSONDecodeError as e:
            return self.send_error(400, reason='invalid json data (line {}, col {})'.format(e.lineno, e.colno))

        # tag name
        name = data.get('name', None)
        if name is not None:
            if not isinstance(name, str):
                return self.send_error(400, reason='missing or invalid new tagname')
            if invalid_tag_chars.search(name):
                return self.send_error(400, reason='invalid characters in tag name')
            if len(name) > cfg.tag_max_len:
                return self.send_error(400, reason='tag name too long')

        # index
        index = data.get('index', None)
        if index is not None:
            try:
                index = int(index)
            except:
                return self.send_error(400, reason='tag index invalid')

        # version
        version = data.get('version', None)
        if version is not None:
            try:
                version = int(version)
                assert(version > 0)
            except:
                return self.send_error(400, reason='tag index invalid')

        tag = self.db.update_tag(self.user, tag, name, index, version)
        if not tag:
            return self.send_error(500, reason='failed to update tag')
        return self.send_data(tag)

    def delete(self, tagname):
        """delete a tag by name if exists"""
        tag = self.db.get_tag_object(self.user, tagname)
        if not tag:
            return self.send_error(404, reason='tag doesn\'t exist')

        ok = self.db.del_tag(self.user, tag)
        if not ok:
            return self.send_error(500, reason='failed to delete tag')


class index_handler(ApiHandler):

    def get(self):
        length = self.get_query_argument('length', 100)
        since = self.get_query_argument('since', 0)
        mark = self.get_query_argument('mark', 0)

        try:
            length = int(length)
            since = float(since)
            mark = int(mark)
        except:
            return self.send_error(400, reason='invalid get parameter types')

        data = self.db.notes_index(self.user, length, since, mark)
        return self.write(data)


class tags_index_handler(ApiHandler):

    def get(self):
        length = self.get_query_argument('length', 100)
        mark = self.get_query_argument('mark', 0)

        try:
            length = int(length)
            mark = int(mark)
        except:
            return self.send_error(400, reason='invalid get parameter types')

        data = self.db.tags_index(self.user, length, mark)
        return self.write(data)

    def post(self):
        """create a tag"""

        # get the tag data
        try:
            data = json_decode(self.request.body)
        except json.JSONDecodeError as e:
            return self.send_error(400, reason='invalid json data (line {}, col {})'.format(e.lineno, e.colno))

        # tag name
        name = data.get('name', None)
        if name is not None:
            if not isinstance(name, str):
                return self.send_error(400, reason='missing or invalid new tagname')
            if invalid_tag_chars.search(name):
                return self.send_error(400, reason='invalid characters in tag name')
            if len(name) > cfg.tag_max_len:
                return self.send_error(400, reason='tag name too long')
        else:
            return self.send_error(400, reason='no tag name given')

        # index
        index = data.get('index', None)
        if index is not None:
            try:
                index = int(index)
            except:
                return self.send_error(400, reason='tag index invalid')

        # version
        version = data.get('version', None)
        if version is not None:
            try:
                version = int(version)
                assert(version > 0)
            except:
                return self.send_error(400, reason='tag index invalid')

        tag = self.db.create_tag(self.user, name, index, version)
        if not tag:
            return self.send_error(500, reason='failed to create tag')
        return self.write(tag)


class login_handler(BaseHandler):
    """handles token operations"""

    def post(self):
        """returns (and generates if needed) the api token for a user"""

        data = self.request.body
        creds = parse_qs(base64.decodebytes(data).decode(encoding='UTF-8'))

        if 'email' in creds and 'password' in creds:
            user = self.db.authenticate(creds['email'][0], creds['password'][0])
            if user:
                token = self.db.get_token(user)
                if token:
                    return self.write(token)
                else:
                    return self.send_error(500)
        return self.send_error(401)


def main():
    db = database.db(cfg.database_url)
    db.create_all()

    app = Application([
        url(r'^/api2/data/([^/]+)/?$', notes_handler),  # get/update/del note
        url(r'^/api2/data/([^/]+)/(\d+)/?$', notes_handler),  # note version
        url(r'^/api2/data/?$', notes_handler),  # create note
        url(r'^/api2/index/?$', index_handler),  # note index
        url(r'^/api2/tags/?$', tags_index_handler),  # tags index
        url(r'^/api2/tags/(.+)$', tags_handler),  # get/update/del tag
        url(r'^/api/login/?$', login_handler),  # login methods
        ],
        debug=cfg.debug,
        db=db
    )

    app.listen(cfg.listen_port, address=cfg.listen_host)
    tornado.ioloop.IOLoop.current().start()


if __name__ == '__main__':
    main()
