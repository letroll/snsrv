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
            return self.send_error(400)

        if version is not None:
            try:
                version = int(version)
            except:
                return self.send_error(400, reason='invalid version type')

        note = self.db.get_note(self.user, key, version)
        if not note:
            return self.send_error(404, reason='bookmark not found')

        self.send_data(note)

    def _create_note(self, data):
        """creates a new note - data is sanitized"""
            # # update note - must save old version
            # if key is not None and content != note.content:
            #     self.db.save_version(note)

        # TODO: check syncnum/version/modifydate to ensure old notes don't
        # overwrite new notes...
        pass

    def _update_note(self, key, data):
        """updates a note - data is sanitized"""

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
                assert(modify >= 0 and modify <= now)
            except:
                return self.send_error(400, reason='invalid modifydate')
        safe_data['modify'] = modify

        # createdate
        create = data.get('createdate', None)
        if create is not None:
            try:
                create = float(create)
                assert(create >= 0 and create <= now)
            except:
                return self.send_error(400, reason='invalid createdate')
        safe_data['create'] = create

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
                for tag in systemtags:
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
                return self.send_error(401, reason='invalid content')
        safe_data['content'] = content

        # note to build on
        if key is not None:
            self._update_note(key, safe_data)
        else:
            self._create_note(safe_data)

    def delete(self, key=None):
        """delete a note if exists"""
        note = self.db.get_note(self.user, key)
        if not note:
            return self.send_error(404, reason='note not found')

        res = self.db.delete_note(self.user, note);
        if res:
            return

        self.send_error(500, reason='error deleting note from database')


class tags_handler(ApiHandler):
    """handles requests for tag operations"""

    def get(self, tagname=None):
        """Return list of all tags"""
        if tagname is None:
            tags = self.db.get_tags(self.user)
            if tags is None:
                return self.send_error(500, reason='failed retrieving tags')
            self.send_data(tags)
        else:
            tag = self.db.get_tag(self.user, tagname)
            if tag:
                self.send_data(tag)
            else:
                self.send_error(404, reason='tag name not found')

    def delete(self, tagname=None):
        """delete a tag by name if exists"""
        status, ok = self.db.del_tag(self.user, tagname)
        if status == 404:
            return self.send_error(404, reason="tag doesn't exist")
        elif status == 500:
            return self.send_error(500, reason="failed to delete tag (database error)")
        else:
            return self.send_data(None)

    def post(self, tagname=None):
        """rename a tag (merge with existing if already tag with new name"""
        if not tagname:
            return self.send_error(400, reason='cannot update without a tag name)')

        try:
            data = json_decode(self.request.body)
        except json.JSONDecodeError as e:
            return self.send_error(400, reason='invalid json data (line {}, col {})'.format(e.lineno, e.colno))
        name = data.get('name', None)
        if not isinstance(name, str):
            return self.send_error(400, reason='missing or invalid new tagname')

        if len(name) > cfg.bm_tag_max_len:
            return self.send_error(400, reason='tag name too long')

        status, tag = self.db.rename_tag(self.user, tagname, name)
        if status == 404:
            return self.send_error(404, reason="tag doesn't exist")
        elif status == 500:
            return self.send_error(500, reason="failed to rename tag (database error)")
        else: # status == 200
            return self.send_data(tag)

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
