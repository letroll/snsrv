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
import base64

import database
import config as cfg
import utils
from basehanders import ApiHandler, BaseHandler


class notes_handler(ApiHandler):
    """handles specific notes requests"""

    def _notes_list(self):
        since = self.get_query_argument('since', None)
        upto = self.get_query_argument('upto', None)
        tags = self.get_query_argument('tags', None)

        if since:
            try:
                since = float(since)
            except:
                return self.send_error(400, reason='invalid "since" value')
        if upto:
            try:
                upto = float(upto)
            except:
                return self.send_error(400, reason='invalid "upto" value')

        if tags:
            tags = tags.split(',')
            tags = set(t for t in tags if t)
            if len(tags) > 3 or len(tags) == 0:
                return self.send_error(400, reason='invalid number of tags (must be from 1 to 3 if specified)')

        return self.db.get_bookmarks(self.user, since, upto, tags)

    def get(self, key=None, version=None):
        """return the note by key"""
        if not key:
            return self.send_error(400)

        if version:
            # send the version of note by key
            note = self.db.get_version(self.user, key)
        else:
            # send the actual note
            note = self.db.get_note(self.user, key)
        if not note:
            return self.send_error(404, reason='bookmark not found')

        self.send_data(note)

    def post(self, key=None):
        """create or update a note"""
        now = utils.now()
        default = {
               'deleted': 0,
               'createdate': now,
               'modifydate': now,
               'syncnum': 0,
               'version': 1,
               'systemtags': [],
               'tags': [],
                 }

        # get the posted data
        data = {}
        try:
            data = json_decode(self.request.body)
        except json.JSONDecodeError as e:
            return self.send_error(400, reason='invalid json data (line {}, col {})'.format(e.lineno, e.colno))

        if key is not None:
            # then lets update the existing note
            pass  # TODO

        else:
            # create new note
            pass  # TODO

        create = data.get('create', default['create'])
        try:
            create = float(create)
            if create > now:
                create = now
        except:
            return self.send_error(400, reason='invalid creation date supplied')

        # setup the modification date
        modify = data.get('modify', default['modify'])

        note = self.db.create_bookmark(self.user, notedata)
        if not note:
            return self.send_error(400, reason='failed to create/update bookmark in database')

        self.send_data(note)

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
        # TODO: notes index
        pass


class tags_index_handler(ApiHandler):

    def get(self):
        # TODO: tags index
        pass


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

    # def delete(self):
    #     ok = self.db.del_token()
    #     if ok:
    #         return self.send_data(None)
    #     self.send_error(500, "unable to delete token")



def main():
    db = database.db(cfg.database_url)
    db.create_all()

    app = Application([
        url(r'^/api2/data/([^/]+)/?$', notes_handler), # get/update/delete note
        url(r'^/api2/data/([^/]+)/(\d+)/?$', notes_handler), # get note version
        url(r'^/api2/data/?$', notes_handler), # create note
        url(r'^/api2/index/?$', index_handler), # note index
        url(r'^/api2/tags/?$', tags_index_handler), # tags index
        url(r'^/api2/tags/([^/,]+)/?$', tags_handler), # get/update/delete tag
        url(r'^/api/login/?$', login_handler), # login methods
        ],
        debug=cfg.debug,
        db=db
    )

    app.listen(cfg.listen_port, address=cfg.listen_host)
    tornado.ioloop.IOLoop.current().start()


if __name__ == '__main__':
    main()
