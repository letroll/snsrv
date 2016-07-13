# These inherit from RequestHander and should be inherited by specific route
# handlers. They provide authentication methods and such.

from tornado.web import RequestHandler

import config as cfg


class BaseHandler(RequestHandler):

    def initialize(self):
        self.db = self.settings.get('db')
        self.user = None

    def send_data(self, data):
        """writes the json data with status message (basic wrapper)"""
        self.write(data);

    def write_error(self, status, **kwargs):
        # don't bother writing anything in response body
        pass

    def set_default_headers(self):
        self.set_header("Access-Control-Allow-Origin", cfg.cors_origin)
        pass


class ApiHandler(BaseHandler):
    """base handler for all api handlers
       handles authentication, returns errors, etc."""

    # also sets current_user
    def prepare(self):
        token = self.get_query_argument('auth', None)
        email = self.get_query_argument('email', None)
        if not email:
            return self.send_error(401, reason='email get parameter missing')
        elif not token:
            return self.send_error(401, reason='auth get parameter missing')

        self.user = self.db.authenticate_token(email, token)

        if not self.user:
            print("sending error")
            return self.send_error(401, reason='invalid credentials')

        self.current_user = self.user.email
