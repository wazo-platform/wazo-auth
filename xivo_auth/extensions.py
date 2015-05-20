from flask.ext.cors import CORS
cors = CORS()

from flask.ext.httpauth import HTTPBasicAuth
httpauth = HTTPBasicAuth()

from blinker import Namespace
token_signals = Namespace()
auth_token = token_signals.signal('auth-token')

consul = None
celery = None
