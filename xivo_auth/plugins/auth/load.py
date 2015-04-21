from xivo_auth import BasePlugin
from xivo_auth.extensions import sqlalchemy as db
from views import auth

class XiVOAuth(BasePlugin):
    def load(self, app):
        app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://asterisk:proformatique@10.41.0.104/asterisk"
        app.register_blueprint(auth)
        db.init_app(app)
