# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Avencall
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

import xivo_dao

from xivo_auth import BasePlugin
from xivo_auth.extensions import sqlalchemy as db
from views import auth


class XiVOAuth(BasePlugin):

    def load(self, app):
        pg_url = "postgresql://asterisk:proformatique@10.37.0.254/asterisk"
        app.config['SQLALCHEMY_DATABASE_URI'] = pg_url
        app.register_blueprint(auth)
        xivo_dao.init_db_from_config({'db_uri': pg_url})
        db.init_app(app)
