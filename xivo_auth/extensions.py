from flask.ext.sqlalchemy import SQLAlchemy
sqlalchemy = SQLAlchemy()

from flask.ext.cors import CORS
cors = CORS()

from flask.ext.celery import Celery
celery = Celery()

from flask.ext.httpauth import HTTPBasicAuth
httpauth = HTTPBasicAuth()
