import logging
from flask import Flask, redirect, url_for, render_template

def create_app():
    app = Flask(__name__)
    configure_logging(app)
    configure_app(app)

    return app


def configure_app(app):
    app.logger.info("Loading configuration")
    app.config.from_object('xivo_auth.settings')


def configure_logging(app):
    app.logger.addHandler(logging.StreamHandler())
    app.logger.setLevel(logging.INFO)
    app.logger.info("Logger started")
