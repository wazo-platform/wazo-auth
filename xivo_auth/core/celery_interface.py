from xivo_auth.extensions import celery
from celery.utils import LOG_LEVELS
from multiprocessing import Process

def make_celery(app):
    app.config.update(
        CELERY_BROKER_URL=app.config["AMQP_URI"],
        CELERY_RESULT_BACKEND=app.config["AMQP_URI"],
        CELERY_ACCEPT_CONTENT = ['json'],
        CELERY_TASK_SERIALIZER = 'json',
        CELERY_RESULT_SERIALIZER = 'json',
        CELERY_ALWAYS_EAGER = False,
        CELERY_EAGER_PROPAGATES_EXCEPTIONS = True,
        CELERYD_LOG_LEVEL = LOG_LEVELS['DEBUG'],
        CELERY_DEFAULT_EXCHANGE_TYPE = 'topic',
    )
    celery.init_app(app)
    return app


class CeleryInterface(Process):
    def __init__(self):
        super(CeleryInterface, self).__init__()

    def run(self):
        print "Running celery interfaces"
        celery.worker_main()
