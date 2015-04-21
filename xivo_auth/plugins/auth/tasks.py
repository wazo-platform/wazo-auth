from xivo_auth.extensions import celery
from factory import consul
import json


@celery.task(bind=True)
def clean_session(self, session):
    print "Lancement session: %s" % session
    consul.session.destroy(session)
    return json.dumps({'data': 'Session cleaned...'})
