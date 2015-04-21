from flask import Blueprint, jsonify
from xivo_auth.extensions import httpauth
from models import User
from tasks import clean_session
from factory import consul

auth = Blueprint('auth', __name__, template_folder='templates')

@auth.route("/api/user")
@httpauth.login_required
def authenticate():
    session_id = create_session()
    task = clean_session.apply_async(args=[session_id,], countdown=5)
    return jsonify({'data': {'task': task.id, 'session': session_id}})

@httpauth.verify_password
def verify_password(login, passwd):
    user = User.query.filter_by(loginclient = login).first()
    if not user or not user.verify_password(passwd):
        return False
    return True

def create_session():
   return consul.session.create()
