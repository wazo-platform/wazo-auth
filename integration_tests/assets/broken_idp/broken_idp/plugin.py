# a wazo_auth.idp plugin implementation with a broken verify_auth method that never works

# import the base class
from flask import request

from wazo_auth import exceptions
from wazo_auth.interfaces import BaseAuthenticationBackend
from wazo_auth.plugins.idp.base import BaseIDP, BaseIDPDependencies


# this implementation always fails to load
class BrokenLoadIDP(BaseIDP):
    loaded = False
    authentication_method = 'broken_load'

    # a load method that fails
    def load(self, dependencies: BaseIDPDependencies):
        raise Exception('Broken load method')

    def can_authenticate(self, args: dict) -> bool:
        return False

    def verify_auth(self, args: dict) -> tuple[BaseAuthenticationBackend, str]:
        raise Exception()


class BrokenCanAuthenticateIDP(BaseIDP):
    loaded = False
    authentication_method = 'broken_can_authenticate'

    # a load method that does nothing
    def load(self, dependencies: BaseIDPDependencies):
        self.loaded = True

    def can_authenticate(self, args: dict) -> bool:
        raise Exception("Say what?")

    def verify_auth(self, args: dict) -> tuple[BaseAuthenticationBackend, str]:
        raise Exception()


class BrokenVerifyAuthIDP(BaseIDP):
    loaded = False
    authentication_method = 'broken_verify_auth'

    # a load method that does nothing
    def load(self, dependencies: BaseIDPDependencies):
        self.loaded = True

    def can_authenticate(self, args: dict) -> bool:
        custom_body_param = request.json.get('broken_verify_auth', False)
        return custom_body_param

    def verify_auth(self, args: dict) -> tuple[BaseAuthenticationBackend, str]:
        raise exceptions.UnknownLoginException(args['login'])


class BrokenVerifyAuthReplacementIDP(BaseIDP):
    loaded = False
    authentication_method = 'broken_verify_auth'

    # a load method that does nothing
    def load(self, dependencies: BaseIDPDependencies):
        self.backend = dependencies['backends']['wazo_user'].obj
        self.loaded = True

    def can_authenticate(self, args: dict) -> bool:
        custom_body_param = request.json.get('broken_verify_auth', False)
        return custom_body_param

    def verify_auth(self, args: dict) -> tuple[BaseAuthenticationBackend, str]:
        return self.backend, args['login']
