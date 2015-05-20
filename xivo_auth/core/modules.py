import abc


class BaseAuthenticationBackend(object):

    __metaclass__ = abc.ABCMeta

    def __init__(self, config):
        pass

    @abc.abstractmethod
    def get_uuid(self, identifier):
        """Returns the uuid of the given user's identifier"""

    @abc.abstractmethod
    def verify_password(self, identifier, passwd):
        """Returns True or False for the given user's identifier/password combination"""


class BasePlugin(object):

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def load(self, app, config):
        pass

    def unload(self):
        pass
