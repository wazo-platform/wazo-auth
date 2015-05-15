import abc


class BasePlugin(object):

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def load(self, app, config):
        pass

    def unload(self):
        pass
