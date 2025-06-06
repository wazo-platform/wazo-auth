# Copyright 2019-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from wazo_auth.interfaces import IDPPlugin, IDPPluginDependencies


class BaseIDPDependencies(IDPPluginDependencies):
    pass


class BaseIDP(IDPPlugin):
    def load(self, dependencies: BaseIDPDependencies):
        pass
