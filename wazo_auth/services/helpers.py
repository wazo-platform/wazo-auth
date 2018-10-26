# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import logging
import os

from jinja2 import BaseLoader, Environment, TemplateNotFound
from anytree import Node, PreOrderIter

from xivo.consul_helpers import address_from_config

logger = logging.getLogger(__name__)


class BaseService:

    def __init__(self, dao, tenant_tree):
        self._dao = dao
        self._top_tenant_uuid = None
        self._tenant_tree = tenant_tree

    def _get_scoped_tenant_uuids(self, scoping_tenant_uuid, recurse):
        if recurse:
            return self._tenant_tree.list_nodes(scoping_tenant_uuid)

        return [scoping_tenant_uuid]

    @property
    def top_tenant_uuid(self):
        if not self._top_tenant_uuid:
            self._top_tenant_uuid = self._dao.tenant.find_top_tenant()
        return self._top_tenant_uuid


class TemplateLoader(BaseLoader):

    _templates = {
        'email_confirmation': 'email_confirmation_template',
        'email_confirmation_get_body': 'email_confirmation_get_reponse_body_template',
        'email_confirmation_subject': 'email_confirmation_subject_template',
        'reset_password': 'password_reset_email_template',
        'reset_password_subject': 'password_reset_email_subject_template',
    }

    def __init__(self, config):
        self._config = config

    def get_source(self, environment, template):
        config_key = self._templates.get(template)
        if not config_key:
            raise TemplateNotFound(template)

        template_path = self._config[config_key]
        if not os.path.exists(template_path):
            raise TemplateNotFound(template)

        mtime = os.path.getmtime(template_path)
        with open(template_path) as f:
            source = f.read()

        return source, template_path, lambda: mtime == os.path.getmtime(template_path)


class TemplateFormatter:

    def __init__(self, config):
        self.environment = Environment(
            loader=TemplateLoader(config),
        )
        self.environment.globals['port'] = config['service_discovery']['advertise_port']
        self.environment.globals['hostname'] = address_from_config(config['service_discovery'])

    def format_confirmation_email(self, context):
        template = self.environment.get_template('email_confirmation')
        return template.render(**context)

    def get_confirmation_email_get_body(self, context=None):
        context = context or {}
        template = self.environment.get_template('email_confirmation_get_body')
        return template.render(**context)

    def format_confirmation_subject(self, context):
        template = self.environment.get_template('email_confirmation_subject')
        return template.render(**context)

    def format_password_reset_email(self, context):
        template = self.environment.get_template('reset_password')
        return template.render(**context)

    def format_password_reset_subject(self, context):
        template = self.environment.get_template('reset_password_subject')
        return template.render(**context)


class TenantTree:

    def __init__(self, tenant_dao):
        self._tenant_dao = tenant_dao
        self._tenant_tree = None

    def list_nodes(self, nid):
        tree = self._build_tree(self._tenant_dao.list_())
        subtree = self._find_subtree(tree, nid)
        return [n.name for n in PreOrderIter(subtree)]

    def _find_subtree(self, tree, uuid):
        for node in PreOrderIter(tree):
            if node.name == uuid:
                return node

    def _build_tree(self, tenants):
        logger.debug('rebuilding tenant tree')
        nb_tenants = len(tenants)
        inserted_tenants = set()

        for tenant in tenants:
            if tenant['uuid'] == tenant['parent_uuid']:
                top = Node(tenant['uuid'])
                inserted_tenants.add(tenant['uuid'])

        while True:
            if len(inserted_tenants) == nb_tenants:
                break

            for tenant in tenants:
                if tenant['uuid'] in inserted_tenants:
                    continue

                if tenant['parent_uuid'] not in inserted_tenants:
                    continue

                parent = self._find_subtree(top, tenant['parent_uuid'])
                if not parent:
                    raise Exception('Could not find parent in tree')

                Node(tenant['uuid'], parent=parent)
                inserted_tenants.add(tenant['uuid'])

        return top
