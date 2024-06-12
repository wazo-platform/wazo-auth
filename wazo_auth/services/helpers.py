# Copyright 2018-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import os

from jinja2 import BaseLoader, Environment, TemplateNotFound

logger = logging.getLogger(__name__)


class BaseService:
    def __init__(self, dao):
        self._dao = dao
        self._top_tenant_uuid = None

    def _get_scoped_tenant_uuids(self, scoping_tenant_uuid, recurse):
        if not recurse:
            return [scoping_tenant_uuid]

        visible_tenants = self._dao.tenant.list_visible_tenants(scoping_tenant_uuid)
        return [tenant.uuid for tenant in visible_tenants]

    @property
    def top_tenant_uuid(self):
        if not self._top_tenant_uuid:
            self._top_tenant_uuid = self._dao.tenant.find_top_tenant()
        return self._top_tenant_uuid

    def list_visible_tenant_uuids_with_slugs(self, scoping_tenant_uuid):
        visible_tenants = self._dao.tenant.list_visible_tenants(scoping_tenant_uuid)
        return [(tenant.uuid, tenant.slug) for tenant in visible_tenants]


class TemplateLoader(BaseLoader):
    _templates = {
        'email_confirmation': 'email_confirmation_template',
        'email_confirmation_get_body': 'email_confirmation_get_response_body_template',
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
        self.environment = Environment(loader=TemplateLoader(config))

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
