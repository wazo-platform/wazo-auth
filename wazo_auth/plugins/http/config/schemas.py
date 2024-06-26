# Copyright 2021-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from marshmallow import Schema
from marshmallow.validate import Equal, OneOf
from xivo.mallow import fields


class ConfigPatchSchema(Schema):
    op = fields.String(validate=Equal('replace'))
    path = fields.String(validate=OneOf(['/debug', '/profiling_enabled']))
    value = fields.Boolean()


config_patch_schema = ConfigPatchSchema()
