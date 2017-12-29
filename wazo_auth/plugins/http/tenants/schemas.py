# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from xivo.mallow import fields
from xivo.mallow import validate
from wazo_auth.schemas import BaseSchema


class TenantRequestSchema(BaseSchema):

    name = fields.String(validate=validate.Length(min=1, max=128), missing=None)
