# Copyright 2016-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import uuid

from hamcrest import assert_that, calling, equal_to
from xivo_test_helpers.hamcrest.raises import raises

from wazo_auth import exceptions
from wazo_auth.database import models
from .helpers import fixtures, base
from .helpers.constants import UNKNOWN_UUID

SESSION_UUID_1 = str(uuid.uuid4())


@base.use_asset('database')
class TestEmailDAO(base.DAOTestCase):
    @fixtures.db.email()
    def test_confirm(self, email_uuid):
        assert_that(self.is_email_confirmed(email_uuid), equal_to(False))
        assert_that(
            calling(self._email_dao.confirm).with_args(UNKNOWN_UUID),
            raises(exceptions.UnknownEmailException),
        )
        self._email_dao.confirm(email_uuid)
        assert_that(self.is_email_confirmed(email_uuid), equal_to(True))

    def is_email_confirmed(self, email_uuid):
        emails = self.session.query(models.Email).filter(
            models.Email.uuid == str(email_uuid)
        )
        for email in emails.all():
            return email.confirmed
        return False
