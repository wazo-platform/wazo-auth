import unittest
from typing import Any, Optional
from unittest.mock import Mock

from wazo_auth.plugin_helpers.backend_mixins import MetadataByPurposeMixin
from wazo_auth.services import UserService


class MockPurpose:
    def __init__(self, metadata_plugins: Optional[list] = None):
        self.metadata_plugins = metadata_plugins or []


class MockPurposes:
    def __init__(self, purposes: dict[str, MockPurpose]) -> None:
        self._purposes = purposes

    def get(self, purpose: str) -> MockPurpose:
        return self._purposes[purpose]

    def __getitem__(self, key: str) -> MockPurpose:
        return self._purposes[key]


class MockMetadata:
    def __init__(self, name: str) -> None:
        self._namespace = f'test.{name}'
        self._depends: dict[str, Any] = {}

    def load(self, dependencies: dict[str, Any]) -> None:
        pass


class MetadataByPurposeBackend(MetadataByPurposeMixin):
    _purposes: MockPurposes
    _user_service: UserService

    def __init__(self, purposes, user_service):
        self._purposes = purposes
        self._user_service = user_service


class TestMetadataByPurposeMixin(unittest.TestCase):
    def setUp(self):
        self.metadata_plugin1 = MockMetadata('plugin1')
        self.metadata_plugin2 = MockMetadata('plugin2')

        purposes_dict = {
            'purpose1': MockPurpose([self.metadata_plugin1]),
            'purpose2': MockPurpose([self.metadata_plugin2]),
        }

        self.purposes = MockPurposes(purposes_dict)
        self.user_service = Mock()
        self.user_service.get_user_uuid_by_login.return_value = 'user-uuid'
        self.user_service.list_users.return_value = [{'purpose': 'purpose1'}]

        self.mixin = MetadataByPurposeBackend(self.purposes, self.user_service)

    def test_get_metadata_plugins_by_purpose(self):
        result = self.mixin.get_metadata_plugins_by_purpose('purpose1')
        self.assertEqual(result, [self.metadata_plugin1])

        result = self.mixin.get_metadata_plugins_by_purpose('purpose2')
        self.assertEqual(result, [self.metadata_plugin2])

    def test_get_metadata_plugins_by_login(self):
        self.user_service.get_user_uuid_by_login.return_value = 'test-uuid'
        self.user_service.list_users.return_value = [{'purpose': 'purpose2'}]

        result = self.mixin.get_metadata_plugins_by_login('test-login')

        self.user_service.get_user_uuid_by_login.assert_called_once_with('test-login')
        self.assertEqual(result, [self.metadata_plugin2])

    def test_get_metadata_plugins_by_uuid(self):
        self.user_service.list_users.return_value = [{'purpose': 'purpose1'}]

        result = self.mixin.get_metadata_plugins_by_uuid('test-uuid')

        self.user_service.list_users.assert_called_once_with(uuid='test-uuid')
        self.assertEqual(result, [self.metadata_plugin1])

    def test_get_metadata_plugins_by_uuid_user_not_found(self):
        self.user_service.list_users.return_value = []

        with self.assertRaises(IndexError):
            self.mixin.get_metadata_plugins_by_uuid('non-existent-uuid')

    def test_get_metadata_plugins_by_purpose_not_found(self):
        with self.assertRaises(KeyError):
            self.mixin.get_metadata_plugins_by_purpose('non-existent-purpose')
