"""add indices for foreign keys

Revision ID: 8216b7bb88db
Revises: 8a04704df15a

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = '8216b7bb88db'
down_revision = '8a04704df15a'


def upgrade():
    op.create_index(
        'auth_address__idx__tenant_uuid',
        'auth_address',
        ['tenant_uuid'],
    )
    op.create_index(
        'auth_email__idx__user_uuid',
        'auth_email',
        ['user_uuid'],
    )
    op.create_index(
        'auth_external_auth_config__idx__type_uuid',
        'auth_external_auth_config',
        ['type_uuid'],
    )
    op.create_index(
        'auth_group__idx__tenant_uuid',
        'auth_group',
        ['tenant_uuid'],
    )
    op.create_index(
        'auth_tenant__idx__contact_uuid',
        'auth_tenant',
        ['contact_uuid'],
    )
    op.create_index(
        'auth_tenant__idx__parent_uuid',
        'auth_tenant',
        ['parent_uuid'],
    )
    op.create_index(
        'auth_tenant_domain__idx__tenant_uuid',
        'auth_tenant_domain',
        ['tenant_uuid'],
    )
    op.create_index(
        'auth_refresh_token__idx__user_uuid',
        'auth_refresh_token',
        ['user_uuid'],
    )
    op.create_index(
        'auth_session__idx__tenant_uuid',
        'auth_session',
        ['tenant_uuid'],
    )
    op.create_index(
        'auth_policy__idx__tenant_uuid',
        'auth_policy',
        ['tenant_uuid'],
    )
    op.create_index(
        'auth_user__idx__tenant_uuid',
        'auth_user',
        ['tenant_uuid'],
    )


def downgrade():
    op.drop_index('auth_user__idx__tenant_uuid')
    op.drop_index('auth_policy__idx__tenant_uuid')
    op.drop_index('auth_session__idx__tenant_uuid')
    op.drop_index('auth_refresh_token__idx__user_uuid')
    op.drop_index('auth_tenant_domain__idx__tenant_uuid')
    op.drop_index('auth_tenant__idx__parent_uuid')
    op.drop_index('auth_tenant__idx__contact_uuid')
    op.drop_index('auth_group__idx__tenant_uuid')
    op.drop_index('auth_external_auth_config__idx__type_uuid')
    op.drop_index('auth_email__idx__user_uuid')
    op.drop_index('auth_address__idx__tenant_uuid')
