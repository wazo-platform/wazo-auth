"""remove check constraint on authentication_method

Revision ID: 8c14d2c98235
Revises: ee3444ea3a43

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '8c14d2c98235'
down_revision = 'ee3444ea3a43'

AUTH_USER_AUTHENTICATION_METHOD_CHECK_CONSTRAINT = (
    'auth_user_authentication_method_check'
)
AUTH_TENANT_DEFAULT_AUTHENTICATION_METHOD_CHECK_CONSTRAINT = (
    'auth_tenant_default_authentication_method_check'
)


def upgrade():
    # drop auth_user constraint
    op.drop_constraint(AUTH_USER_AUTHENTICATION_METHOD_CHECK_CONSTRAINT, 'auth_user')
    # drop auth_tenant constraint
    op.drop_constraint(
        AUTH_TENANT_DEFAULT_AUTHENTICATION_METHOD_CHECK_CONSTRAINT, 'auth_tenant'
    )


def downgrade():
    # recreate check constraint
    op.create_check_constraint(
        AUTH_TENANT_DEFAULT_AUTHENTICATION_METHOD_CHECK_CONSTRAINT,
        'auth_tenant',
        sa.text("default_authentication_method in ('native', 'ldap', 'saml')"),
    )
    # recreate check constraint
    op.create_check_constraint(
        AUTH_USER_AUTHENTICATION_METHOD_CHECK_CONSTRAINT,
        'auth_user',
        sa.text("authentication_method in ('default', 'native', 'ldap', 'saml')"),
    )
