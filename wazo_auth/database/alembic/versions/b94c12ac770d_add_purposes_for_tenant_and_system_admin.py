"""add purposes for tenant and system admin

Revision ID: b94c12ac770d
Revises: 72c4a39fa885

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = 'b94c12ac770d'
down_revision = '72c4a39fa885'


def upgrade():
    add_purpose_tenant_admin()


def add_purpose_tenant_admin():
    # update all users with policy wazo_default_admin_policy
    query = '''
        UPDATE auth_user SET purpose = 'tenant_admin'
        WHERE uuid in (
          SELECT user_uuid FROM auth_user_policy
          JOIN auth_policy ON auth_policy.uuid = auth_user_policy.policy_uuid
          WHERE auth_policy.name = 'wazo_default_admin_policy'
        )
        AND purpose = 'user'
    '''
    op.execute(query)


def downgrade():
    reset_purpose_user()


def reset_purpose_user():
    query = '''
        UPDATE auth_user SET purpose = 'user'
        WHERE purpose == 'tenant_admin'
    '''
    op.execute(query)
