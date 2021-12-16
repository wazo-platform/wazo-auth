"""make policy names unique in a tenant

Revision ID: 5a81ee363008
Revises: df074292741f

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = '5a81ee363008'
down_revision = 'df074292741f'


def upgrade():
    op.drop_constraint('auth_policy_name', 'auth_policy')
    op.create_unique_constraint(
        'auth_policy_name_tenant', 'auth_policy', ['name', 'tenant_uuid']
    )


def downgrade():
    op.drop_constraint('auth_policy_name_tenant', 'auth_policy')
    op.create_unique_constraint('auth_policy_name', 'auth_policy', ['name'])
