"""make group name unique inside tenant

Revision ID: e1b78cd7c702
Revises: bf0e37d18ef8

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = 'e1b78cd7c702'
down_revision = 'bf0e37d18ef8'


def upgrade():
    op.drop_constraint('auth_group_name_key', 'auth_group')
    op.create_unique_constraint(
        'auth_group_name_tenant', 'auth_group', ['name', 'tenant_uuid']
    )


def downgrade():
    op.drop_constraint('auth_group_name_tenant', 'auth_group')
    op.create_unique_constraint('auth_group_name_key', 'auth_group', ['name'])
