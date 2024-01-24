"""remove-config-managed-policies-from-tenant

Revision ID: 56cea38f6815
Revises: caede349e1ab

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '56cea38f6815'
down_revision = 'caede349e1ab'

tenant_tbl = sa.sql.table(
    'auth_tenant',
    sa.Column('uuid'),
    sa.Column('parent_uuid'),
)
policy_tbl = sa.sql.table(
    'auth_policy',
    sa.Column('config_managed'),
    sa.Column('tenant_uuid'),
)


def find_master_tenant():
    query = sa.sql.select([tenant_tbl.c.uuid]).where(
        tenant_tbl.c.uuid == tenant_tbl.c.parent_uuid
    )

    for row in op.get_bind().execute(query):
        return row.uuid

    raise Exception('Failed to find the TOP of the tenant tree')


def upgrade():
    master_tenant = find_master_tenant()
    query = (
        policy_tbl.delete()
        .where(policy_tbl.c.tenant_uuid != master_tenant)
        .where(policy_tbl.c.config_managed.is_(True))
    )
    op.execute(query)


def downgrade():
    pass
