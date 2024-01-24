"""make_session_multi_tenant

Revision ID: 53a816c76f56
Revises: 976f73df0476

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '53a816c76f56'
down_revision = '976f73df0476'

TABLE = 'auth_session'
COL = 'tenant_uuid'

session_table = sa.sql.table(
    'auth_session', sa.Column('uuid'), sa.Column('tenant_uuid')
)
tenant_table = sa.sql.table('auth_tenant', sa.Column('uuid'), sa.Column('parent_uuid'))


def find_master_tenant():
    query = sa.sql.select([tenant_table.c.uuid]).where(
        tenant_table.c.uuid == tenant_table.c.parent_uuid
    )

    for row in op.get_bind().execute(query):
        return row.uuid

    raise Exception('Failed to find the TOP of the tenant tree')


def upgrade():
    master_tenant = find_master_tenant()
    op.add_column(
        TABLE,
        sa.Column(
            COL,
            sa.String(38),
            sa.ForeignKey('auth_tenant.uuid', ondelete='CASCADE'),
            server_default=master_tenant,
            nullable=False,
        ),
    )
    op.alter_column(TABLE, COL, nullable=False, server_default=None)


def downgrade():
    op.drop_column(TABLE, COL)
