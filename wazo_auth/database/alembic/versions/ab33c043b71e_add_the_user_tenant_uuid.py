"""add the user tenant_uuid

Revision ID: ab33c043b71e
Revises: bbd6a0735a7b

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'ab33c043b71e'
down_revision = 'bbd6a0735a7b'

TABLE = 'auth_user'
COL = 'tenant_uuid'
tenant_table = sa.sql.table('auth_tenant', sa.Column('uuid'), sa.Column('parent_uuid'))


def upgrade():
    query = sa.sql.select([tenant_table.c.uuid]).where(
        tenant_table.c.uuid == tenant_table.c.parent_uuid
    )

    for row in op.get_bind().execute(query):
        tenant_uuid = row.uuid
        break
    else:
        raise Exception('Failed to find the TOP of the tenant tree')

    op.add_column(
        TABLE,
        sa.Column(
            COL,
            sa.String(38),
            sa.ForeignKey('auth_tenant.uuid', ondelete='CASCADE'),
            server_default=tenant_uuid,
            nullable=False,
        ),
    )
    op.alter_column(TABLE, COL, nullable=False, server_default=None)


def downgrade():
    op.drop_column(TABLE, COL)
