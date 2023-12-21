"""add_tenant_parent_uuid

Revision ID: bbd6a0735a7b
Revises: 13295ff5b213

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'bbd6a0735a7b'
down_revision = '13295ff5b213'

TABLE = 'auth_tenant'
COL = 'parent_uuid'
INITIAL_TENANT = 'master'
tenant_table = sa.sql.table('auth_tenant', sa.Column('uuid'), sa.Column('name'))


def upgrade():
    query = (
        tenant_table.insert().returning(tenant_table.c.uuid).values(name=INITIAL_TENANT)
    )
    tenant_uuid = op.get_bind().execute(query).scalar()

    op.add_column(
        TABLE,
        sa.Column(
            COL,
            sa.String(38),
            sa.ForeignKey('auth_tenant.uuid'),
            server_default=tenant_uuid,
            nullable=False,
        ),
    )
    op.alter_column(TABLE, COL, nullable=False, server_default=None)


def downgrade():
    op.drop_column(TABLE, COL)

    query = tenant_table.delete().where(tenant_table.c.name == INITIAL_TENANT)
    op.get_bind().execute(query)
