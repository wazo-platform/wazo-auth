"""add the group tenant relationship

Revision ID: 955c667efc65
Revises: 5a81ee363008

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '955c667efc65'
down_revision = '5a81ee363008'

TABLE = 'auth_group'
COL = 'tenant_uuid'

group_table = sa.sql.table('auth_group', sa.Column('uuid'), sa.Column('tenant_uuid'))
tenant_table = sa.sql.table('auth_tenant', sa.Column('uuid'), sa.Column('parent_uuid'))
user_group_table = sa.sql.table(
    'auth_user_group', sa.Column('user_uuid'), sa.Column('group_uuid')
)
user_table = sa.sql.table('auth_user', sa.Column('uuid'), sa.Column('tenant_uuid'))


def find_master_tenant():
    query = sa.sql.select([tenant_table.c.uuid]).where(
        tenant_table.c.uuid == tenant_table.c.parent_uuid
    )

    for row in op.get_bind().execute(query):
        return row.uuid

    raise Exception('Failed to find the TOP of the tenant tree')


def find_all_group_uuids():
    query = sa.sql.select([group_table.c.uuid])
    return [row.uuid for row in op.get_bind().execute(query)]


def find_all_users_in_group(group_uuid):
    query = sa.sql.select([user_group_table.c.user_uuid]).where(
        user_group_table.c.group_uuid == group_uuid
    )

    return [row.user_uuid for row in op.get_bind().execute(query)]


def get_user(user_uuid):
    query = sa.sql.select([user_table.c.tenant_uuid]).where(
        user_table.c.uuid == user_uuid
    )

    for row in op.get_bind().execute(query):
        return row


def update_group_tenant(group_uuid, tenant_uuid):
    filter_ = group_table.c.uuid == group_uuid
    query = group_table.update().values(tenant_uuid=tenant_uuid).where(filter_)
    op.execute(query)


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

    # If a group has one or more user, one of the user's tenant should be used.
    for group_uuid in find_all_group_uuids():
        user_uuids = find_all_users_in_group(group_uuid)
        for user_uuid in user_uuids:
            user = get_user(user_uuid)
            if not user:
                continue
            update_group_tenant(group_uuid, user.tenant_uuid)
            break


def downgrade():
    op.drop_column(TABLE, COL)
