"""add wazo-all-users group

Revision ID: 16f98957ec7e
Revises: 91e8de642bee

"""

# revision identifiers, used by Alembic.
revision = '16f98957ec7e'
down_revision = '91e8de642bee'

from alembic import op
import sqlalchemy as sa

group_table = sa.sql.table(
    'auth_group', sa.Column('uuid'), sa.Column('tenant_uuid'), sa.Column('name')
)
tenant_table = sa.sql.table('auth_tenant', sa.Column('uuid'), sa.Column('parent_uuid'))


def all_tenant_uuids():
    query = sa.sql.select([tenant_table.c.uuid])
    for row in op.get_bind().execute(query):
        yield row.uuid


def create_wazo_all_users_group(tenant_uuid):
    query = (
        group_table.insert()
        .returning(group_table.c.uuid)
        .values(name=f'wazo-all-users-tenant-{tenant_uuid}', tenant_uuid=tenant_uuid)
    )
    group_uuid = op.get_bind().execute(query).scalar()

    return group_uuid


def delete_wazo_all_users_group(tenant_uuid):
    query = group_table.delete().where(
        group_table.c.name == f'wazo-all-users-tenant-{tenant_uuid}'
    )
    op.execute(query)


def upgrade():
    for tenant_uuid in all_tenant_uuids():
        group_uuid = create_wazo_all_users_group(tenant_uuid)


def downgrade():
    for tenant_uuid in all_tenant_uuids():
        delete_wazo_all_users_group(tenant_uuid)
