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
user_group_table = sa.sql.table(
    'auth_user_group',
    sa.Column('user_uuid'),
    sa.Column('group_uuid'),
    sa.Column('tenant_uuid'),
)
user_table = sa.sql.table(
    'auth_user',
    sa.Column('uuid'),
    sa.Column('tenant_uuid', None, sa.ForeignKey('auth_tenant.uuid')),
)


def rename_groups_already_present():
    group_name_query = sa.sql.select(
        [sa.sql.functions.concat('wazo-all-users-tenant-', tenant_table.c.uuid)]
    ).select_from(tenant_table)
    group_uuid_query = sa.sql.select([group_table.c.uuid]).where(
        group_table.c.name.in_(group_name_query)
    )
    update_query = (
        group_table.update()
        .values(
            {group_table.c.name: sa.sql.functions.concat(group_table.c.name, '-old')}
        )
        .where(group_table.c.uuid.in_(group_uuid_query))
    )
    op.get_bind().execute(update_query)


def create_wazo_all_users_group():
    group_query = sa.sql.select(
        [
            sa.sql.functions.concat('wazo-all-users-tenant-', tenant_table.c.uuid),
            tenant_table.c.uuid,
        ]
    ).select_from(tenant_table)
    query = (
        group_table.insert()
        .returning(group_table.c.uuid)
        .from_select([group_table.c.name, group_table.c.tenant_uuid], group_query)
    )
    group_uuids = op.get_bind().execute(query)

    return [row.uuid for row in group_uuids]


def delete_wazo_all_users_group():
    query = group_table.delete().where(
        group_table.c.name.in_(
            sa.sql.select(
                [
                    sa.sql.functions.concat(
                        'wazo-all-users-tenant-', tenant_table.c.uuid
                    ),
                ]
            ).select_from(tenant_table)
        )
    )
    op.execute(query)


def add_all_users_in_group(group_uuids):
    group_members_query = (
        sa.sql.select([user_table.c.uuid, group_table.c.uuid])
        .select_from(
            user_table.join(
                tenant_table, user_table.c.tenant_uuid == tenant_table.c.uuid
            ).join(group_table, tenant_table.c.uuid == group_table.c.tenant_uuid)
        )
        .where(group_table.c.uuid.in_(group_uuids))
    )
    query = user_group_table.insert().from_select(
        [user_group_table.c.user_uuid, user_group_table.c.group_uuid],
        group_members_query,
    )
    op.get_bind().execute(query)


def upgrade():
    rename_groups_already_present()
    group_uuids = create_wazo_all_users_group()
    add_all_users_in_group(group_uuids)


def downgrade():
    delete_wazo_all_users_group()
