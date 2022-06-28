"""move root to super admin policy

Revision ID: bf0e37d18ef8
Revises: 72c4a39fa885

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'bf0e37d18ef8'
down_revision = '72c4a39fa885'

policy_table = sa.sql.table('auth_policy', sa.Column('uuid'), sa.Column('name'))
user_table = sa.sql.table('auth_user', sa.Column('uuid'), sa.Column('username'))
user_policy_table = sa.sql.table(
    'auth_user_policy', sa.Column('user_uuid'), sa.Column('policy_uuid')
)

DEFAULT_ADMIN_POLICY_NAME = 'wazo_default_admin_policy'
DEFAULT_MASTER_USER_POLICY_NAME = 'wazo_default_master_user_policy'
ROOT_USERNAME = 'root'


def find_root_user_uuid():
    query = sa.sql.select([user_table.c.uuid]).where(
        user_table.c.username == ROOT_USERNAME
    )
    return op.get_bind().execute(query).scalar()


def find_policy_uuid(policy_name):
    query = sa.sql.select([policy_table.c.uuid]).where(
        policy_table.c.name == policy_name
    )
    return op.get_bind().execute(query).scalar()


def upgrade():
    root_user_uuid = find_root_user_uuid()
    default_admin_policy_uuid = find_policy_uuid(DEFAULT_ADMIN_POLICY_NAME)
    master_user_policy_uuid = find_policy_uuid(DEFAULT_MASTER_USER_POLICY_NAME)
    query = (
        user_policy_table.update()
        .values(policy_uuid=master_user_policy_uuid)
        .where(
            sa.and_(
                user_policy_table.c.user_uuid == root_user_uuid,
                user_policy_table.c.policy_uuid == default_admin_policy_uuid,
            )
        )
    )
    op.execute(query)


def downgrade():
    root_user_uuid = find_root_user_uuid()
    default_admin_policy_uuid = find_policy_uuid(DEFAULT_ADMIN_POLICY_NAME)
    master_user_policy_uuid = find_policy_uuid(DEFAULT_MASTER_USER_POLICY_NAME)
    query = (
        user_policy_table.update()
        .values(policy_uuid=default_admin_policy_uuid)
        .where(
            sa.and_(
                user_policy_table.c.user_uuid == root_user_uuid,
                user_policy_table.c.policy_uuid == master_user_policy_uuid,
            )
        )
    )
    op.execute(query)
