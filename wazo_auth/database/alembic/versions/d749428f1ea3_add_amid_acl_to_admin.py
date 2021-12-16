"""add-amid-acl-to-admin

Revision ID: d749428f1ea3
Revises: 40d8f37d7096

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'd749428f1ea3'
down_revision = '40d8f37d7096'

POLICY_NAME = 'wazo_default_admin_policy'
ACL = ['amid.#']

policy_tbl = sa.sql.table(
    'auth_policy',
    sa.Column('uuid'),
    sa.Column('name'),
)
access_tbl = sa.sql.table(
    'auth_access',
    sa.Column('id'),
    sa.Column('access'),
)
policy_access_tbl = sa.sql.table(
    'auth_policy_access',
    sa.Column('policy_uuid'),
    sa.Column('access_id'),
)


def _find_access(conn, access):
    query = (
        sa.sql.select([access_tbl.c.id]).where(access_tbl.c.access == access).limit(1)
    )
    return conn.execute(query).scalar()


def _find_accesses(conn, accesses):
    access_ids = []
    for access in accesses:
        access_id = _find_access(conn, access)
        if access_id:
            access_ids.append(access_id)
    return access_ids


def _get_policy_uuid(conn, policy_name):
    policy_query = sa.sql.select([policy_tbl.c.uuid]).where(
        policy_tbl.c.name == policy_name
    )

    for policy in conn.execute(policy_query).fetchall():
        return policy[0]


def _insert_accesses(conn, accesses):
    access_ids = []
    for access in accesses:
        access_id = _find_access(conn, access)
        if not access_id:
            query = access_tbl.insert().returning(access_tbl.c.id).values(access=access)
            access_id = conn.execute(query).scalar()
        access_ids.append(access_id)
    return access_ids


def _get_access_ids(conn, policy_uuid):
    query = sa.sql.select([policy_access_tbl.c.access_id]).where(
        policy_access_tbl.c.policy_uuid == policy_uuid
    )
    return [access_id for (access_id,) in conn.execute(query).fetchall()]


def upgrade():
    conn = op.get_bind()
    policy_uuid = _get_policy_uuid(conn, POLICY_NAME)
    if not policy_uuid:
        return

    access_ids = _insert_accesses(conn, ACL)
    access_ids_already_associated = _get_access_ids(conn, policy_uuid)
    for access_id in set(access_ids) - set(access_ids_already_associated):
        query = policy_access_tbl.insert().values(
            policy_uuid=policy_uuid, access_id=access_id
        )
        conn.execute(query)


def downgrade():
    conn = op.get_bind()
    access_ids = _find_accesses(conn, ACL)
    if not access_ids:
        return

    policy_uuid = _get_policy_uuid(conn, POLICY_NAME)
    if not policy_uuid:
        return

    delete_query = policy_access_tbl.delete().where(
        sa.sql.and_(
            policy_access_tbl.c.policy_uuid == policy_uuid,
            policy_access_tbl.c.access_id.in_(access_ids),
        )
    )
    op.execute(delete_query)
