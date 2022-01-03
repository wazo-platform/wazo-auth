"""give-wazo-auth-cli-all-accesses

Revision ID: 6ab0ef651dcd
Revises: 56cea38f6815

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '6ab0ef651dcd'
down_revision = '56cea38f6815'

POLICY_NAME = 'wazo_default_master_user_policy'
ACCESS = '#'
OLD_ACCESS = 'auth.#'

policy_table = sa.sql.table(
    'auth_policy',
    sa.Column('uuid', sa.String(38)),
    sa.Column('name', sa.String(80)),
)
access_tbl = sa.sql.table(
    'auth_access',
    sa.Column('id', sa.Integer),
    sa.Column('access', sa.Text),
)
policy_access_tbl = sa.sql.table(
    'auth_policy_access',
    sa.Column('policy_uuid', sa.String(38)),
    sa.Column('access_id', sa.Integer),
)


def _find_access(conn, access):
    query = (
        sa.sql.select([access_tbl.c.id]).where(access_tbl.c.access == access).limit(1)
    )
    return conn.execute(query).scalar()


def _find_accesses(conn, policy_uuid):
    query = sa.sql.select([policy_access_tbl.c.access_id]).where(
        policy_access_tbl.c.policy_uuid == policy_uuid
    )
    return [row.access_id for row in conn.execute(query)]


def _get_policy_uuid(conn, policy_name):
    policy_query = sa.sql.select([policy_table.c.uuid]).where(
        policy_table.c.name == policy_name
    )

    for policy in conn.execute(policy_query).fetchall():
        return policy[0]


def _insert_access(conn, access):
    access_id = _find_access(conn, access)
    if not access_id:
        query = access_tbl.insert().returning(access_tbl.c.id).values(access=access)
        access_id = conn.execute(query).scalar()
    return access_id


def _delete_all_accesses(conn, policy_uuid):
    access_ids = _find_accesses(conn, policy_uuid)
    query = policy_access_tbl.delete().where(
        policy_access_tbl.c.policy_uuid == policy_uuid
    )
    op.execute(query)
    for access_id in access_ids:
        query = sa.sql.select([policy_access_tbl.c.access_id]).where(
            policy_access_tbl.c.access_id == access_id
        )
        used = conn.execute(query).scalar()
        if not used:
            query = access_tbl.delete().where(access_tbl.c.id == access_id)
            op.execute(query)


def upgrade():
    conn = op.get_bind()
    policy_uuid = _get_policy_uuid(conn, POLICY_NAME)
    if not policy_uuid:
        return

    _delete_all_accesses(conn, policy_uuid)
    access_id = _insert_access(conn, ACCESS)
    query = policy_access_tbl.insert().values(
        policy_uuid=policy_uuid, access_id=access_id
    )
    conn.execute(query)


def downgrade():
    conn = op.get_bind()
    policy_uuid = _get_policy_uuid(conn, POLICY_NAME)
    if not policy_uuid:
        return

    _delete_all_accesses(conn, policy_uuid)
    access_id = _insert_access(conn, OLD_ACCESS)
    query = policy_access_tbl.insert().values(
        policy_uuid=policy_uuid, access_id=access_id
    )
    conn.execute(query)
