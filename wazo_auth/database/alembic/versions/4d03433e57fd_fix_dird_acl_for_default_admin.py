"""fix dird ACL for default admin

Revision ID: 4d03433e57fd
Revises: ac4b46ecf507

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '4d03433e57fd'
down_revision = 'ac4b46ecf507'

POLICY_NAME = 'wazo_default_admin_policy'
ACL_TEMPLATE_TO_REMOVE = 'dird.displays.#dird.profiles.#dird.sources.read'
ACL_TEMPLATE_TO_ADD = 'dird.displays.#'

policy_table = sa.sql.table(
    'auth_policy', sa.Column('uuid', sa.String(38)), sa.Column('name', sa.String(80))
)
acl_template_table = sa.sql.table(
    'auth_acl_template', sa.Column('id', sa.Integer), sa.Column('template', sa.Text)
)
policy_template_table = sa.sql.table(
    'auth_policy_template',
    sa.Column('policy_uuid', sa.String(38)),
    sa.Column('template_id', sa.Integer),
)


def _find_acl_template(conn, acl_template):
    query = (
        sa.sql.select([acl_template_table.c.id])
        .where(acl_template_table.c.template == acl_template)
        .limit(1)
    )
    return conn.execute(query).scalar()


def _find_acl_templates(conn, acl_templates):
    acl_template_ids = []
    for acl_template in acl_templates:
        acl_template_id = _find_acl_template(conn, acl_template)
        if acl_template_id:
            acl_template_ids.append(acl_template_id)
    return acl_template_ids


def _get_policy_uuid(conn, policy_name):
    policy_query = sa.sql.select([policy_table.c.uuid]).where(
        policy_table.c.name == policy_name
    )

    for policy in conn.execute(policy_query).fetchall():
        return policy[0]


def _update_policy_acl_template(conn, old_acl_template_id, new_acl_template_id):
    query = (
        policy_template_table.update()
        .values(template_id=new_acl_template_id)
        .where(policy_template_table.c.template_id == old_acl_template_id)
    )
    op.execute(query)


def _delete_acl_template(conn, acl_template_id):
    delete_query = acl_template_table.delete().where(
        acl_template_table.c.id == acl_template_id
    )
    op.execute(delete_query)


def _acl_template_is_in_policy(conn, acl_template_id, policy_uuid):
    query = sa.sql.select([policy_template_table.c.template_id]).where(
        sa.sql.and_(
            policy_template_table.c.template_id == acl_template_id,
            policy_template_table.c.policy_uuid == policy_uuid,
        )
    )
    return any(conn.execute(query).fetchall())


def _insert_acl_template(conn, acl_template):
    acl_template_id = _find_acl_template(conn, acl_template)
    if not acl_template_id:
        query = (
            acl_template_table.insert()
            .returning(acl_template_table.c.id)
            .values(template=acl_template)
        )
        acl_template_id = conn.execute(query).scalar()
    return acl_template_id


def upgrade():
    conn = op.get_bind()
    policy_uuid = _get_policy_uuid(conn, POLICY_NAME)
    if not policy_uuid:
        return

    acl_template_to_remove_id = _find_acl_template(conn, ACL_TEMPLATE_TO_REMOVE)
    if not acl_template_to_remove_id:
        return

    acl_template_to_add_id = _insert_acl_template(conn, ACL_TEMPLATE_TO_ADD)

    if not _acl_template_is_in_policy(conn, acl_template_to_add_id, policy_uuid):
        _update_policy_acl_template(
            conn, acl_template_to_remove_id, acl_template_to_add_id
        )

    _delete_acl_template(conn, acl_template_to_remove_id)


def downgrade():
    # we will not reintroduce the bug
    pass
