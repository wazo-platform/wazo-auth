"""add user cdr ACL

Revision ID: 1c19f4acd0bd
Revises: 50de5600b678

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '1c19f4acd0bd'
down_revision = '50de5600b678'


POLICY_NAME = 'wazo_default_user_policy'
ACL_TEMPLATES = ['call-logd.users.me.cdr.read']

policy_table = sa.sql.table(
    'auth_policy', sa.Column('uuid', sa.String(38)), sa.Column('name', sa.String(80))
)
acl_template_table = sa.sql.table(
    'auth_acl_template', sa.Column('id', sa.Integer), sa.Column('template', sa.Text)
)
policy_template = sa.sql.table(
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


def _insert_acl_template(conn, acl_templates):
    acl_template_ids = []
    for acl_template in acl_templates:
        acl_template_id = _find_acl_template(conn, acl_template)
        if not acl_template_id:
            query = (
                acl_template_table.insert()
                .returning(acl_template_table.c.id)
                .values(template=acl_template)
            )
            acl_template_id = conn.execute(query).scalar()
        acl_template_ids.append(acl_template_id)
    return acl_template_ids


def upgrade():
    conn = op.get_bind()
    policy_uuid = _get_policy_uuid(conn, POLICY_NAME)
    if not policy_uuid:
        return

    acl_template_ids = _insert_acl_template(conn, ACL_TEMPLATES)
    op.bulk_insert(
        policy_template,
        [
            {'policy_uuid': policy_uuid, 'template_id': template_id}
            for template_id in acl_template_ids
        ],
    )


def downgrade():
    conn = op.get_bind()
    acl_template_ids = _find_acl_templates(conn, ACL_TEMPLATES)
    if acl_template_ids:
        policy_uuid = _get_policy_uuid(conn, POLICY_NAME)
        delete_query = policy_template.delete().where(
            sa.sql.and_(
                policy_template.c.policy_uuid == policy_uuid,
                policy_template.c.template_id.in_(acl_template_ids),
            )
        )
        op.execute(delete_query)
