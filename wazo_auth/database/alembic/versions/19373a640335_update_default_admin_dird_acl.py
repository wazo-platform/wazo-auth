"""update default_admin dird acl

Revision ID: 19373a640335
Revises: 14fdce448099

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '19373a640335'
down_revision = '14fdce448099'


OLD_ACL_TEMPLATE = 'dird.tenants.{% if entity %}{{ entity }}.#{% else %}#{% endif %}'
NEW_ACL_TEMPLATE = (
    '{% for tenant in visible_tenants %}dird.tenants.{{ tenant.name }}.#:{% endfor %}'
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


def _update_policy_acl_template(conn, old_acl_template_id, new_acl_template_id):
    query = (
        policy_template_table.update()
        .values(template_id=new_acl_template_id)
        .where(policy_template_table.c.template_id == old_acl_template_id)
    )
    op.execute(query)


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


def _delete_acl_template(conn, old_acl_template_id):
    query = acl_template_table.delete().where(
        acl_template_table.c.id == old_acl_template_id
    )
    op.execute(query)


def upgrade():
    conn = op.get_bind()

    old_acl_template_id = _find_acl_template(conn, OLD_ACL_TEMPLATE)
    new_acl_template_id = _insert_acl_template(conn, NEW_ACL_TEMPLATE)
    _update_policy_acl_template(conn, old_acl_template_id, new_acl_template_id)
    _delete_acl_template(conn, old_acl_template_id)


def downgrade():
    conn = op.get_bind()

    new_acl_template_id = _find_acl_template(conn, NEW_ACL_TEMPLATE)
    old_acl_template_id = _insert_acl_template(conn, OLD_ACL_TEMPLATE)
    _update_policy_acl_template(conn, new_acl_template_id, old_acl_template_id)
    _delete_acl_template(conn, new_acl_template_id)
