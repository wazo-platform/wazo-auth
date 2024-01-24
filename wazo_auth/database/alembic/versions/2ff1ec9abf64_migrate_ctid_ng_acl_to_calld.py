"""migrate ctid-ng ACL to calld

Revision ID: 2ff1ec9abf64
Revises: 5c7d44ebeedc

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '2ff1ec9abf64'
down_revision = '5c7d44ebeedc'

acl_template_table = sa.sql.table(
    'auth_acl_template', sa.Column('id', sa.Integer), sa.Column('template', sa.Text)
)


def upgrade():
    conn = op.get_bind()
    acl_template_query = sa.sql.select(
        [acl_template_table.c.id, acl_template_table.c.template]
    ).where(acl_template_table.c.template.ilike('ctid-ng.%'))

    for acl_template_id, acl_template in conn.execute(acl_template_query).fetchall():
        new_template = acl_template.replace('ctid-ng.', 'calld.', 1)
        query = (
            acl_template_table.update()
            .values(template=new_template)
            .where(acl_template_table.c.id == acl_template_id)
        )
        op.execute(query)


def downgrade():
    conn = op.get_bind()
    acl_template_query = sa.sql.select(
        [acl_template_table.c.id, acl_template_table.c.template]
    ).where(acl_template_table.c.template.ilike('calld.%'))

    for acl_template_id, acl_template in conn.execute(acl_template_query).fetchall():
        new_template = acl_template.replace('calld.', 'ctid-ng.', 1)
        query = (
            acl_template_table.update()
            .values(template=new_template)
            .where(acl_template_table.c.id == acl_template_id)
        )
        op.execute(query)
