"""fix cdr acl

Revision ID: 2654b641d1f6
Revises: 1c19f4acd0bd

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '2654b641d1f6'
down_revision = '1c19f4acd0bd'


NEW_TEMPLATE = 'call-logd.cdr.read'
OLD_TEMPLATE = 'call_logd.cdr.read'

acl_template_table = sa.sql.table(
    'auth_acl_template', sa.Column('id', sa.Integer), sa.Column('template', sa.Text)
)


def upgrade():
    query = (
        acl_template_table.update()
        .values(template=NEW_TEMPLATE)
        .where(acl_template_table.c.template == OLD_TEMPLATE)
    )
    op.execute(query)


def downgrade():
    query = (
        acl_template_table.update()
        .values(template=OLD_TEMPLATE)
        .where(acl_template_table.c.template == NEW_TEMPLATE)
    )
    op.execute(query)
