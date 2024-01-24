"""fix-corrupt-acl

Revision ID: d779d0640bd7
Revises: 17ce2e46c43e

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'd779d0640bd7'
down_revision = '17ce2e46c43e'

acl_template_tbl = sa.sql.table(
    'auth_acl_template', sa.Column('id'), sa.Column('template')
)


def remove_duplicate_template(template_name):
    first_skipped = False
    query = sa.sql.select([acl_template_tbl.c.id]).where(
        acl_template_tbl.c.template == template_name
    )
    duplicates = op.get_bind().execute(query)
    for template in duplicates:
        if not first_skipped:
            first_skipped = True
            continue
        query = acl_template_tbl.delete().where(acl_template_tbl.c.id == template.id)
        op.execute(query)


def upgrade():
    op.drop_constraint('auth_acl_template_template', 'auth_acl_template')
    count_query = (
        sa.sql.select(
            [
                sa.func.count(acl_template_tbl.c.id).label('count'),
                acl_template_tbl.c.template.label('template'),
            ]
        )
        .group_by(acl_template_tbl.c.template)
        .alias('count_query')
    )
    query = (
        sa.sql.select([count_query.c.count, count_query.c.template])
        .select_from(count_query)
        .where(count_query.c.count > 1)
    )
    templates = op.get_bind().execute(query)
    for template in templates:
        remove_duplicate_template(template.template)
    op.create_unique_constraint(
        'auth_acl_template_template', 'auth_acl_template', ['template']
    )


def downgrade():
    pass
