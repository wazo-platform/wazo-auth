"""add system_managed column to group table

Revision ID: 31000c80366b
Revises: 67ac1f04b6cb

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '31000c80366b'
down_revision = '67ac1f04b6cb'

group_table = sa.sql.table(
    'auth_group',
    sa.Column('name'),
    sa.Column('system_managed'),
)


def upgrade():
    op.add_column(
        'auth_group',
        sa.Column(
            'system_managed',
            sa.Boolean,
            default=False,
            server_default='false',
            nullable=False,
        ),
    )

    query = (
        group_table.update()
        .values(system_managed=True)
        .where(group_table.c.name.like('wazo-all-users-tenant-%'))
    )
    op.execute(query)


def downgrade():
    op.drop_column('auth_group', 'system_managed')
