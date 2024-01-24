"""add the auth_policy table

Revision ID: 42abef26feff
Revises: 59b2f9faf3d

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.schema import Column

# revision identifiers, used by Alembic.
revision = '42abef26feff'
down_revision = '59b2f9faf3d'

constraint_name = 'auth_policy_name'
table_name = 'auth_policy'


def upgrade():
    op.create_table(
        table_name,
        Column(
            'uuid',
            sa.String(38),
            server_default=sa.text('uuid_generate_v4()'),
            primary_key=True,
        ),
        Column('name', sa.String(80), nullable=False),
        Column('description', sa.Text),
    )
    op.create_unique_constraint(constraint_name, table_name, ['name'])


def downgrade():
    op.drop_constraint(constraint_name, table_name)
    op.drop_table(table_name)
