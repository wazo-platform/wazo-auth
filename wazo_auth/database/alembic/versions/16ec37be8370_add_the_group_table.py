"""add the group table

Revision ID: 16ec37be8370
Revises: c11c395a7b6

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.schema import Column

# revision identifiers, used by Alembic.
revision = '16ec37be8370'
down_revision = 'c11c395a7b6'

TABLE_NAME = 'auth_group'


def upgrade():
    op.create_table(
        TABLE_NAME,
        Column(
            'uuid',
            sa.String(38),
            server_default=sa.text('uuid_generate_v4()'),
            primary_key=True,
        ),
        Column('name', sa.Text, unique=True, nullable=False),
    )


def downgrade():
    op.drop_table(TABLE_NAME)
