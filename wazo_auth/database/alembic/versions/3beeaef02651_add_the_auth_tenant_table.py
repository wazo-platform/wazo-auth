"""add the auth_tenant table

Revision ID: 3beeaef02651
Revises: 443b172ad7f6

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.schema import Column

# revision identifiers, used by Alembic.
revision = '3beeaef02651'
down_revision = '443b172ad7f6'


def upgrade():
    op.create_table(
        'auth_tenant',
        Column(
            'uuid',
            sa.String(38),
            server_default=sa.text('uuid_generate_v4()'),
            primary_key=True,
        ),
        Column('name', sa.Text, unique=True, nullable=False),
    )


def downgrade():
    op.drop_table('auth_tenant')
