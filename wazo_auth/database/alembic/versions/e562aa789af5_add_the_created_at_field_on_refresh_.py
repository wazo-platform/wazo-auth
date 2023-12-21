"""add the created_at field on refresh tokens

Revision ID: e562aa789af5
Revises: 7b15f7bd52ba

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'e562aa789af5'
down_revision = '7b15f7bd52ba'

TABLE_NAME = 'auth_refresh_token'
COLUMN_NAME = 'created_at'


def upgrade():
    op.add_column(
        TABLE_NAME,
        sa.Column(
            COLUMN_NAME, sa.DateTime(timezone=True), server_default=sa.text('NOW()')
        ),
    )


def downgrade():
    op.drop_column(TABLE_NAME, COLUMN_NAME)
