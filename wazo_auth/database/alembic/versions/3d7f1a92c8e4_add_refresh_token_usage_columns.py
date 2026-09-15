"""add refresh token last_used_at

Revision ID: 3d7f1a92c8e4
Revises: 1c862ebfbb3a

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '3d7f1a92c8e4'
down_revision = '1c862ebfbb3a'

TABLE_NAME = 'auth_refresh_token'


def upgrade():
    op.add_column(
        TABLE_NAME,
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
    )


def downgrade():
    op.drop_column(TABLE_NAME, 'last_used_at')
