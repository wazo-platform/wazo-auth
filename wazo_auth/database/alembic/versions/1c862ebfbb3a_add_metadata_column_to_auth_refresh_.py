"""Add metadata column to auth_refresh_token

Revision ID: 1c862ebfbb3a
Revises: 8c14d2c98235

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '1c862ebfbb3a'
down_revision = '8c14d2c98235'


def upgrade():
    op.add_column(
        'auth_refresh_token',
        sa.Column(
            'metadata',
            postgresql.JSON(astext_type=sa.Text()),
            nullable=False,
            server_default='{}',
        ),
    )


def downgrade():
    op.drop_column('auth_refresh_token', 'metadata')
