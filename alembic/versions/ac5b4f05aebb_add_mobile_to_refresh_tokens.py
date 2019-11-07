"""add mobile to refresh tokens

Revision ID: ac5b4f05aebb
Revises: f6df424cb3b8

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'ac5b4f05aebb'
down_revision = 'f6df424cb3b8'


def upgrade():
    # All existing refresh tokens are mobile
    op.add_column(
        'auth_refresh_token',
        sa.Column('mobile', sa.Boolean, nullable=False, default=True, server_default='true'),
    )
    # After the migration the default for new refresh token mobile is False
    op.alter_column('auth_refresh_token', 'mobile', nullable=False, server_default='false')


def downgrade():
    op.drop_column('auth_refresh_token', 'mobile')
