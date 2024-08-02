"""add refresh_token_uuid to auth_token

Revision ID: 2903ea6f2f20
Revises: d79360e9e554

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '2903ea6f2f20'
down_revision = 'd79360e9e554'

table = 'auth_token'
column_name = 'refresh_token_uuid'


def upgrade():
    op.add_column(
        table,
        sa.Column(
            column_name,
            sa.String(36),
            sa.ForeignKey('auth_refresh_token.uuid', ondelete='SET NULL'),
            nullable=True,
        ),
    )


def downgrade():
    op.drop_column(table, column_name)
