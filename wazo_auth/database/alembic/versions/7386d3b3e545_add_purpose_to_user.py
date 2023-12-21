"""add_purpose_to_user

Revision ID: 7386d3b3e545
Revises: 955c667efc65

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '7386d3b3e545'
down_revision = '955c667efc65'

TABLE = 'auth_user'
COL = 'purpose'


def upgrade():
    op.add_column(
        TABLE,
        sa.Column(
            COL,
            sa.Text,
            sa.CheckConstraint("purpose in ('user', 'internal', 'external_api')"),
            server_default='user',
            nullable=False,
        ),
    )
    op.alter_column(TABLE, COL, nullable=False, server_default=None)


def downgrade():
    op.drop_column(TABLE, COL)
