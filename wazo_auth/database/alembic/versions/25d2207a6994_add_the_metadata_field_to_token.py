"""add the metadata field to token

Revision ID: 25d2207a6994
Revises: 67efdbc6619

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '25d2207a6994'
down_revision = '67efdbc6619'

TABLE = 'auth_token'
COLUMN = 'metadata'


def upgrade():
    op.add_column(TABLE, sa.Column(COLUMN, sa.Text))


def downgrade():
    op.drop_column(TABLE, COLUMN)
