"""add the external_auth enabled column

Revision ID: 534e987560f5
Revises: 28d461e6fb86

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.schema import Column

# revision identifiers, used by Alembic.
revision = '534e987560f5'
down_revision = '28d461e6fb86'


TABLE = 'auth_external_auth_type'
COLUMN = 'enabled'


def upgrade():
    op.add_column(TABLE, Column(COLUMN, sa.Boolean, default=True))


def downgrade():
    op.drop_column(TABLE, COLUMN)
