"""add search_filters to ldap_config

Revision ID: a6cda77a7e3f
Revises: f6d7dfe84740

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'a6cda77a7e3f'
down_revision = 'f6d7dfe84740'

TABLE = 'auth_ldap_config'
COLUMN_NAME = 'search_filters'


def upgrade():
    op.add_column(TABLE, sa.Column(COLUMN_NAME, sa.Text))


def downgrade():
    op.drop_column(TABLE, COLUMN_NAME)
