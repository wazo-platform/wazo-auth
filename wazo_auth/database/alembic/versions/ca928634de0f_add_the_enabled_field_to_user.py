"""add the enabled field to user

Revision ID: ca928634de0f
Revises: 25d2207a6994

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'ca928634de0f'
down_revision = '25d2207a6994'


def upgrade():
    op.add_column('auth_user', sa.Column('enabled', sa.Boolean, server_default='true'))


def downgrade():
    op.drop_column('auth_user', 'enabled')
