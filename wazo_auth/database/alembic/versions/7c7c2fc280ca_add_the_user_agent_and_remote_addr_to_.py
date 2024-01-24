"""add the user-agent and remote_addr to the token

Revision ID: 7c7c2fc280ca
Revises: 63acf2b9a7b9

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '7c7c2fc280ca'
down_revision = '63acf2b9a7b9'


def upgrade():
    op.add_column(
        'auth_token', sa.Column('user_agent', sa.Text, server_default='', default='')
    )
    op.add_column(
        'auth_token', sa.Column('remote_addr', sa.Text, server_default='', default='')
    )


def downgrade():
    op.drop_column('auth_token', 'remote_addr')
    op.drop_column('auth_token', 'user_agent')
