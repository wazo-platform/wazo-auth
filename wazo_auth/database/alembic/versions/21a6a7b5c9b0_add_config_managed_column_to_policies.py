"""add config_managed column to policies

Revision ID: 21a6a7b5c9b0
Revises: 16f98957ec7e

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '21a6a7b5c9b0'
down_revision = '16f98957ec7e'


def upgrade():
    op.add_column(
        'auth_policy',
        sa.Column(
            'config_managed',
            sa.Boolean,
            default=False,
            server_default='false',
            nullable=True,
        ),
    )


def downgrade():
    op.drop_column('auth_policy', 'config_managed')
