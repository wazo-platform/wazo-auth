"""add-shared-policy

Revision ID: 2821c95ce276
Revises: 6834e544e667

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '2821c95ce276'
down_revision = '6834e544e667'


def upgrade():
    op.add_column(
        'auth_policy',
        sa.Column('shared', sa.Boolean, server_default='false', nullable=False),
    )


def downgrade():
    op.drop_column('auth_policy', 'shared')
