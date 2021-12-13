"""make username nullable

Revision ID: 6e70558d8898
Revises: 2821c95ce276

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = '6e70558d8898'
down_revision = '2821c95ce276'


def upgrade():
    op.alter_column('auth_user', 'username', nullable=True)


def downgrade():
    op.alter_column('auth_user', 'username', nullable=False)
