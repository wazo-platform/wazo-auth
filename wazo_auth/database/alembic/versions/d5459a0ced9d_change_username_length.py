"""change username length

Revision ID: d5459a0ced9d
Revises: dd5257951c20

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'd5459a0ced9d'
down_revision = 'dd5257951c20'


def upgrade():
    op.alter_column('auth_user', 'username', nullable=False, type_=sa.String(256))


def downgrade():
    op.alter_column('auth_user', 'username', nullable=False, type_=sa.String(128))
