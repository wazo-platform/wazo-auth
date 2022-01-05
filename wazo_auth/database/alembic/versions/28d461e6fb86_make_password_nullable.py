"""make password nullable

Revision ID: 28d461e6fb86
Revises: 13572931d28f

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = '28d461e6fb86'
down_revision = '13572931d28f'


t = 'auth_user'
columns = ['password_hash', 'password_salt']


def upgrade():
    for c in columns:
        op.alter_column(t, c, nullable=True)


def downgrade():
    for c in columns:
        op.alter_column(t, c, nullable=False)
