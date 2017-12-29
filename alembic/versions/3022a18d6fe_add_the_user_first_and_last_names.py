"""add the user first and last names

Revision ID: 3022a18d6fe
Revises: 41ef5facca2d

"""

# revision identifiers, used by Alembic.
revision = '3022a18d6fe'
down_revision = '41ef5facca2d'

from alembic import op
import sqlalchemy as sa

table_name = 'auth_user'


def upgrade():
    op.add_column(
        table_name,
        sa.Column('firstname', sa.Text),
    )
    op.add_column(
        table_name,
        sa.Column('lastname', sa.Text),
    )


def downgrade():
    op.drop_column(table_name, 'firstname')
    op.drop_column(table_name, 'lastname')
