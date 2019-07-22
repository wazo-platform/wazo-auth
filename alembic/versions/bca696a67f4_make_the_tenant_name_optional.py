"""make the tenant name optional

Revision ID: bca696a67f4
Revises: 3022a18d6fe

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = 'bca696a67f4'
down_revision = '3022a18d6fe'

table_name = 'auth_tenant'
column_name = 'name'


def upgrade():
    op.alter_column(table_name, column_name, nullable=True)
    op.drop_constraint('auth_tenant_name_key', table_name)


def downgrade():
    op.alter_column(table_name, column_name, nullable=False)
