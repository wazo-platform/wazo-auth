"""add-auth-tenant-auth-method

Revision ID: 3db769f10acb
Revises: 8216b7bb88db

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '3db769f10acb'
down_revision = '8216b7bb88db'

table = 'auth_tenant'
column_name = 'default_authentication_method'


def upgrade():
    op.add_column(
        table,
        sa.Column(
            column_name,
            sa.Text,
            sa.CheckConstraint(f"{column_name} in ('native', 'ldap', 'saml')"),
            server_default='native',
            nullable=False,
        ),
    )


def downgrade():
    op.drop_column(table, column_name)
