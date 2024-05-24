"""add-user-authentication-method

Revision ID: a1149ec5ad50
Revises: 3db769f10acb

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'a1149ec5ad50'
down_revision = '3db769f10acb'


table = 'auth_user'
column_name = 'authentication_method'


def upgrade():
    op.add_column(
        table,
        sa.Column(
            column_name,
            sa.Text,
            sa.CheckConstraint(
                f"{column_name} in ('default', 'native', 'ldap', 'saml')"
            ),
            server_default='default',
            nullable=False,
        ),
    )


def downgrade():
    op.drop_column(table, column_name)
