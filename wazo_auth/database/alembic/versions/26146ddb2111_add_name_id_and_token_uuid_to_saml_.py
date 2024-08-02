"""add name_id and token_uuid to saml_session

Revision ID: 26146ddb2111
Revises: 2903ea6f2f20

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '26146ddb2111'
down_revision = '2903ea6f2f20'

table = 'auth_saml_session'


def upgrade():
    op.add_column(
        table,
        sa.Column(
            'saml_name_id',
            sa.Text,
            nullable=True,
        ),
    )
    op.add_column(
        table,
        sa.Column(
            'refresh_token_uuid',
            sa.String(36),
            sa.ForeignKey('auth_refresh_token.uuid', ondelete='SET NULL'),
            nullable=True,
        ),
    )


def downgrade():
    op.drop_column(table, 'saml_name_id')
    op.drop_column(table, 'refresh_token_uuid')
