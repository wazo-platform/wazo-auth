"""create saml_pysaml2_cache table for single logout service

Revision ID: 4e674b12400f
Revises: 26146ddb2111

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '4e674b12400f'
down_revision = '26146ddb2111'

TABLE_NAME = 'auth_saml_pysaml2_cache'


def upgrade():
    op.create_table(
        TABLE_NAME,
        sa.Column(
            'name_id',
            sa.String(512),
            primary_key=True,
        ),
        sa.Column(
            'entity_id',
            sa.String(1024),
            primary_key=True,
        ),
        sa.Column(
            'info',
            sa.Text,
            nullable=False,
        ),
        sa.Column(
            'not_on_or_after',
            sa.Integer,
            nullable=False,
        ),
    )


def downgrade():
    op.drop_table(TABLE_NAME)
