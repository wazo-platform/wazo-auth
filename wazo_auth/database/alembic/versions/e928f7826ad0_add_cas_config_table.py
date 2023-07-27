"""add cas config table

Revision ID: e928f7826ad0
Revises: 8216b7bb88db

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'e928f7826ad0'
down_revision = '8216b7bb88db'


TABLE_NAME = 'auth_cas_config'


def upgrade():
    op.create_table(
        TABLE_NAME,
        sa.Column(
            'tenant_uuid',
            sa.String(38),
            sa.ForeignKey('auth_tenant.uuid', ondelete='CASCADE'),
            primary_key=True,
        ),
        sa.Column(
            'server_url',
            sa.String(512),
            nullable=False,
        ),
        sa.Column(
            'service_url',
            sa.String(512),
            nullable=False,
        ),
        sa.Column(
            'user_email_attribute',
            sa.String(64),
        ),
    )


def downgrade():
    op.drop_table(TABLE_NAME)
