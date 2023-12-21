"""add External Auth Config table

Revision ID: 4d994bfa20e0
Revises: a514118b80b8

"""

from alembic import op
from sqlalchemy import String
from sqlalchemy.schema import Column, ForeignKey

# revision identifiers, used by Alembic.
revision = '4d994bfa20e0'
down_revision = 'a514118b80b8'


def upgrade():
    op.create_table(
        'auth_external_auth_config',
        Column(
            'data_uuid',
            String(36),
            ForeignKey('auth_external_auth_data.uuid', ondelete='CASCADE'),
        ),
        Column(
            'type_uuid',
            String(36),
            ForeignKey('auth_external_auth_type.uuid', ondelete='CASCADE'),
            primary_key=True,
        ),
        Column(
            'tenant_uuid',
            String(38),
            ForeignKey('auth_tenant.uuid', ondelete='CASCADE'),
            primary_key=True,
        ),
    )


def downgrade():
    op.drop_table('auth_external_auth_config')
