"""create saml config table

Revision ID: 036d80b11825
Revises: a1149ec5ad50

"""

import sqlalchemy as sa
from alembic import op

from wazo_auth.database.datatypes import XMLPostgresqlType

# revision identifiers, used by Alembic.
revision = '036d80b11825'
down_revision = 'a1149ec5ad50'


TABLE_NAME = 'auth_saml_config'


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
            'domain_uuid',
            sa.String(38),
            sa.ForeignKey('auth_tenant_domain.uuid', ondelete='CASCADE'),
            primary_key=True,
        ),
        sa.Column(
            'entity_id',
            sa.String(512),
            nullable=False,
        ),
        sa.Column(
            'idp_metadata',
            XMLPostgresqlType(),
            nullable=False,
        ),
        sa.Column(
            'acs_url',
            sa.String(512),
            nullable=False,
        ),
    )


def downgrade():
    op.drop_table(TABLE_NAME)
