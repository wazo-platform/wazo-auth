"""add the tenant policy association

Revision ID: dd5257951c20
Revises: ca928634de0f

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'dd5257951c20'
down_revision = 'ca928634de0f'


def upgrade():
    op.create_table(
        'auth_tenant_policy',
        sa.Column(
            'tenant_uuid',
            sa.String(38),
            sa.ForeignKey('auth_tenant.uuid', ondelete='CASCADE'),
            primary_key=True,
        ),
        sa.Column(
            'policy_uuid',
            sa.String(38),
            sa.ForeignKey('auth_policy.uuid', ondelete='CASCADE'),
            primary_key=True,
        ),
    )


def downgrade():
    op.drop_table('auth_tenant_policy')
