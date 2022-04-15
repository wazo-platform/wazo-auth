"""add auth_tenant_domain_name

Revision ID: 0c9ccb1b16a8
Revises: a6cda77a7e3f

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0c9ccb1b16a8'
down_revision = 'a6cda77a7e3f'

TABLE_NAME = 'auth_tenant_domain_name'
RFC_DN_MAX_LENGTH = 61


def upgrade():
    op.create_table(
        TABLE_NAME,
        Column(
            'tenant_uuid',
            Column(
                sa.String(38),
                sa.ForeignKey('auth_tenant.uuid', ondelete='CASCADE'),
                nullable=False,
            ),
        ),
        Column(
            'name',
            sa.String(RFC_DN_MAX_LENGTH),
            nullable=False,
        ),
    )
    op.create_unique_constraint(
        'auth_tenant_domain_name_key', TABLE_NAME, ['name', 'tenant_uuid']
    )


def downgrade():
    op.drop_constraint('auth_tenant_domain_name_key', TABLE_NAME)
    op.drop_table(TABLE_NAME)
