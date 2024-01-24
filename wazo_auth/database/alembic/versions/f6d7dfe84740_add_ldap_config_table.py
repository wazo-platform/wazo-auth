"""add ldap config table

Revision ID: f6d7dfe84740
Revises: 6e70558d8898

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'f6d7dfe84740'
down_revision = '6e70558d8898'

TABLE_NAME = 'auth_ldap_config'


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
            'host',
            sa.String(512),
            nullable=False,
        ),
        sa.Column(
            'port',
            sa.Integer,
            nullable=False,
        ),
        sa.Column(
            'protocol_version',
            sa.SmallInteger,
        ),
        sa.Column(
            'protocol_security',
            sa.Text,
            sa.CheckConstraint("protocol_security in ('ldaps', 'tls')"),
        ),
        sa.Column(
            'bind_dn',
            sa.String(256),
        ),
        sa.Column(
            'bind_password',
            sa.Text,
        ),
        sa.Column(
            'user_base_dn',
            sa.String(256),
            nullable=False,
        ),
        sa.Column(
            'user_login_attribute',
            sa.String(64),
        ),
        sa.Column(
            'user_email_attribute',
            sa.String(64),
        ),
    )


def downgrade():
    op.drop_table(TABLE_NAME)
