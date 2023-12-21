"""migrate_acl_tbl_to_token_column

Revision ID: 17ce2e46c43e
Revises: 548fcce8aad9

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import ARRAY

# revision identifiers, used by Alembic.
revision = '17ce2e46c43e'
down_revision = '548fcce8aad9'


def upgrade():
    op.add_column(
        'auth_token',
        sa.Column(
            'acl',
            ARRAY(sa.Text),
            nullable=False,
            server_default='{}',
        ),
    )

    op.execute(
        "UPDATE auth_token SET acl = (SELECT \
        array(SELECT value from auth_acl WHERE token_uuid = auth_token.uuid));"
    )

    op.drop_table('auth_acl')


def downgrade():
    op.create_table(
        'auth_acl',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('value', sa.Text, nullable=False),
        sa.Column(
            'token_uuid',
            sa.String(38),
            sa.ForeignKey('auth_token.uuid', ondelete='CASCADE'),
            nullable=False,
        ),
    )
    op.drop_column('auth_token', 'acl')
