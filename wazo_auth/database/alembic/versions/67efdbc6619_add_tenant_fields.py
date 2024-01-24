"""add tenant fields

Revision ID: 67efdbc6619
Revises: bca696a67f4

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.schema import Column

# revision identifiers, used by Alembic.
revision = '67efdbc6619'
down_revision = 'bca696a67f4'


def upgrade():
    op.create_table(
        'auth_address',
        Column('id', sa.Integer, primary_key=True),
        Column('line_1', sa.Text),
        Column('line_2', sa.Text),
        Column('city', sa.Text),
        Column('state', sa.Text),
        Column('zip_code', sa.Text),
        Column('country', sa.Text),
    )
    op.add_column(
        'auth_tenant',
        Column(
            'address_id',
            sa.Integer,
            sa.ForeignKey('auth_address.id', ondelete='SET NULL'),
        ),
    )
    op.add_column('auth_tenant', Column('phone', sa.Text))
    op.add_column(
        'auth_tenant',
        Column(
            'contact_uuid',
            sa.String(38),
            sa.ForeignKey('auth_user.uuid', ondelete='SET NULL'),
        ),
    )


def downgrade():
    op.drop_column('auth_tenant', 'contact_uuid')
    op.drop_column('auth_tenant', 'phone')
    op.drop_column('auth_tenant', 'address_id')
    op.drop_table('auth_address')
