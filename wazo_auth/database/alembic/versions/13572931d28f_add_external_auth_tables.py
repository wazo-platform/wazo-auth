"""add external auth tables

Revision ID: 13572931d28f
Revises: 4edfead052cd

"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.schema import Column

# revision identifiers, used by Alembic.
revision = '13572931d28f'
down_revision = '4edfead052cd'

constraint_name = 'auth_external_user_type_auth_constraint'


def upgrade():
    uuid_gen = sa.text('uuid_generate_v4()')

    op.create_table(
        'auth_external_auth_type',
        Column('uuid', sa.String(38), primary_key=True, server_default=uuid_gen),
        Column('name', sa.Text, unique=True, nullable=False),
    )

    op.create_table(
        'auth_external_auth_data',
        Column('uuid', sa.String(38), primary_key=True, server_default=uuid_gen),
        Column('data', sa.Text, nullable=False),
    )

    op.create_table(
        'auth_user_external_auth',
        Column(
            'user_uuid',
            sa.String(38),
            sa.ForeignKey('auth_user.uuid', ondelete='CASCADE'),
            primary_key=True,
        ),
        Column(
            'external_auth_type_uuid',
            sa.String(38),
            sa.ForeignKey('auth_external_auth_type.uuid', ondelete='CASCADE'),
            primary_key=True,
        ),
        Column(
            'external_auth_data_uuid',
            sa.String(38),
            sa.ForeignKey('auth_external_auth_data.uuid', ondelete='CASCADE'),
            primary_key=True,
        ),
    )

    op.create_unique_constraint(
        constraint_name,
        'auth_user_external_auth',
        ['user_uuid', 'external_auth_type_uuid'],
    )


def downgrade():
    op.drop_constraint(constraint_name, 'auth_user_external_auth')
    op.drop_table('auth_user_external_auth')
    op.drop_table('auth_external_auth_data')
    op.drop_table('auth_external_auth_type')
