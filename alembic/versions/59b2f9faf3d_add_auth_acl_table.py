"""add auth_acl table

Revision ID: 59b2f9faf3d
Revises: 223324065345

"""
from alembic import op
from sqlalchemy import Column, ForeignKey, Integer, String, Text

# revision identifiers, used by Alembic.
revision = '59b2f9faf3d'
down_revision = '223324065345'

table_name = 'auth_acl'


def upgrade():
    op.create_table(
        table_name,
        Column('id', Integer, primary_key=True),
        Column('value', Text, nullable=False),
        Column(
            'token_uuid',
            String(38),
            ForeignKey('auth_token.uuid', ondelete='CASCADE'),
            nullable=False,
        ),
    )


def downgrade():
    op.drop_table(table_name)
