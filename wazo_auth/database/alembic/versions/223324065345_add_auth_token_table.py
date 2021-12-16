"""add auth_token table

Revision ID: 223324065345
Revises: None

"""

from alembic import op
from sqlalchemy.schema import Column
from sqlalchemy import Integer, String, text, Text

# revision identifiers, used by Alembic.
revision = '223324065345'
down_revision = None


table_name = 'auth_token'


def upgrade():
    op.create_table(
        table_name,
        Column(
            'uuid',
            String(38),
            server_default=text('uuid_generate_v4()'),
            primary_key=True,
        ),
        Column('auth_id', Text, nullable=False),
        Column('user_uuid', String(38)),
        Column('xivo_uuid', String(38)),
        Column('issued_t', Integer),
        Column('expire_t', Integer),
    )


def downgrade():
    op.drop_table(table_name)
