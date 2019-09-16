"""update-wazo-auth-cli-purpose

Revision ID: 14fdce448099
Revises: 7386d3b3e545

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '14fdce448099'
down_revision = '7386d3b3e545'

user = sa.sql.table('auth_user', sa.Column('username'), sa.Column('purpose'))

USERNAME = 'wazo-auth-cli'
NEW_PURPOSE = 'internal'
OLD_PURPOSE = 'user'


def upgrade():
    _update_purpose(NEW_PURPOSE)


def downgrade():
    _update_purpose(OLD_PURPOSE)


def _update_purpose(purpose):
    query = user.update().values(purpose=purpose).where(user.c.username == USERNAME)
    op.execute(query)
