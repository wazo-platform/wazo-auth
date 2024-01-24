"""add tenant slug

Revision ID: 9b80db8b7860
Revises: 67013e93544f

"""

import random
import re
import string

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '9b80db8b7860'
down_revision = '67013e93544f'

MAX_SLUG_LEN = 10
SLUG_LEN = 3

tenant_tbl = sa.sql.table(
    'auth_tenant',
    sa.Column('uuid'),
    sa.Column('name'),
    sa.Column('slug'),
)


def slug_from_name(name):
    if not name:
        return
    return re.sub(r'[^a-zA-Z0-9_]', '', name)[:MAX_SLUG_LEN]


def upgrade():
    op.add_column(
        'auth_tenant', sa.Column('slug', sa.String(MAX_SLUG_LEN), unique=True)
    )

    slugs = set()
    query = sa.sql.select([tenant_tbl.c.uuid, tenant_tbl.c.name])
    for tenant in op.get_bind().execute(query):
        slug = slug_from_name(tenant.name)
        if slug in slugs:
            slug = None

        if not slug:
            while True:
                slug = _generate_random_name(SLUG_LEN)
                if slug not in slugs:
                    break

        slugs.add(slug)
        op.execute(
            tenant_tbl.update()
            .values(slug=slug)
            .where(tenant_tbl.c.uuid == tenant.uuid)
        )

    op.alter_column('auth_tenant', 'slug', nullable=False)


def downgrade():
    op.drop_column('auth_tenant', 'slug')


def _generate_random_name(length):
    return ''.join(
        random.choice(string.ascii_letters + string.digits) for _ in range(length)
    )
