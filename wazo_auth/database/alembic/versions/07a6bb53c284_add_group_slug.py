"""add group slug

Revision ID: 07a6bb53c284
Revises: e1b78cd7c702

"""

import random
import re
import string

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '07a6bb53c284'
down_revision = 'e1b78cd7c702'

MAX_SLUG_LEN = 80
SLUG_LEN = 3
IDX_NAME = 'auth_group__idx__slug'

group_tbl = sa.sql.table(
    'auth_group',
    sa.Column('uuid'),
    sa.Column('name'),
    sa.Column('tenant_uuid'),
    sa.Column('slug'),
)

tenant_tbl = sa.sql.table(
    'auth_tenant',
    sa.Column('uuid'),
)


def _slug_from_name(name):
    if not name:
        return
    return re.sub(r'[^a-zA-Z0-9_-]', '', name)[:MAX_SLUG_LEN]


def _generate_random_slug():
    choices = string.ascii_lowercase + string.digits
    return ''.join(random.choice(choices) for _ in range(SLUG_LEN))


def upgrade():
    op.add_column('auth_group', sa.Column('slug', sa.String(MAX_SLUG_LEN)))
    columns = '((lower(slug)), tenant_uuid)'
    op.execute(f'CREATE UNIQUE INDEX {IDX_NAME} ON auth_group {columns};')

    query = sa.sql.select([tenant_tbl.c.uuid])
    for tenant in op.get_bind().execute(query):
        slugs = set()
        query = sa.sql.select([group_tbl.c.uuid, group_tbl.c.name]).where(
            group_tbl.c.tenant_uuid == tenant.uuid
        )
        for group in op.get_bind().execute(query):
            slug = _slug_from_name(group.name)
            if slug.lower() in slugs:
                slug = None

            if not slug:
                while True:
                    slug = _generate_random_slug()
                    if slug not in slugs:
                        break

            slugs.add(slug.lower())
            op.execute(
                group_tbl.update()
                .values(slug=slug)
                .where(group_tbl.c.uuid == group.uuid)
            )

    op.alter_column('auth_group', 'slug', nullable=False)


def downgrade():
    op.drop_index(IDX_NAME)
    op.drop_column('auth_group', 'slug')
