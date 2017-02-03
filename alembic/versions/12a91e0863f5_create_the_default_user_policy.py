"""create the default_user_policy

Revision ID: 12a91e0863f5
Revises: 4d42b4db090f

"""

# revision identifiers, used by Alembic.
revision = '12a91e0863f5'
down_revision = '4d42b4db090f'

from alembic import op
import sqlalchemy as sa

POLICY_NAME = 'wazo_default_user_policy'
POLICY_DESCRIPTION = '''\
Default Wazo policy for user authentification backends

Do not modify this policy, it can be modified in future Wazo upgrades
'''
DEFAULT_USER_ACL_TEMPLATES = [
    'confd.infos.read',
    'confd.users.me.read',
    'confd.users.me.update',
    'confd.users.me.funckeys.*',
    'confd.users.me.funckeys.*.*',
    'confd.users.me.#.read',
    'confd.users.me.services.*.*',
    'confd.users.me.forwards.*.*',
    'ctid-ng.users.me.#',
    'ctid-ng.users.*.presences.read',
    'ctid-ng.lines.*.presences.read',
    'ctid-ng.switchboards.#',
    'ctid-ng.transfers.*.read',
    'ctid-ng.transfers.*.delete',
    'ctid-ng.transfers.*.complete.update',
    'dird.#.me.read',
    'dird.directories.favorites.#',
    'dird.directories.lookup.*.headers.read',
    'dird.directories.lookup.*.read',
    'dird.directories.personal.*.read',
    'dird.personal.#',
    'events.calls.me',
    'events.chat.message.*.me',
    'events.config.users.me.#',
    'events.statuses.*',
    'events.switchboards.#',
    'events.transfers.me',
    'events.users.me.#',
    'events.directory.me.#',
    'websocketd',
]

policy_table = sa.sql.table(
    'auth_policy',
    sa.Column('uuid', sa.String(38)),
    sa.Column('name', sa.String(80)),
    sa.Column('description', sa.Text),
)
acl_template_table = sa.sql.table(
    'auth_acl_template',
    sa.Column('id', sa.Integer),
    sa.Column('template', sa.Text),
)
policy_template = sa.sql.table(
    'auth_policy_template',
    sa.Column('policy_uuid', sa.String(38)),
    sa.Column('template_id', sa.Integer),
)


def upgrade():
    op.execute(policy_table.delete().where(policy_table.c.name == POLICY_NAME))

    conn = op.get_bind()
    query = policy_table.insert().returning(policy_table.c.uuid).values(
        name=POLICY_NAME,
        description=POLICY_DESCRIPTION,
    )
    policy_uuid = conn.execute(query).scalar()
    acl_template_ids = []
    for acl_template in DEFAULT_USER_ACL_TEMPLATES:
        query = sa.sql.select(
            [acl_template_table.c.id]
        ).where(
            acl_template_table.c.template == acl_template,
        ).limit(1)
        acl_template_id = conn.execute(query).scalar()
        if not acl_template_id:
            query = acl_template_table.insert().returning(acl_template_table.c.id).values(
                template=acl_template,
            )
            acl_template_id = conn.execute(query).scalar()
        acl_template_ids.append(acl_template_id)
    op.bulk_insert(
        policy_template,
        [{'policy_uuid': policy_uuid,
          'template_id': template_id} for template_id in acl_template_ids],
    )


def downgrade():
    op.execute(policy_table.delete().where(policy_table.c.name == POLICY_NAME))
