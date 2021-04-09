"""create the wazo_default_admin_policy

Revision ID: 2c1a43889d04
Revises: 12a91e0863f5

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '2c1a43889d04'
down_revision = '12a91e0863f5'


POLICY_NAME = 'wazo_default_admin_policy'
POLICY_DESCRIPTION = '''\
Default Wazo policy for administrator authentification backends

Do not modify this policy, it can be modified in future Wazo upgrades
'''
DEFAULT_USER_ACL_TEMPLATES = [
    "confd.#",
    "auth.policies.#",
    "dird.tenants.{% if entity %}{{ entity }}.#{% else %}#{% endif %}",
]

policy_table = sa.sql.table(
    'auth_policy',
    sa.Column('uuid', sa.String(38)),
    sa.Column('name', sa.String(80)),
    sa.Column('description', sa.Text),
)
acl_template_table = sa.sql.table(
    'auth_acl_template', sa.Column('id', sa.Integer), sa.Column('template', sa.Text)
)
policy_template = sa.sql.table(
    'auth_policy_template',
    sa.Column('policy_uuid', sa.String(38)),
    sa.Column('template_id', sa.Integer),
)


def upgrade():
    op.execute(policy_table.delete().where(policy_table.c.name == POLICY_NAME))

    if True:
        # NOTE(fblackburn): Since 21.05 default policies are not managed by the database anymore
        # But we don't want to keep this historic for new DB
        return

    conn = op.get_bind()
    query = (
        policy_table.insert()
        .returning(policy_table.c.uuid)
        .values(name=POLICY_NAME, description=POLICY_DESCRIPTION)
    )
    policy_uuid = conn.execute(query).scalar()
    acl_template_ids = []
    for acl_template in DEFAULT_USER_ACL_TEMPLATES:
        query = (
            sa.sql.select([acl_template_table.c.id])
            .where(acl_template_table.c.template == acl_template)
            .limit(1)
        )
        acl_template_id = conn.execute(query).scalar()
        if not acl_template_id:
            query = (
                acl_template_table.insert()
                .returning(acl_template_table.c.id)
                .values(template=acl_template)
            )
            acl_template_id = conn.execute(query).scalar()
        acl_template_ids.append(acl_template_id)
    op.bulk_insert(
        policy_template,
        [
            {'policy_uuid': policy_uuid, 'template_id': template_id}
            for template_id in acl_template_ids
        ],
    )


def downgrade():
    op.execute(policy_table.delete().where(policy_table.c.name == POLICY_NAME))
