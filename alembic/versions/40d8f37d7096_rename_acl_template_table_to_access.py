"""rename_acl_template_table_to_access

Revision ID: 40d8f37d7096
Revises: d779d0640bd7

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = '40d8f37d7096'
down_revision = 'd779d0640bd7'


def upgrade():
    op.drop_constraint('auth_policy_template_template_id_fkey', 'auth_policy_template')
    op.rename_table('auth_acl_template', 'auth_access')
    op.rename_table('auth_policy_template', 'auth_policy_access')
    op.alter_column('auth_access', 'template', new_column_name='access')
    op.alter_column('auth_policy_access', 'template_id', new_column_name='access_id')

    # Rename constraints
    op.drop_constraint('auth_acl_template_pkey', 'auth_access')
    op.create_primary_key('auth_access_pkey', 'auth_access', ['id'])

    op.drop_constraint('auth_acl_template_template', 'auth_access')
    op.create_unique_constraint('auth_access_access', 'auth_access', ['access'])

    op.drop_constraint('auth_policy_template_pkey', 'auth_policy_access')
    op.create_primary_key(
        'auth_policy_access_pkey', 'auth_policy_access', ['policy_uuid', 'access_id']
    )
    op.drop_constraint('auth_policy_template_policy_uuid_fkey', 'auth_policy_access')
    op.create_foreign_key(
        'auth_policy_access_policy_uuid_fkey',
        'auth_policy_access',
        'auth_policy',
        ['policy_uuid'],
        ['uuid'],
        ondelete='CASCADE',
    )

    op.create_foreign_key(
        'auth_policy_access_access_id_fkey',
        'auth_policy_access',
        'auth_access',
        ['access_id'],
        ['id'],
        ondelete='CASCADE',
    )


def downgrade():
    op.drop_constraint('auth_policy_access_access_id_fkey', 'auth_policy_access')
    op.rename_table('auth_access', 'auth_acl_template')
    op.rename_table('auth_policy_access', 'auth_policy_template')
    op.alter_column('auth_acl_template', 'access', new_column_name='template')
    op.alter_column('auth_policy_template', 'access_id', new_column_name='template_id')

    # Rename constraints
    op.drop_constraint('auth_access_pkey', 'auth_acl_template')
    op.create_primary_key('auth_acl_template_pkey', 'auth_acl_template', ['id'])

    op.drop_constraint('auth_access_access', 'auth_acl_template')
    op.create_unique_constraint(
        'auth_acl_template_template', 'auth_acl_template', ['template']
    )

    op.drop_constraint('auth_policy_access_pkey', 'auth_policy_template')
    op.create_primary_key(
        'auth_policy_template_pkey',
        'auth_policy_template',
        ['policy_uuid', 'template_id'],
    )
    op.drop_constraint('auth_policy_access_policy_uuid_fkey', 'auth_policy_template')
    op.create_foreign_key(
        'auth_policy_template_policy_uuid_fkey',
        'auth_policy_template',
        'auth_policy',
        ['policy_uuid'],
        ['uuid'],
        ondelete='CASCADE',
    )

    op.create_foreign_key(
        'auth_policy_template_template_id_fkey',
        'auth_policy_template',
        'auth_acl_template',
        ['template_id'],
        ['id'],
        ondelete='CASCADE',
    )
