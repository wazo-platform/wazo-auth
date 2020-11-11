"""remove-template-from-acl

Revision ID: 548fcce8aad9
Revises: 24ffaae58c03

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = '548fcce8aad9'
down_revision = '24ffaae58c03'


def _sed_acl_template(old, new):
    new_value = f"replace(template, '{old}', '{new}')"
    all_templates = "SELECT template from auth_acl_template"
    op.execute(
        f"UPDATE auth_acl_template SET template = {new_value} \
        WHERE {new_value} NOT IN ({all_templates});"
    )


def _remove_real_acl_template():
    op.execute("DELETE FROM auth_acl_template WHERE template LIKE '%{{%';")
    op.execute("DELETE FROM auth_acl_template WHERE template LIKE '%{\\%%';")


def upgrade():
    _sed_acl_template('.{{ user_uuid }}.', '.me.')
    _sed_acl_template('.{{ uuid }}.', '.me.')
    _remove_real_acl_template()


def downgrade():
    _sed_acl_template('.me.', '.{{ uuid }}.')
    _sed_acl_template('.me.', '.{{ user_uuid }}.')
