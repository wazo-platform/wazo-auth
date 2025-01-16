"""use-update-suffix-for-required-acl

Revision ID: ee3444ea3a43
Revises: 4e674b12400f

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = 'ee3444ea3a43'
down_revision = '4e674b12400f'


def upgrade():
    # Remove invalid access that could cause conflict
    op.execute(
        "DELETE FROM auth_access a1 "
        "WHERE a1.access IN "
        "("
        "SELECT replace(access, '.edit', '.update') "
        "FROM auth_access a2 "
        "WHERE a2.access like '%.edit'"
        ");"
    )

    # Update all access ending from 'edit' to 'update'
    op.execute(
        "UPDATE auth_access SET access = replace(access, '.edit', '.update') "
        "WHERE access like '%.edit';"
    )


def downgrade():
    pass
