"""squashed baseline wazo-25.14

Revision ID: 1c862ebfbb3a
Revises: None

"""

import os

from alembic import op

# revision identifiers, used by Alembic.
revision = '1c862ebfbb3a'
down_revision = None


def upgrade():
    # Read and execute the SQL dump file
    versions_dir_path = os.path.dirname(__file__)
    sql_file_path = os.path.join(versions_dir_path, 'baseline-2514.sql')

    with open(sql_file_path) as f:
        sql_content = f.read()

    # Execute the SQL content
    op.execute(sql_content)


def downgrade():
    pass
