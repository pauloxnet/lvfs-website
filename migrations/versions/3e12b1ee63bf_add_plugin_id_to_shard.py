"""

Revision ID: 3e12b1ee63bf
Revises: 2b65564aa489
Create Date: 2019-05-23 09:51:35.446477

"""

# revision identifiers, used by Alembic.
revision = '3e12b1ee63bf'
down_revision = '2b65564aa489'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('component_shards', sa.Column('plugin_id', sa.Text(), nullable=True))

def downgrade():
    op.drop_column('component_shards', 'plugin_id')
