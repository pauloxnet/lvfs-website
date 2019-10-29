"""

Revision ID: ecd1aef76799
Revises: 234e715a953a
Create Date: 2019-10-29 14:27:33.345056

"""

# revision identifiers, used by Alembic.
revision = 'ecd1aef76799'
down_revision = '234e715a953a'

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

def upgrade():
    op.drop_column('component_shard_infos', 'name')

def downgrade():
    op.add_column('component_shard_infos', sa.Column('name', mysql.TEXT(), nullable=True))
