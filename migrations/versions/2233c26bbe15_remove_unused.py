"""

Revision ID: 2233c26bbe15
Revises: 2885e0d3f684
Create Date: 2020-01-28 15:37:04.548157

"""

# revision identifiers, used by Alembic.
revision = '2233c26bbe15'
down_revision = '2885e0d3f684'

from alembic import op
import sqlalchemy as sa

def upgrade():
    op.drop_column('component_claims', 'value')
    op.drop_column('component_claims', 'kind')
    op.drop_column('component_shard_claims', 'value')
    op.drop_column('component_shard_claims', 'kind')
    op.drop_column('component_shard_infos', 'claim_value')
    op.drop_column('component_shard_infos', 'claim_kind')

def downgrade():
    op.add_column('component_shard_infos', sa.Column('claim_kind', sa.TEXT(), autoincrement=False, nullable=True))
    op.add_column('component_shard_infos', sa.Column('claim_value', sa.TEXT(), autoincrement=False, nullable=True))
    op.add_column('component_shard_claims', sa.Column('kind', sa.TEXT(), autoincrement=False, nullable=True))
    op.add_column('component_shard_claims', sa.Column('value', sa.TEXT(), autoincrement=False, nullable=True))
    op.add_column('component_claims', sa.Column('kind', sa.TEXT(), autoincrement=False, nullable=False))
    op.add_column('component_claims', sa.Column('value', sa.TEXT(), autoincrement=False, nullable=False))
