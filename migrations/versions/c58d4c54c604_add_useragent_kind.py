"""

Revision ID: c58d4c54c604
Revises: b59b7d74ed0f
Create Date: 2019-04-10 11:45:38.810364

"""

# revision identifiers, used by Alembic.
revision = 'c58d4c54c604'
down_revision = 'b59b7d74ed0f'

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

def upgrade():
    op.add_column('useragents', sa.Column('kind', sa.Integer(), nullable=True))
    op.create_index(op.f('ix_useragents_kind'), 'useragents', ['kind'], unique=False)

def downgrade():
    op.drop_index(op.f('ix_useragents_kind'), table_name='useragents')
    op.drop_column('useragents', 'kind')
