"""

Revision ID: c30479270168
Revises: c58d4c54c604
Create Date: 2019-04-11 10:33:55.036576

"""

# revision identifiers, used by Alembic.
revision = 'c30479270168'
down_revision = 'c58d4c54c604'

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

def upgrade():
    op.create_table('analytics_firmware',
    sa.Column('analytic_id', sa.Integer(), nullable=False),
    sa.Column('datestr', sa.Integer(), nullable=True),
    sa.Column('firmware_id', sa.Integer(), nullable=False),
    sa.Column('cnt', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['firmware_id'], ['firmware.firmware_id'], ),
    sa.PrimaryKeyConstraint('analytic_id'),
    sa.UniqueConstraint('analytic_id'),
    mysql_character_set='utf8mb4'
    )
    op.create_index(op.f('ix_analytics_firmware_datestr'), 'analytics_firmware', ['datestr'], unique=False)
    op.create_index(op.f('ix_analytics_firmware_firmware_id'), 'analytics_firmware', ['firmware_id'], unique=False)

def downgrade():
    op.drop_table('analytics_firmware')
