"""

Revision ID: 92ee0671e568
Revises: 3dc586299daf
Create Date: 2020-05-31 14:56:30.210420

"""

# revision identifiers, used by Alembic.
revision = '92ee0671e568'
down_revision = '3dc586299daf'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table('agents',
    sa.Column('agent_id', sa.Integer(), nullable=False),
    sa.Column('addr', sa.String(length=40), nullable=False),
    sa.Column('machine_id', sa.String(length=64), nullable=False),
    sa.Column('timestamp', sa.DateTime(), nullable=False),
    sa.Column('display_name', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('agent_id'),
    sa.UniqueConstraint('agent_id')
    )
    op.create_table('agent_devices',
    sa.Column('agent_device_id', sa.Integer(), nullable=False),
    sa.Column('agent_id', sa.Integer(), nullable=False),
    sa.Column('fwupd_id', sa.Text(), nullable=False),
    sa.Column('name', sa.Text(), nullable=False),
    sa.Column('icon', sa.Text(), nullable=False),
    sa.Column('version', sa.Text(), nullable=False),
    sa.Column('updatable', sa.Boolean(), nullable=True),
    sa.Column('needs_reboot', sa.Boolean(), nullable=True),
    sa.ForeignKeyConstraint(['agent_id'], ['agents.agent_id'], ),
    sa.PrimaryKeyConstraint('agent_device_id'),
    sa.UniqueConstraint('agent_device_id')
    )
    op.create_index(op.f('ix_agent_devices_agent_id'), 'agent_devices', ['agent_id'], unique=False)
    op.create_table('agent_releases',
    sa.Column('agent_release_id', sa.Integer(), nullable=False),
    sa.Column('agent_device_id', sa.Integer(), nullable=False),
    sa.Column('version', sa.Text(), nullable=False),
    sa.Column('checksum', sa.Text(), nullable=False),
    sa.Column('is_upgrade', sa.Boolean(), nullable=True),
    sa.Column('blocked_approval', sa.Boolean(), nullable=True),
    sa.ForeignKeyConstraint(['agent_device_id'], ['agent_devices.agent_device_id'], ),
    sa.PrimaryKeyConstraint('agent_release_id'),
    sa.UniqueConstraint('agent_release_id')
    )
    op.create_index(op.f('ix_agent_releases_agent_device_id'), 'agent_releases', ['agent_device_id'], unique=False)
    op.create_table('agent_approvals',
    sa.Column('approval_id', sa.Integer(), nullable=False),
    sa.Column('agent_id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('timestamp', sa.DateTime(), nullable=False),
    sa.Column('checksum', sa.Text(), nullable=True),
    sa.ForeignKeyConstraint(['agent_id'], ['agents.agent_id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['users.user_id'], ),
    sa.PrimaryKeyConstraint('approval_id'),
    sa.UniqueConstraint('approval_id')
    )
    op.create_index(op.f('ix_agent_approvals_agent_id'), 'agent_approvals', ['agent_id'], unique=False)
    op.create_index(op.f('ix_agent_approvals_user_id'), 'agent_approvals', ['user_id'], unique=False)


def downgrade():
    op.drop_index(op.f('ix_agent_approvals_user_id'), table_name='agent_approvals')
    op.drop_index(op.f('ix_agent_approvals_agent_id'), table_name='agent_approvals')
    op.drop_table('agent_approvals')
    op.drop_index(op.f('ix_agent_releases_agent_device_id'), table_name='agent_releases')
    op.drop_table('agent_releases')
    op.drop_index(op.f('ix_agent_devices_agent_id'), table_name='agent_devices')
    op.drop_table('agent_devices')
    op.drop_table('agents')
