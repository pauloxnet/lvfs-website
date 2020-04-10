"""

Revision ID: 6e1c3e4cfe3c
Revises: 57315c468b88
Create Date: 2020-04-10 10:20:26.701796

"""

# revision identifiers, used by Alembic.
revision = '6e1c3e4cfe3c'
down_revision = '57315c468b88'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('components', sa.Column('release_message', sa.Text(), nullable=True))


def downgrade():
    op.drop_column('components', 'release_message')
