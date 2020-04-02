"""

Revision ID: f1d919f4797b
Revises: 160f5fd39ab4
Create Date: 2020-04-02 12:19:16.905554

"""

# revision identifiers, used by Alembic.
revision = 'f1d919f4797b'
down_revision = '160f5fd39ab4'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('components', sa.Column('screenshot_url_safe', sa.Text(), nullable=True))

def downgrade():
    op.drop_column('components', 'screenshot_url_safe')
