"""

Revision ID: 814ccd8a065b
Revises: 38831f5bfa01
Create Date: 2019-08-12 15:13:50.655955

"""

# revision identifiers, used by Alembic.
revision = '814ccd8a065b'
down_revision = '38831f5bfa01'

from alembic import op
import sqlalchemy as sa

def upgrade():
    op.add_column('vendors', sa.Column('internal_team', sa.Text(), nullable=True))

def downgrade():
    op.drop_column('vendors', 'internal_team')
