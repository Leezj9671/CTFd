"""Change Solves IP to BigInteger and add IP to WrongKeys

Revision ID: 9840438e109d
Revises: c7225db614c1
Create Date: 2017-07-08 13:33:13.930031

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9840438e109d'
down_revision = 'c7225db614c1'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('solves', 'ip', existing_type=sa.Integer(), type_=sa.BigInteger())
    op.add_column('wrong_keys', sa.Column('ip', sa.BigInteger(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('solves', 'ip', existing_type=sa.BigInteger(), type_=sa.Integer())
    op.drop_column('wrong_keys', 'ip')
    # ### end Alembic commands ###