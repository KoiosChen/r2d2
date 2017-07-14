"""empty message

Revision ID: a41e470fa5ad
Revises: 0f3966b5cf96
Create Date: 2017-03-14 09:11:24.910144

"""

# revision identifiers, used by Alembic.
revision = 'a41e470fa5ad'
down_revision = '0f3966b5cf96'

from alembic import op
import sqlalchemy as sa


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.add_column('pon_alarm_record', sa.Column('ontid', sa.String(length=3), nullable=True))
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('pon_alarm_record', 'ontid')
    ### end Alembic commands ###
