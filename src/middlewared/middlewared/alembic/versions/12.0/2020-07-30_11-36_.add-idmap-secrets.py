""" Add encrypted idmap secret field

Revision ID: 2ad09c4f1b80
Revises: 6d3efdc7ba5b
Create Date: 2020-07-30 11:36:33.228879+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2ad09c4f1b80'
down_revision = '6d3efdc7ba5b'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('directoryservice_idmap_domain', schema=None) as batch_op:
        batch_op.add_column(sa.Column('idmap_domain_secret', middlewared.sqlalchemy.EncryptedText(), nullable=True))

    op.execute("UPDATE directoryservice_idmap_domain SET idmap_domain_secret = ''")

    with op.batch_alter_table('directoryservice_idmap_domain', schema=None) as batch_op:
        batch_op.alter_column('idmap_domain_secret', nullable=False)



def downgrade():
    with op.batch_alter_table('directoryservice_idmap_domain', schema=None) as batch_op:
        batch_op.drop_column('idmap_domain_secret')
