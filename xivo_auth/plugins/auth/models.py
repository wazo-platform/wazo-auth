from xivo_auth.extensions import sqlalchemy as db
from sqlalchemy.types import Integer, String
from sqlalchemy.schema import Column, PrimaryKeyConstraint

class User(db.Model):

    __tablename__ = 'userfeatures'
    __table_args__ = (
        PrimaryKeyConstraint('id'),
    )

    id = Column(Integer, nullable=False)
    loginclient = Column(String(64), nullable=False, server_default='')
    passwdclient = Column(String(64), nullable=False, server_default='')

    def verify_password(self, passwd):
        if self.passwdclient == passwd:
            return True
        return False
