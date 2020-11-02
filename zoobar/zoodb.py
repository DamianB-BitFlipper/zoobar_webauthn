from sqlalchemy import *
from sqlalchemy.orm import *
from sqlalchemy.ext.declarative import *
import os
from debug import *

PersonBase = declarative_base()
TransferBase = declarative_base()

class Person(PersonBase):
    __tablename__ = "person"
    id = Column(Integer, primary_key=True)
    
    ukey = Column(String(20), unique=True, nullable=False)
    username = Column(String(128), unique=True, nullable=False)
    password = Column(String(128), nullable=False)
    display_name = Column(String(128), nullable=False)
    pub_key = Column(String(65), unique=True, nullable=True)
    credential_id = Column(String(250), unique=True, nullable=False)
    sign_count = Column(Integer, default=0)
    rp_id = Column(String(253), nullable=False)
    icon_url = Column(String(128), nullable=False)
    
    token = Column(String(128))
    zoobars = Column(Integer, nullable=False, default=10)
    profile = Column(String(5000), nullable=False, default="")

class Transfer(TransferBase):
    __tablename__ = "transfer"
    id = Column(Integer, primary_key=True)
    
    sender = Column(String(128))
    recipient = Column(String(128))
    amount = Column(Integer)
    time = Column(String)

def dbsetup(name, base):
    thisdir = os.path.dirname(os.path.abspath(__file__))
    dbdir   = os.path.join(thisdir, "db", name)
    if not os.path.exists(dbdir):
        os.makedirs(dbdir)

    dbfile  = os.path.join(dbdir, "%s.db" % name)
    engine  = create_engine('sqlite:///%s' % dbfile,
                            isolation_level='SERIALIZABLE')
    base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)
    return session()

def person_setup():
    return dbsetup("person", PersonBase)

def transfer_setup():
    return dbsetup("transfer", TransferBase)

import sys
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: %s [init-person|init-transfer]" % sys.argv[0])
        exit(1)

    cmd = sys.argv[1]
    if cmd == 'init-person':
        person_setup()
    elif cmd == 'init-transfer':
        transfer_setup()
    else:
        raise Exception("unknown command %s" % cmd)
