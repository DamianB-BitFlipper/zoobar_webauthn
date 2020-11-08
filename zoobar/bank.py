from zoodb import *
from debug import *

import auth
import time

def transfer(sender, recipient, zoobars):
    persondb, senderp = auth.getPerson(sender)
    _, recipientp = auth.getPerson(sender, db=persondb)

    senderp.zoobars -= zoobars
    recipientp.zoobars += zoobars

    # Make sure no balances went negative
    if senderp.zoobars < 0 or recipientp.zoobars < 0:
        raise ValueError()    
    
    persondb.commit()

    transfer = Transfer()
    transfer.sender = sender
    transfer.recipient = recipient
    transfer.amount = zoobars
    transfer.time = time.asctime()

    transferdb = transfer_setup()
    transferdb.add(transfer)
    transferdb.commit()

def balance(username):
    db, person = auth.getPerson(username)
    return person.zoobars

def get_log(username):
    db = transfer_setup()
    return db.query(Transfer).filter(or_(Transfer.sender==username,
                                         Transfer.recipient==username))

