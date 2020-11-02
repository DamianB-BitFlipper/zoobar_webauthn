from zoodb import *
from debug import *

import sys
import hashlib
import random

def newtoken(db, person):
    hashinput = "%s%.10f" % (person.password, random.random())

    # Since Python3, strings need to be encoded before hashing
    if sys.version_info >= (3, 0):
        hashinput = hashinput.encode('utf-8')
    
    person.token = hashlib.md5(hashinput).hexdigest()
    db.commit()
    return person.token

def getPerson(username):
    db = person_setup()
    person = db.query(Person).filter(Person.username == username)
    return db, person.first()
    
def login(username, password):
    db, person = getPerson(username)
    if not person:
        return None
    if person.password == password:
        return newtoken(db, person)
    else:
        return None

def isRegistered(username):
    _, person = getPerson(username)
    return person is not None

def register(ukey, username, password,
             display_name, pub_key,
             credential_id, sign_count,
             rp_id, icon_url):
    # If the `username` is already registered, do not register again
    if isRegistered(username):
        return None
    
    db = person_setup()
    newperson = Person()
    newperson.ukey = ukey
    newperson.username = username
    newperson.password = password
    newperson.display_name = display_name
    newperson.pub_key = pub_key
    newperson.credential_id = credential_id
    newperson.sign_count = sign_count
    newperson.rp_id = rp_id
    newperson.icon_url = icon_url
    
    db.add(newperson)
    db.commit()
    return newtoken(db, newperson)

def credentialIDExists(credential_id):
    db = person_setup()
    person = db.query(Person).filter(Person.credential_id == credential_id).first()
    return person is not None

def check_token(username, token):
    db, person = getPerson(username)
    if person and person.token == token:
        return True
    else:
        return False

