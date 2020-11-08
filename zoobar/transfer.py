from flask import g
from flask import render_template
from flask import request
from flask import jsonify
from flask import make_response
from flask import session

import webauthn

from login import requirelogin
from zoodb import *
from debug import *

from util import https_url_for, ORIGIN
import util

import auth
import bank
import traceback

@catch_err
@requirelogin
def webauthn_begin_transfer():
    amount = request.form.get('transfer_amount')
    recipient = request.form.get('transfer_recipient')

    if not util.validate_transfer_amount(amount):
        return make_response(jsonify({'fail': 'Invalid transfer amount.'}), 401)

    # Make the amount into an int type. Type safety assured by `util.validate_transfer_amount`
    amount = int(amount)
    
    # Extract the logged in `g.user`
    person = g.user.person

    if not person:
        return make_response(jsonify({'fail': 'User does not exist.'}), 401)
    if not person.credential_id:
        return make_response(jsonify({'fail': 'Unknown credential ID.'}), 401)

    session.pop('challenge', None)
    session.pop('transfer_amount', None)
    session.pop('transfer_recipient', None)

    challenge = util.generate_challenge(32)

    # We strip the padding from the challenge stored in the session
    # for the reasons outlined in the comment in webauthn_begin_activate.
    session['challenge'] = challenge.rstrip('=')
    session['transfer_amount'] = amount
    session['transfer_recipient'] = recipient
    session['clientExtensions'] = {'txAuthSimple': "Authorize sending {} coins from {} to {}!".
                                   format(amount, person.username, recipient)}
    
    webauthn_user = webauthn.WebAuthnUser(
        person.ukey, person.username, person.display_name, person.icon_url,
        person.credential_id, person.pub_key, person.sign_count, person.rp_id)

    webauthn_assertion_options = webauthn.WebAuthnAssertionOptions(
        webauthn_user, challenge,
        clientExtensions=session['clientExtensions'])
    
    return jsonify(webauthn_assertion_options.assertion_dict)

@catch_err
@requirelogin
def webauthn_finish_transfer():
    cookie = None    
    
    challenge = session.get('challenge')
    amount = session.get('transfer_amount')
    recipient = session.get('transfer_recipient')
    clientExtensions = session.get('clientExtensions')
    
    assertion_response = request.form
    credential_id = assertion_response.get('id')

    # Make sure action is performed on correct user
    if g.user.person.credential_id != credential_id:
        return make_response(jsonify({'fail': 'Credential ID does not match that of logged in user.'}), 401)
    
    db, person = auth.getPersonByCredentialID(credential_id)
    if not person:
        return make_response(jsonify({'fail': 'User does not exist.'}), 401)
    
    webauthn_user = webauthn.WebAuthnUser(
        person.ukey, person.username, person.display_name, person.icon_url,
        person.credential_id, person.pub_key, person.sign_count, person.rp_id)

    def verify_authenticator_extensions_fn(client_data, expected_authenticator_extensions):
        client_data_extensions = client_data.get('clientExtensions')
        
        # Make sure that the extensions dicts have the same keys
        if client_data_extensions.keys() != expected_authenticator_extensions.keys():
            return False

        # Make sure that the key is only `txAuthSimple` for now
        if client_data_extensions.keys() != {'txAuthSimple'}:
            return False

        # Test the `txAuthSimple` extension, except for line breaks
        if client_data_extensions['txAuthSimple'].replace('\n', '') != \
           expected_authenticator_extensions['txAuthSimple'].replace('\n', ''):
            return False

        # All passed
        return True

    webauthn_assertion_response = webauthn.WebAuthnAssertionResponse(
        webauthn_user,
        assertion_response,
        challenge,
        ORIGIN,
        uv_required=False, # User Verification
        expected_assertion_authenticator_extensions=clientExtensions,
        verify_authenticator_extensions_fn=verify_authenticator_extensions_fn,
    )
   
    try:
        sign_count = webauthn_assertion_response.verify()
    except Exception as e:
        return make_response(jsonify({'fail': 'Assertion failed. Error: {}'.format(e)}), 401)
    
    # Update counter.
    person.sign_count = sign_count
    db.commit()

    # Perform the zoobar transfer
    bank.transfer(g.user.person.username, recipient, amount)
    
    nexturl = request.values.get('nexturl', https_url_for('transfer_page'))
    response = make_response(jsonify({'nexturl': nexturl}), 200)
    
    return response

@catch_err
@requirelogin
def transfer_page():
    return render_template('transfer.html')
