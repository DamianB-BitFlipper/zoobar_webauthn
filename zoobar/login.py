from flask import g
from flask import redirect
from flask import render_template
from flask import request
from flask import Markup
from flask import make_response
from flask import jsonify
from flask import session

import webauthn

from functools import wraps
from debug import *
from zoodb import *

from util import https_url_for, RP_ID, RP_NAME, ORIGIN
import util

import auth
import bank
import random
import sys

# Trust anchors (trusted attestation roots) should be
# placed in TRUST_ANCHOR_DIR.
TRUST_ANCHOR_DIR = 'trusted_attestation_roots'

class User(object):
    def __init__(self):
        self.person = None

    def checkLogin(self, username, password):
        token = auth.login(username, password)
        if token is not None:
            return self.loginCookie(username, token)
        else:
            return None

    def loginCookie(self, username, token):
        self.setPerson(username, token)
        return "%s#%s" % (username, token)

    def logout(self):
        self.person = None

    def addRegistration(self, ukey, username, password,
                        display_name, pub_key,
                        credential_id, sign_count,
                        rp_id, icon_url):
        token = auth.register(ukey, username, password,
                              display_name, pub_key,
                              credential_id, sign_count,
                              rp_id, icon_url)
        if token is not None:
            return self.loginCookie(username, token)
        else:
            return None

    def checkCookie(self, cookie):
        if not cookie:
            return
        (username, token) = cookie.rsplit("#", 1)
        if auth.check_token(username, token):
            self.setPerson(username, token)

    def setPerson(self, username, token):
        db, person = auth.getPerson(username)
        self.person = person
        self.token = token
        self.zoobars = bank.balance(username)

def logged_in():
    g.user = User()
    g.user.checkCookie(request.cookies.get("PyZoobarLogin"))
    if g.user.person:
        return True
    else:
        return False

def requirelogin(page):
    @wraps(page)
    def loginhelper(*args, **kwargs):
        if not logged_in():
            return redirect(https_url_for('login_page') + "?nexturl=" + request.url.replace("http://localhost", "https://localhost:8080"))
        else:
            return page(*args, **kwargs)
    return loginhelper

@catch_err
def webauthn_begin_register():
    # MakeCredentialOptions
    username = request.form.get('register_username')
    display_name = request.form.get('register_display_name')
    password = request.form.get('register_password')

    if not util.validate_username(username):
        return make_response(jsonify({'fail': 'Invalid username.'}), 401)
    if not util.validate_display_name(display_name):
        return make_response(jsonify({'fail': 'Invalid display name.'}), 401)
    
    if auth.isRegistered(username):
        return make_response(jsonify({'fail': 'User already exists.'}), 401)

    #clear session variables prior to starting a new registration
    session.pop('register_ukey', None)
    session.pop('register_username', None)
    session.pop('register_display_name', None)
    session.pop('register_password', None)
    session.pop('challenge', None)

    session['register_username'] = username
    session['register_display_name'] = display_name

    # TODO: I am not sure if this is safe to do?!?!?
    session['register_password'] = password

    challenge = util.generate_challenge(32)
    ukey = util.generate_ukey()

    # We strip the saved challenge of padding, so that we can do a byte
    # comparison on the URL-safe-without-padding challenge we get back
    # from the browser.
    # We will still pass the padded version down to the browser so that the JS
    # can decode the challenge into binary without too much trouble.
    session['challenge'] = challenge.rstrip('=')
    session['register_ukey'] = ukey
    
    make_credential_options = webauthn.WebAuthnMakeCredentialOptions(
        challenge, RP_NAME, RP_ID, ukey, username, display_name,
        ORIGIN, attestation='none')
    
    return jsonify(make_credential_options.registration_dict)

@catch_err
def webauthn_finish_register():
    user = User()
    cookie = None
    
    challenge = session['challenge']
    username = session['register_username']
    display_name = session['register_display_name']
    password = session['register_password']
    ukey = session['register_ukey']

    registration_response = request.form
    trust_anchor_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), TRUST_ANCHOR_DIR)
    trusted_attestation_cert_required = False
    self_attestation_permitted = True
    none_attestation_permitted = True

    webauthn_registration_response = webauthn.WebAuthnRegistrationResponse(
        RP_ID,
        ORIGIN,
        registration_response,
        challenge,
        trust_anchor_dir,
        trusted_attestation_cert_required,
        self_attestation_permitted,
        none_attestation_permitted,
        uv_required=False)  # User Verification

    try:
        webauthn_credential = webauthn_registration_response.verify()
    except Exception as e:
        return make_response(
            jsonify({'fail': 'Registration failed. Error: {}'.format(e)}), 401)

    # Step 17.
    #
    # Check that the credentialId is not yet registered to any other user.
    # If registration is requested for a credential that is already registered
    # to a different user, the Relying Party SHOULD fail this registration
    # ceremony, or it MAY decide to accept the registration, e.g. while deleting
    # the older registration.
    if auth.credentialIDExists(webauthn_credential.credential_id):
        return make_response(
            jsonify({'fail': 'Credential ID already exists.'}), 401)

    if sys.version_info >= (3, 0):
        webauthn_credential.credential_id = str(
            webauthn_credential.credential_id, "utf-8")
        webauthn_credential.public_key = str(
            webauthn_credential.public_key, "utf-8")
        
    cookie = user.addRegistration(ukey=ukey,
                                  username=username,
                                  password=password,
                                  display_name=display_name,
                                  pub_key=webauthn_credential.public_key,
                                  credential_id=webauthn_credential.credential_id,
                                  sign_count=webauthn_credential.sign_count,
                                  rp_id=RP_ID,
                                  icon_url='https://localhost:8080')

    if not cookie:
        return make_response(jsonify({'fail': 'User already exists.'}), 401)

    nexturl = request.values.get('nexturl', https_url_for('index'))
    response = make_response(jsonify({'nexturl': nexturl}), 200)

    ## Be careful not to include semicolons in cookie value; see
    ## https://github.com/mitsuhiko/werkzeug/issues/226 for more
    ## details.
    response.set_cookie('PyZoobarLogin', cookie)
    return response

@catch_err
def webauthn_begin_login():
    username = request.form.get('login_username')
    password = request.form.get('login_password')

    if not util.validate_username(username):
        return make_response(jsonify({'fail': 'Invalid username.'}), 401)

    _, person = auth.getPerson(username)

    if not person:
        return make_response(jsonify({'fail': 'User does not exist.'}), 401)
    if not person.credential_id:
        return make_response(jsonify({'fail': 'Unknown credential ID.'}), 401)

    session.pop('challenge', None)
    session.pop('login_password', None)

    challenge = util.generate_challenge(32)

    # We strip the padding from the challenge stored in the session
    # for the reasons outlined in the comment in webauthn_begin_activate.
    session['challenge'] = challenge.rstrip('=')
    session['login_password'] = password
    
    webauthn_user = webauthn.WebAuthnUser(
        person.ukey, person.username, person.display_name, person.icon_url,
        person.credential_id, person.pub_key, person.sign_count, person.rp_id)

    webauthn_assertion_options = webauthn.WebAuthnAssertionOptions(
        webauthn_user, challenge)
    
    return jsonify(webauthn_assertion_options.assertion_dict)

@catch_err
def webauthn_finish_login():
    user = User()
    cookie = None    
    
    challenge = session.get('challenge')
    password = session.get('login_password')
    
    assertion_response = request.form
    credential_id = assertion_response.get('id')

    db, person = auth.getPersonByCredentialID(credential_id)
    if not person:
        return make_response(jsonify({'fail': 'User does not exist.'}), 401)

    webauthn_user = webauthn.WebAuthnUser(
        person.ukey, person.username, person.display_name, person.icon_url,
        person.credential_id, person.pub_key, person.sign_count, person.rp_id)

    webauthn_assertion_response = webauthn.WebAuthnAssertionResponse(
        webauthn_user,
        assertion_response,
        challenge,
        ORIGIN,
        uv_required=False)  # User Verification
   
    try:
        sign_count = webauthn_assertion_response.verify()
    except Exception as e:
        return make_response(jsonify({'fail': 'Assertion failed. Error: {}'.format(e)}), 401)
    
    # Update counter.
    person.sign_count = sign_count
    db.commit()

    # TODO: Is this check not performing anything useful?
    if not person.username:
        return make_response(jsonify({'fail': 'You must supply a username to log in.'}), 401)
    elif not password:
        return make_response(jsonify({'fail': 'You must supply a password to log in.'}), 401)
    else:
        cookie = user.checkLogin(person.username, password)
        if not cookie:
            return make_response(jsonify({'fail': 'Invalid username or password.'}), 401)

    nexturl = request.values.get('nexturl', https_url_for('index'))
    response = make_response(jsonify({'nexturl': nexturl}), 200)
    
    ## Be careful not to include semicolons in cookie value; see
    ## https://github.com/mitsuhiko/werkzeug/issues/226 for more
    ## details.
    response.set_cookie('PyZoobarLogin', cookie)
    return response


@catch_err
def login_page():
    nexturl = request.values.get('nexturl', https_url_for('index'))
    return render_template('login.html',
                           nexturl=nexturl,
                           login_username=Markup(request.form.get('login_username', '')))

@catch_err
def logout():
    if logged_in():
        g.user.logout()
    response = redirect(https_url_for('login_page'))
    response.set_cookie('PyZoobarLogin', '')
    return response
