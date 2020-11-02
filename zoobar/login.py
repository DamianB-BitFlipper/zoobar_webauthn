from flask import g
from flask import redirect
from flask import render_template
from flask import request
from flask import url_for
from flask import Markup
from flask import make_response
from flask import jsonify
from flask import session

from functools import wraps
from debug import *
from zoodb import *

import webauthn

import util
import auth
import bank
import random
import sys

RP_ID = 'localhost'
RP_NAME = 'webauthn demo localhost'
ORIGIN = 'https://localhost:8080'

# Trust anchors (trusted attestation roots) should be
# placed in TRUST_ANCHOR_DIR.
TRUST_ANCHOR_DIR = 'trusted_attestation_roots'

def https_url_for(page):
    return "https://localhost:8080" + url_for(page)

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
            return redirect(https_url_for('login') + "?nexturl=" + request.url.replace("http://localhost", "https://localhost:8080"))
        else:
            return page(*args, **kwargs)
    return loginhelper

@catch_err
def webauthn_begin_register():
    """ ADDED
    cookie = None
    login_error = ""
    user = User()

    if request.method == 'POST':
        log("ADDED Chasing my cheddar: %s" % (request.form.get('data')))

    nexturl = request.values.get('nexturl', url_for('index'))

    return render_template('login.html',
                           nexturl=nexturl,
                           login_error=login_error,
                           login_username=Markup(request.form.get('login_username', '')))
    """
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
        'https://localhost:8080', attestation='none')
    
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
        return jsonify({'fail': 'Registration failed. Error: {}'.format(e)})

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
    response = redirect(nexturl)

    # ADDED
    log("NEXT URL!")
    log("https://localhost:8080" + nexturl)
    
    ## Be careful not to include semicolons in cookie value; see
    ## https://github.com/mitsuhiko/werkzeug/issues/226 for more
    ## details.
    response.set_cookie('PyZoobarLogin', cookie)
    return response
    
    # ADDED return jsonify({'success': 'User successfully registered.'})

@catch_err
def login():
    cookie = None
    login_error = ""
    user = User()

    if request.method == 'POST':
        username = request.form.get('login_username')
        password = request.form.get('login_password')

        if 'submit_registration' in request.form:
            if not username:
                login_error = "You must supply a username to register."
            elif not password:
                login_error = "You must supply a password to register."
            else:
                cookie = user.addRegistration(username, password)
                if not cookie:
                    login_error = "Registration failed."
        elif 'submit_login' in request.form:
            if not username:
                login_error = "You must supply a username to log in."
            elif not password:
                login_error = "You must supply a password to log in."
            else:
                cookie = user.checkLogin(username, password)
                if not cookie:
                    login_error = "Invalid username or password."

    nexturl = request.values.get('nexturl', https_url_for('index'))
    if cookie:
        response = redirect(nexturl)
        ## Be careful not to include semicolons in cookie value; see
        ## https://github.com/mitsuhiko/werkzeug/issues/226 for more
        ## details.
        response.set_cookie('PyZoobarLogin', cookie)
        return response

    return render_template('login.html',
                           nexturl=nexturl,
                           login_error=login_error,
                           login_username=Markup(request.form.get('login_username', '')))

@catch_err
def logout():
    if logged_in():
        g.user.logout()
    response = redirect(https_url_for('login'))
    response.set_cookie('PyZoobarLogin', '')
    return response
