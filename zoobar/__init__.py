#!/usr/bin/env python3.7

from flask import Flask, g

import login
import index
import users
import transfer
import zoobarjs
import zoodb
from debug import catch_err

app = Flask(__name__)

app.add_url_rule("/", "index", index.index, methods=['GET', 'POST'])
app.add_url_rule("/users", "users", users.users)
app.add_url_rule("/zoobarjs", "zoobarjs", zoobarjs.zoobarjs, methods=['GET'])
app.add_url_rule("/webauthn_js", "webauthn_js", zoobarjs.webauthn_js, methods=['GET'])
app.add_url_rule("/base64_js", "base64_js", zoobarjs.base64_js, methods=['GET'])

app.add_url_rule("/webauthn_begin_register", "webauthn_begin_register", login.webauthn_begin_register, methods=['POST'])
app.add_url_rule("/webauthn_finish_register", "webauthn_finish_register", login.webauthn_finish_register, methods=['POST'])

app.add_url_rule("/webauthn_begin_login", "webauthn_begin_login", login.webauthn_begin_login, methods=['POST'])
app.add_url_rule("/webauthn_finish_login", "webauthn_finish_login", login.webauthn_finish_login, methods=['POST'])

app.add_url_rule("/webauthn_begin_transfer", "webauthn_begin_transfer", transfer.webauthn_begin_transfer, methods=['POST'])
app.add_url_rule("/webauthn_finish_transfer", "webauthn_finish_transfer", transfer.webauthn_finish_transfer, methods=['POST'])
app.add_url_rule("/transfer_page", "transfer_page", transfer.transfer_page, methods=['GET'])

app.add_url_rule("/login_page", "login_page", login.login_page, methods=['GET'])
app.add_url_rule("/logout", "logout", login.logout)

# Set the secret key for the `session` container
app.secret_key = "A random string" # TODO: This is insecure

@app.after_request
@catch_err
def disable_xss_protection(response):
    response.headers.add("X-XSS-Protection", "0")
    return response

if __name__ == "__main__":
    app.run()
    #app.run(ssl_context=('/home/httpd/server.crt', '/home/httpd/server.key'))
