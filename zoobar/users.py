from flask import g, render_template, request, Markup

from login import requirelogin
from zoodb import *
from debug import *

import auth
import bank

@catch_err
@requirelogin
def users():
    args = {}
    args['req_user'] = Markup(request.args.get('user', ''))
    if 'user' in request.values:
        _, user = auth.getPerson(request.values['user'])
        if user:
            p = user.profile

            p_markup = Markup("<b>%s</b>" % p)
            args['profile'] = p_markup

            args['user'] = user
            args['user_zoobars'] = bank.balance(user.username)
            args['transfers'] = bank.get_log(user.username)
        else:
            args['warning'] = "Cannot find that user."
    return render_template('users.html', **args)
