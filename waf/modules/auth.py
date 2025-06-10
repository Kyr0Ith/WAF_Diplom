from functools import wraps
from flask import request, session, redirect
#WIP or not?
USERNAME = 'admin'
PASSWORD = 'waf_admin'  #REPLACE

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'authenticated' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function