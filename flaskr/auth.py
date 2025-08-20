import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

# view code

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        # request.form is a special type of dict mapping, submitted form keys and values
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'

        if error is None:
            try:
                db.execute( 
                    "INSERT INTO user (username, password) VALUES (?, ?)",
                    (username, generate_password_hash(password)), # hash password, hash is stored
                )
                db.commit() # previous query modifies data, this is called to save changes
            except db.IntegrityError:
                error = f"User {username} is already registered."
            else:
                return redirect(url_for("auth.login"))
            

        flash(error)
    
    return render_template('auth/register.html')

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone() # returns one row from query

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], password): # hashes submitted pw the same as stored hash, and securely compares them. 
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))
        # session = dict that stores data across requests
        # when validation succeeds, user ID stored in new session.
        # data stored in cookie -> sent to browser -> broswer sends back with requests

        flash(error)
    
    return render_template('auth/login.html')

@bp.before_app_request
def load_logged_in_user(): # checks if user id is stored in session, gets user data from db (storing in g.user), which lasts for the length of request.
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


# for creating, editing, and deleting blog posts
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        
        return view(**kwargs)
    
    return wrapped_view


