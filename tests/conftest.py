import os 
import tempfile

import pytest
from flaskr import create_app
from flaskr.db import get_db, init_db

with open(os.path.join(os.path.dirname(__file__), 'data.sql'), 'rb') as f:
    _data_sql = f.read().decode('utf8')

@pytest.fixture
def app():
    db_fd, db_path = tempfile.mkstemp() # creates and opens a temporary file, returning file descriptor and path to it

    app = create_app({
        'TESTING': True, # tells Flask app is in test mode
        'DATABASE': db_path,
    })

    with app.app_context():
        init_db()
        get_db().executescript(_data_sql)
    
    yield app

    os.close(db_fd)
    os.unlink(db_path)

@pytest.fixture
def client(app):
    return app.test_client() # creates test client objects, allows HTTP rrequest simulation

@pytest.fixture
def runner(app):
    return app.test_cli_runner() # can call Click commands registered with application

class AuthActions(object): # helper class for User Login Authorization
    def __init__(self, client):
        self._client = client
    
    def login(self, username='test', password='test'): # logs in as test user POST
        return self._client.post(
            '/auth/login',
            data={'username': username, 'password': password}
        )
    
    def logout(self): # logs out as test user GET
        return self._client.get('/auth/logout')



@pytest.fixture
def auth(client):
    return AuthActions(client)