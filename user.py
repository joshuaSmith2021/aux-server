from base64 import urlsafe_b64encode
import os
from time import time
from uuid import uuid4

from flask_login import UserMixin
import requests

from db import get_db

SPOTIFY_CLIENT_ID = os.environ.get('SPOTIFY_CLIENT_ID', None)
SPOTIFY_CLIENT_SECRET = os.environ.get('SPOTIFY_CLIENT_SECRET', None)
SPOTIFY_REDIRECT_URI = 'https://127.0.0.1:5000/spotifycallback'


class User(UserMixin):
    def __init__(self, id_, name, email, profile_pic):
        self.id = id_
        self.name = name
        self.email = email
        self.profile_pic = profile_pic

    @staticmethod
    def get(user_id):
        db = get_db()
        user = db.execute(
            "SELECT * FROM user WHERE id = ?", (user_id,)
        ).fetchone()
        if not user:
            return None

        user = User(
            id_=user[0], name=user[1], email=user[2], profile_pic=user[3]
        )
        return user

    @staticmethod
    def get_user_id_from_uuid(user_uuid):
        db = get_db()

        user = db.execute(
            'SELECT id FROM user WHERE uuid = "%s"' % user_uuid
        ).fetchone()

        if not user:
            return None

        return user[0]

    @staticmethod
    def create(id_, name, email, profile_pic):
        db = get_db()
        db.execute(
            "INSERT INTO user (id, name, email, profile_pic) "
            "VALUES (?, ?, ?, ?)",
            (id_, name, email, profile_pic),
        )
        db.commit()

    @staticmethod
    def refresh_access_token(user_id):
        # TODO: Refresh the access token for a user

        db = get_db()

        query = [
            'SELECT refresh_token',
            'FROM user',
            'WHERE id = "%s"' % user_id
        ]

        row = db.execute(' '.join(query)).fetchone()
        refresh_token = row[0]

        request_url = 'https://accounts.spotify.com/api/token'

        client_info = '%s:%s' % (SPOTIFY_CLIENT_ID, SPOTIFY_CLIENT_SECRET)
        authorization = urlsafe_b64encode(client_info.encode()).decode()

        headers = {
            'Authorization': 'Basic %s' % authorization,
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        data = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token
        }

        req = requests.post(request_url, headers=headers, data=data)

        response = req.json()

        access_token = response['access_token']
        expiration = int(time()) + response['expires_in']

        user = User.get(user_id)
        user.update_access_token(access_token, expiration)

        return access_token

    @staticmethod
    def get_code_status(user_id):
        db = get_db()

        query = [
            'SELECT active',
            'FROM user',
            'WHERE id = "%s"' % user_id
        ]

        row = db.execute(' '.join(query)).fetchone()
        active = row[0]

        if active is None:
            user = User.get(user_id)
            user.set_code_status(0)
            active = 0

        return bool(active)

    @staticmethod
    def get_access_token(user_id):
        # TODO: Get the access token for a user. If the token
        # should be refreshed, refresh it, update the database,
        # and return the new access token.

        db = get_db()

        query = [
            'SELECT access_token, expiration',
            'FROM user',
            'WHERE id = "%s"' % user_id
        ]

        access_token, expiration = db.execute(' '.join(query)).fetchone()

        if time() + 10 > expiration:
            access_token = User.refresh_access_token(user_id)

        return access_token

    def spotify_connected(self):
        db = get_db()

        query = [
            'SELECT refresh_token',
            'FROM user',
            'WHERE id = "%s"' % self.id
        ]

        row = db.execute(' '.join(query)).fetchone()

        return row[0] is not None

    def update_tokens(self, refresh_token, access_token, expiration):
        db = get_db()

        query = [
            'UPDATE user',
            'SET',
            'refresh_token = "%s",' % refresh_token,
            'access_token = "%s",' % access_token,
            'expiration = %d' % expiration,
            'WHERE id = "%s"' % self.id
        ]

        db.execute(' '.join(query))
        db.commit()

    def get_uuid(self):
        db = get_db()

        query = [
            'SELECT uuid',
            'FROM user',
            'WHERE id = "%s"' % self.id
        ]

        row = db.execute(' '.join(query)).fetchone()
        user_uuid = row[0]

        if user_uuid is None:
            user_uuid = self.refresh_uuid()

        return user_uuid

    def update_access_token(self, access_token, expiration):
        db = get_db()

        query = [
            'UPDATE user',
            'SET',
            'access_token = "%s",' % access_token,
            'expiration = %d' % expiration,
            'WHERE id = "%s"' % self.id
        ]

        db.execute(' '.join(query))
        db.commit()

    def update_refresh_token(self, refresh_token):
        db = get_db()
        query = 'UPDATE user SET refresh_token = "%s" WHERE id = "%s"' \
                % (refresh_token, self.id)

        db.execute(query)
        db.commit()

    def refresh_uuid(self):
        db = get_db()

        new_uuid = str(uuid4()).replace('-', '')

        query = [
            'UPDATE user',
            'SET',
            'uuid = "%s"' % new_uuid,
            'WHERE id = "%s"' % self.id
        ]

        db.execute(' '.join(query))
        db.commit()

        return new_uuid

    def set_code_status(self, status):
        '''Status should be a 0 or 1. 1 represents True, meaning that the QR
        code is active. 0 represents False, meaning that the code is disabled.
        '''

        db = get_db()

        query = [
            'UPDATE user',
            'SET',
            'active = %d' % status,
            'WHERE id = "%s"' % self.id
        ]

        db.execute(' '.join(query))
        db.commit()

    def print_status(self):
        db = get_db()
        query = 'SELECT * FROM user WHERE id = "%s"' % self.id
        user = db.execute(query).fetchone()

        print(tuple(user))
