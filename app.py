"""
Flask application. Modeled in part on https://requests-oauthlib.readthedocs.org/en/latest/#overview

This is a demonstration application, only. This is not the recommended way to handle secret info in production,
    and contains minimal error handling at best.
"""

import httplib as http
import os
import uuid

from flask import Flask, redirect, request, session, url_for
import furl
import requests
from requests import exceptions
from requests_oauthlib import OAuth2Session

import settings


app = Flask(__name__)


# Keep track of authorizations (tokens) granted. This is not persistent and will be wiped whenever the server restarts
#   (to facilitate end to end testing of new features). Dict of form {user_id: token_data}
USER_STORAGE = {}


# Utility functions
def token_updater(token):
    """Store the newest version of the token"""
    uid = session.get('uid')
    if uid is None:
        session['uid'] = uuid.uuid4().hex

    uid = session['uid']
    USER_STORAGE[uid] = token


def get_request_client(token_dict):
    """
    Create a request client configured for OAuth with the appropriate access tokens for a given user

    :param token_dict: Token data returned from OAuth server (including access and refresh tokens for a user)
    :return: Preconfigured oauth2 client
    """
    refresh_kwargs = {'client_id': settings.CLIENT_ID,
                      'client_secret': settings.CLIENT_SECRET,
                      'redirect_uri': settings.CALLBACK_URL}

    client = OAuth2Session(settings.CLIENT_ID,
                           redirect_uri=settings.CALLBACK_URL,
                           token=token_dict,
                           auto_refresh_url=settings.TOKEN_REFRESH_URL,
                           auto_refresh_kwargs=refresh_kwargs,
                           token_updater=token_updater)
    return client


# API Handlers
def api_v2_url(path_str,
               params=None,
               base_route=settings.API_BASE_URL,
               **kwargs):
    """
    Convenience function for APIv2 usage: Concatenates parts of the absolute API url based on arguments provided

    For example: given path_str = '/nodes/abcd3/contributors/' and params {'filter[fullname]': 'bob'},
        this function would return the following on the local staging environment:
        'http://localhost:8000/nodes/abcd3/contributors/?filter%5Bfullname%5D=bob'

    This is NOT a full lookup function. It does not verify that a route actually exists to match the path_str given.
    """
    params = params or {}  # Optional params dict for special-character param names, eg filter[fullname]

    base_url = furl.furl(base_route)
    sub_url = furl.furl(path_str)

    base_url.path.add(sub_url.path.segments)

    base_url.args.update(params)
    base_url.args.update(kwargs)
    return str(base_url)


class ApiV2(object):
    """
    Mock class for OSF APIv2 calls. Can pass in a preconfigured client for OAuth usage.

    :param client: A `requests`-like object for making API calls.
    """
    def __init__(self, client=None):
        self.client = client or requests

    def get_user_id(self):
        url = api_v2_url('/users/me')
        res = self.client.get(url)
        # Raise exception if bad error code
        try:
            res.raise_for_status()
        except exceptions.HTTPError as e:
            # print res.content
            raise e

        data = res.json()['data']
        return data['id']

    def get_projects_count(self, filters=None):
        url = api_v2_url('/nodes', params=filters)
        res = self.client.get(url)
        # Raise exception if bad error code
        try:
            res.raise_for_status()
        except exceptions.HTTPError as e:
            # print res.content
            raise e
        return res.json()['links']['meta']['total']

    def get_applications(self):
        url = api_v2_url('/applications')
        res = self.client.get(url)
        try:
            res.raise_for_status()
        except exceptions.HTTPError as e:
            # print res.content
            raise e
        return res.json()


# Routes
@app.route('/', methods=['GET'])
def home():
    """Display auth screen, or redirect to the action, as appropriate"""
    uid = session.get('uid')
    if uid is None:
        session['uid'] = uuid.uuid4().hex

    token = USER_STORAGE.get(uid)
    if token is None:
        return redirect(url_for('login_with_full_read_scope'))

    return redirect(url_for('permissions_checker'))


def login_common(scope_names_list=None):
    """Ask user to grant authorization with the specified scopes. Used by various login methods."""
    osf = OAuth2Session(client_id=settings.CLIENT_ID,
                        redirect_uri=settings.CALLBACK_URL,
                        scope=scope_names_list)
    authorization_url, state = osf.authorization_url(settings.AUTH_BASE_URL,
                                                     approval_prompt='force',
                                                     access_type='online')
    # State is a value used for CSRF prevention, and is sent along with auth to callback URL after user logs in
    session['oauth_state'] = state
    return redirect(authorization_url)


@app.route('/login_bare/', methods=['GET'])
def login_bare():
    """Request access grant, but do not specify any scopes. Expected behavior: grant fails"""
    return login_common()


@app.route('/login_nonexistent/', methods=['GET'])
def login_as_nonexistent():
    """
    Request access grant, with a scope that does not exist. Expected behavior: grant fails.
    """
    scopes = ['nonexistent_scope']
    return login_common(scope_names_list=scopes)


@app.route('/login_with_full_read_scope/', methods=['GET'])
def login_with_full_read_scope():
    """Request access grant. (read only access) Expected behavior: grant succeeds"""
    scopes = ['osf.full_read']
    return login_common(scope_names_list=scopes)


@app.route('/login_with_full_write_scope/', methods=['GET'])
def login_with_full_write_scope():
    """Request access grant. (read and write access) Expected behavior: grant succeeds"""
    scopes = ['osf.full_write']
    return login_common(scope_names_list=scopes)


@app.route('/login_with_two_scopes/', methods=['GET'])
def login_with_two_scopes():
    """Request access grant, including two separate scopes.
    Expected behavior: grant succeeds"""
    scopes = ['osf.full_read', 'osf.full_write']

    return login_common(scope_names_list=scopes)


@app.route('/callback/', methods=['GET'])
def callback():
    """The oauth app redirects the user here; perform logic to fetch access token and redirect to a target url"""
    osf = OAuth2Session(settings.CLIENT_ID, redirect_uri=settings.CALLBACK_URL, state=session['oauth_state'])
    auth_response = request.url

    token = osf.fetch_token(settings.TOKEN_REQUEST_URL,
                            client_secret=settings.CLIENT_SECRET,
                            authorization_response=auth_response,
                            verify=settings.REQUIRE_HTTPS)

    token_updater(token)
    return redirect(url_for('permissions_checker'))


@app.route('/permissions_checker/', methods=['GET'])
def permissions_checker():
    """Test various forms of access"""
    uid = session.get('uid')
    if uid is None:
        return redirect(url_for('home'))

    token = USER_STORAGE.get(uid)

    client = get_request_client(token)
    api = ApiV2(client=client)

    try:
        api.get_user_id()
    except exceptions.HTTPError:
        can_read_users = False
    else:
        can_read_users = True

    try:
        api.get_projects_count()
    except exceptions.HTTPError:
        can_read_projects = False
    else:
        can_read_projects = True

    try:
        api.get_applications()
    except exceptions.HTTPError:
        can_read_applications = False
    else:
        can_read_applications = True

    return """
    Can read users: {} <br>
    Can read projects: {} <br>
    Can read applications: {} <br>
    """.format(can_read_users, can_read_projects, can_read_applications)


@app.route('/query/', methods=['GET'])
def query_as_user():
    """If the user is logged in and has registered an access token, perform queries"""
    uid = session.get('uid')
    if uid is None:
        return redirect(url_for('home'))

    token = USER_STORAGE.get(uid)

    client = get_request_client(token)
    api = ApiV2(client=client)

    try:
        user = api.get_user_id()
        public_count = api.get_projects_count(filters={'filter[public]': 'true'})
        private_count = api.get_projects_count(filters={'filter[public]': 'false'})
    except http.HTTPException:
        return "The token is expired, or does not provide permission for some or all parts of this request"

    return "You're logged in, {}! You have {} public and {} private projects".format(user, public_count, private_count)


@app.route('/reset/', methods=['GET'])
def dump_tokens():
    """For debugging purposes: provide a quick way to drop all token data saved in memory. (will this be
    enough to force a new authorization grant request?)"""
    USER_STORAGE.clear()


if __name__ == '__main__':
    # For local development *only*: disable the HTTPS requirement. Don't do this in production. Really.
    app.config.from_pyfile('settings.py')
    if settings.REQUIRE_HTTPS is False:
        os.environ['DEBUG'] = '1'
        os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

    app.run(port=5001)
