"""
Settings for OSF OAuth2 demo client
"""

import os

DEBUG = True
SECRET_KEY = os.environ.get('OSF_OAUTH_SECRET_KEY',
                            'Never commit a production secret key to VCS. But for this app, any key will do.')
SESSION_COOKIE_NAME = 'OAUTH_DEMO'

API_BASE_URL = 'https://test-api.osf.io/v2/'

######## OAUTH2 CLIENT SETTINGS ##########
# Describe the application as registered on the OSF
# NOTE: If the callback URL is not registered (or does not match one that is registered), you will get a
#   "successful login" screen from CAS rather than a confirmation page. This is not intuitive, so make sure the
#   callback URL you provide below exactly matches the one used by your application.

# This file contains fake locally generated data; never commit production secret data to Github. Use env vars instead.
CALLBACK_URL = 'http://localhost:5001/callback'  # Must *exactly* match the URL registered for this app
CLIENT_ID = os.environ.get('OSF_OAUTH_CLIENT_ID',
                           'SampleDefaultValue')
CLIENT_SECRET = os.environ.get('OSF_OAUTH_CLIENT_SECRET',
                               'SampleDefaultValue_ResetYourSecretIfCommittedToGithub')


# Server URLs (from the API documentation)
AUTH_BASE_URL = 'https://test-accounts.osf.io/login/oauth2/authorize'
TOKEN_REQUEST_URL = 'https://test-accounts.osf.io/login/oauth2/token'
TOKEN_REFRESH_URL = TOKEN_REQUEST_URL

# If in debug mode, allow oauth client to work without using and/or checking HTTPS
REQUIRE_HTTPS = not DEBUG
