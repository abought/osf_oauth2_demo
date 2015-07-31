"""
Settings for OSF OAuth2 demo client
"""

import os

DEBUG = True
SECRET_KEY = "Never commit a secret key to production. For our purposes, though, the key just needs to exist"
SESSION_COOKIE_NAME = 'OAUTH_DEMO'

API_BASE_URL = 'http://localhost:8000/v2/'

######## OAUTH2 CLIENT SETTINGS ##########
# Describe the application as registered on the OSF
# TODO: If the callback URL is not registered (or does not match one that is registered), you will get a
#   "successful login" screen rather than a confirmation page. This is not intuitive, so make sure the
#   callback URL you provide below exactly matches the one used by your application.

# This file contains fake locally generated data; never commit production secret data to Github. Use env vars instead
CALLBACK_URL = 'http://localhost:5000/callback'  # Must exactly match the URL registered with app
CLIENT_ID = os.environ.get('OSF_OAUTH_CLIENT_ID',
                           'b90cf426f99849988d648a0a68987a22')
CLIENT_SECRET = os.environ.get('OSF_OAUTH_CLIENT_SECRET',
                               '7R0XjBt6VvzGhaQxkLDuAptyiDhTCXLvFSIheQUi')


# Server URLs (from the API documentation)
AUTH_BASE_URL = 'https://localhost:8443/oauth2/authorize'
TOKEN_REQUEST_URL = 'https://localhost:8443/oauth2/token'
TOKEN_REFRESH_URL = TOKEN_REQUEST_URL

# If in debug mode, allow oauth client to work without using and/or checking HTTPS
REQUIRE_HTTPS = not DEBUG
