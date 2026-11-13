"""Authenticated HTTP interface; OIDC verification is delegated to Authlib."""
import hashlib
import hmac
import json
import os
import secrets
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit

from authlib.integrations.flask_client import OAuth
from flask import Flask, abort, g, jsonify, redirect, render_template, request, session, send_from_directory
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

import server
import storage
from security_state import SecurityState


def env_bool(name, default):
    return os.environ.get(name, str(default)).lower() in ['1', 'true', 'yes']


def create_app(overrides=None):
    app = Flask(__name__, static_folder=None, template_folder='static')
    public = os.environ.get('PUBLIC_URL', 'http://localhost:8102').rstrip('/')
    app.config.update(
        SECRET_KEY=os.environ.get('SESSION_SECRET', ''),
        ADMIN_PASSWORD=os.environ.get('ADMIN_PASSWORD', ''),
        ADMIN_USERNAME=os.environ.get('ADMIN_USERNAME', 'admin'),
        PUBLIC_URL=public,
        SESSION_COOKIE_NAME='invy_session',
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        SESSION_COOKIE_SECURE=env_bool('SESSION_COOKIE_SECURE', public.startswith('https://')),
        PERMANENT_SESSION_LIFETIME=timedelta(hours=int(os.environ.get('SESSION_HOURS', '8'))),
        SESSION_REFRESH_EACH_REQUEST=False,
        MAX_CONTENT_LENGTH=8_000_000,
        MAX_FORM_MEMORY_SIZE=16384,
        MAX_FORM_PARTS=4,
        OIDC_ISSUER_URL=os.environ.get('OIDC_ISSUER_URL', ''),
        OIDC_DISCOVERY_URL=os.environ.get('OIDC_DISCOVERY_URL', ''),
        OIDC_CLIENT_ID=os.environ.get('OIDC_CLIENT_ID', ''),
        OIDC_CLIENT_SECRET=os.environ.get('OIDC_CLIENT_SECRET', ''),
        OIDC_SCOPES=os.environ.get('OIDC_SCOPES', 'openid profile email'),
        OIDC_USERNAME_CLAIM=os.environ.get('OIDC_USERNAME_CLAIM', 'preferred_username'),
        OIDC_GROUPS_CLAIM=os.environ.get('OIDC_GROUPS_CLAIM', 'groups'),
        OIDC_ALLOWED_GROUPS=os.environ.get('OIDC_ALLOWED_GROUPS', ''),
        OIDC_TOKEN_AUTH_METHOD=os.environ.get('OIDC_TOKEN_AUTH_METHOD', 'client_secret_basic'),
        ADMIN_LOGIN_ATTEMPTS=int(os.environ.get('ADMIN_LOGIN_ATTEMPTS', '5')),
        ADMIN_LOGIN_WINDOW=int(os.environ.get('ADMIN_LOGIN_WINDOW', '900')),
    )
    if overrides:
        app.config.update(overrides)
    if len(app.config['SECRET_KEY']) < 32:
        raise ValueError('SESSION_SECRET must contain at least 32 characters.')
    if len(app.config['ADMIN_PASSWORD']) < 24:
        raise ValueError('ADMIN_PASSWORD must contain at least 24 characters.')
    storage.safe_username(app.config['ADMIN_USERNAME'])
    url = urlsplit(app.config['PUBLIC_URL'])
    if url.scheme not in ['http', 'https'] or not url.netloc or url.path not in ['', '/'] or url.query or url.fragment or url.username or url.password:
        raise ValueError('PUBLIC_URL must be the public origin, e.g. https://inventory.clankpilot.top')
    if not app.testing and url.scheme == 'https' and not app.config['SESSION_COOKIE_SECURE']:
        raise ValueError('HTTPS deployments require SESSION_COOKIE_SECURE=true.')
    if app.config['ADMIN_PASSWORD'].startswith('replace-') or app.config['SECRET_KEY'].startswith('replace-'):
        raise ValueError('Replace the example passwords/secrets with independently generated random values.')
    if not 0 < app.config['PERMANENT_SESSION_LIFETIME'].total_seconds() <= 86400:
        raise ValueError('SESSION_HOURS must be positive and at most 24.')
    if not 1 <= app.config['ADMIN_LOGIN_ATTEMPTS'] <= 20 or not 30 <= app.config['ADMIN_LOGIN_WINDOW'] <= 86400:
        raise ValueError('Invalid admin throttle limits.')
    app.config['TRUSTED_HOSTS'] = [url.hostname, 'localhost', '127.0.0.1']
    if app.config['SESSION_COOKIE_SECURE']:
        app.config['SESSION_COOKIE_NAME'] = '__Host-invy_session'
    password_hash = generate_password_hash(app.config['ADMIN_PASSWORD'])
    fingerprints = {
        'admin': hmac.new(app.secret_key.encode(), ('admin:' + app.config['ADMIN_USERNAME'] + ':' + app.config['ADMIN_PASSWORD']).encode(), 'sha256').hexdigest(),
        'oidc': hmac.new(app.secret_key.encode(), json.dumps({key: app.config[key] for key in app.config if key.startswith('OIDC_')}, sort_keys=True).encode(), 'sha256').hexdigest(),
    }
    registry = SecurityState(server.DATA_FILE.parent)
    # Keep only the derived hash in Flask config once initialized.
    app.config.pop('ADMIN_PASSWORD')
    configured = all(app.config[key] for key in ['OIDC_ISSUER_URL', 'OIDC_CLIENT_ID', 'OIDC_CLIENT_SECRET'])
    oauth = OAuth(app)
    provider = None
    if configured:
        if 'openid' not in app.config['OIDC_SCOPES'].split():
            raise ValueError('OIDC_SCOPES must include openid.')
        if not app.testing:
            for endpoint in [app.config['OIDC_ISSUER_URL'], app.config['OIDC_DISCOVERY_URL'] or app.config['OIDC_ISSUER_URL']]:
                parsed = urlsplit(endpoint)
                if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
                    raise ValueError('OIDC issuer and discovery URLs must use HTTPS without embedded credentials.')
        provider = oauth.register('provider', client_id=app.config['OIDC_CLIENT_ID'], client_secret=app.config['OIDC_CLIENT_SECRET'],
            server_metadata_url=app.config['OIDC_DISCOVERY_URL'] or app.config['OIDC_ISSUER_URL'].rstrip('/') + '/.well-known/openid-configuration',
            client_kwargs={'scope': app.config['OIDC_SCOPES'], 'code_challenge_method': 'S256',
                           'token_endpoint_auth_method': app.config['OIDC_TOKEN_AUTH_METHOD'], 'timeout': 10})
    app.extensions['invy_provider'] = provider

    def csrf():
        if 'csrf' not in session:
            session['csrf'] = secrets.token_urlsafe(32)
        return session['csrf']

    def verify_csrf():
        if request.is_json:
            body = request.get_json(silent=True)
            value = request.headers.get('X-CSRF-Token') or (body.get('csrf') if isinstance(body, dict) else None)
        else:
            value = request.form.get('csrf_token')
        if not value or not secrets.compare_digest(str(value), session.get('csrf', '')):
            abort(403, 'Invalid CSRF token. Reload the page and try again.')

    def sign_in(username, identity, email='', method='oidc'):
        previous = session.get('user')
        if previous:
            registry.revoke(previous['session_id'])
        session.clear()
        session.permanent = True
        session['user'] = {'id': identity, 'username': storage.safe_username(username), 'email': email, 'method': method,
                           'session_id': secrets.token_urlsafe(32)}
        registry.issue(session['user']['session_id'], fingerprints[method], app.config['PERMANENT_SESSION_LIFETIME'].total_seconds())
        csrf()

    def check_issuer():
        metadata = provider.load_server_metadata()
        if metadata.get('issuer') != app.config['OIDC_ISSUER_URL']:
            raise ValueError('OIDC discovery issuer does not match OIDC_ISSUER_URL.')
        for name in ['authorization_endpoint', 'token_endpoint', 'jwks_uri']:
            endpoint = urlsplit(metadata.get(name, ''))
            if endpoint.scheme != 'https' or not endpoint.hostname or endpoint.username or endpoint.password:
                raise ValueError('OIDC endpoints must use HTTPS without embedded credentials.')

    @app.before_request
    def authenticate():
        if request.path == '/admin':
            request.max_content_length = 16384
        g.user = session.get('user')
        if g.user:
            fingerprint = fingerprints.get(g.user.get('method'))
            if not fingerprint or not registry.active(g.user['session_id'], fingerprint):
                session.clear()
                g.user = None
        if request.path == '/admin' and request.content_length and request.content_length > 16384:
            abort(413, 'Login request is too large.')
        public_route = request.path in ['/health', '/admin', '/auth/login', '/auth/callback', '/style.css'] or request.path.startswith('/vendor/')
        if not public_route and not g.user:
            if request.path.startswith('/api/'):
                return jsonify(error='Sign in required.', login_url='/auth/login'), 401
            return redirect('/auth/login')
        if g.user and request.method == 'POST' and request.path != '/admin':
            verify_csrf()

    @app.after_request
    def headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'same-origin'
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Content-Security-Policy'] = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        if app.config['SESSION_COOKIE_SECURE']:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000'
        return response

    @app.errorhandler(HTTPException)
    def http_error(error):
        if request.path.startswith('/api/'):
            return jsonify(error=error.description), error.code
        return render_template('auth.html', title='Unable to continue', message=error.description), error.code

    @app.get('/')
    def index():
        return render_template('index.html', csrf_token=csrf(), username=g.user['username'])

    @app.get('/style.css')
    @app.get('/app.js')
    @app.get('/vendor/<path:filename>')
    def assets(filename=None):
        relative = 'vendor/' + filename if filename is not None else request.path.lstrip('/')
        return send_from_directory(Path(__file__).parent / 'static', relative)

    @app.route('/admin', methods=['GET', 'POST'])
    def admin_login():
        if request.method == 'GET':
            return render_template('auth.html', title='Admin login', admin=True, csrf_token=csrf())
        verify_csrf()
        # Do not trust arbitrary X-Forwarded-For values. Behind a proxy, clients
        # share a bucket unless the host explicitly establishes trusted real-IP handling.
        key = hashlib.sha256(request.remote_addr.encode()).hexdigest()
        if not registry.attempt(key, app.config['ADMIN_LOGIN_ATTEMPTS'], app.config['ADMIN_LOGIN_WINDOW']):
            return render_template('auth.html', title='Admin login', admin=True, csrf_token=csrf(), message='Too many attempts. Try again later.'), 429
        if len(request.form.get('password', '')) > 1024:
            abort(413, 'Password is too long.')
        if not check_password_hash(password_hash, request.form.get('password', '')):
            return render_template('auth.html', title='Admin login', admin=True, csrf_token=csrf(), message='Incorrect password.'), 401
        registry.clear_attempts(key)
        sign_in(app.config['ADMIN_USERNAME'], 'admin:' + app.config['ADMIN_USERNAME'], method='admin')
        return redirect('/')

    @app.get('/auth/login')
    def login():
        if g.user:
            return redirect('/')
        if provider is None:
            return render_template('auth.html', title='Sign-in is not configured', message='The administrator must configure the external sign-in provider before you can continue.'), 503
        try:
            check_issuer()
            return provider.authorize_redirect(app.config['PUBLIC_URL'] + '/auth/callback', nonce=secrets.token_urlsafe(32))
        except Exception:
            app.logger.exception('OIDC authorization could not start')
            return render_template('auth.html', title='Sign-in unavailable', message='The identity provider could not be reached. Please try again later.'), 503

    @app.get('/auth/callback')
    def callback():
        if provider is None:
            abort(503, 'External sign-in is not configured.')
        try:
            check_issuer()
            token = provider.authorize_access_token()
            # Authlib verifies ID-token signature, issuer, audience, expiry, nonce
            # and the authorization response state before providing userinfo.
            claims = token.get('userinfo')
            if not token.get('id_token') or not claims or not claims.get('sub') or claims.get('iss') != app.config['OIDC_ISSUER_URL']:
                raise ValueError('A validated OIDC ID token is required.')
            allowed = {group.strip() for group in app.config['OIDC_ALLOWED_GROUPS'].split(',') if group.strip()}
            groups = claims.get(app.config['OIDC_GROUPS_CLAIM'], [])
            if allowed and (not isinstance(groups, list) or not allowed.intersection(groups)):
                abort(403, 'Your account is not assigned to Invy.')
            username = claims.get(app.config['OIDC_USERNAME_CLAIM']) or claims['sub']
            sign_in(username, claims['iss'] + ':' + claims['sub'], claims.get('email', ''))
            return redirect('/')
        except HTTPException:
            raise
        except Exception:
            app.logger.warning('OIDC callback rejected', exc_info=False)
            return render_template('auth.html', title='Sign-in failed', message='The sign-in response could not be verified. Start a new sign-in attempt.'), 400

    @app.post('/auth/logout')
    def logout():
        registry.revoke(g.user['session_id'])
        with storage.transaction(server.DATA_FILE) as state:
            if state and state['lease'] and state['lease'].get('owner') == g.user['session_id']:
                state['lease'] = None
        session.clear()
        return render_template('auth.html', title='Signed out', message='You have signed out of Invy.', sign_in=True)

    @app.get('/health')
    @app.get('/api/inventory')
    def inventory():
        try:
            with storage.transaction(server.DATA_FILE) as state:
                if state is None:
                    raise ValueError('Missing inventory file')
                result = storage.snapshot(state)
            return jsonify(ok=True) if request.path == '/health' else jsonify(result)
        except Exception:
            app.logger.exception('Inventory file unavailable')
            return jsonify(error='Inventory file unavailable. Keep your draft and try again.'), 503

    @app.post('/api/<action>')
    def mutation(action):
        if not request.is_json:
            return jsonify(error='JSON required.'), 415
        body = request.get_json()
        if not isinstance(body, dict):
            abort(400, 'Invalid request.')
        try:
            return jsonify(server.mutate('/api/' + action, body, g.user))
        except server.RequestError as error:
            return jsonify(error=error.message), error.status
        except Exception:
            app.logger.exception('Inventory save or history commit failed')
            return jsonify(error='The inventory could not be saved. Keep your draft and try again.'), 503

    server.initialize()
    return app
