import json
import os
import secrets
import time
from pathlib import Path

import storage

ROOT = Path(__file__).parent
DATA_FILE = Path(os.environ.get('INVENTORY_FILE', str(ROOT / 'data' / 'inventory.ods')))
LEASE = 90

class RequestError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message


def initialize():
    storage.initialize(DATA_FILE, [])
    with storage.transaction(DATA_FILE) as state:
        storage.ensure_committed(DATA_FILE, state)
        for rollback in DATA_FILE.parent.glob('.invy-rollback-*'):
            if rollback.is_file() or rollback.is_symlink():
                rollback.unlink()


def mutate(path, body, actor):
    with storage.transaction(DATA_FILE, commit_changes=True) as state:
        if state is None:
            raise ValueError('Inventory file is missing; restore it before restarting.')
        now = time.time()
        lease = state['lease']
        active = lease and lease['expires'] > now
        if path == '/api/lock':
            if active:
                raise RequestError(423, 'Someone else is editing. You can keep browsing; try again shortly.')
            token = secrets.token_urlsafe(32)
            state['lease'] = {'token': token, 'expires': now + LEASE, 'owner': actor['session_id']}
            result = storage.snapshot(state)
            result.update(token=token, expires=now + LEASE)
        elif path in ['/api/heartbeat', '/api/release', '/api/save']:
            if not active or lease.get('owner') != actor['session_id'] or not secrets.compare_digest(str(body.get('token', '')), lease['token']):
                raise RequestError(423, 'Your editing lock has expired. Your changes are still on screen. Download your draft before reloading.')
            if path == '/api/heartbeat':
                state['lease']['expires'] = now + LEASE
                result = {'expires': now + LEASE}
            elif path == '/api/release':
                state['lease'] = None
                result = {'ok': True}
            else:
                if body.get('revision') != storage.revision(state['rows']):
                    raise RequestError(409, 'The inventory has changed. Save was rejected to protect newer data.')
                rows = body.get('rows')
                try:
                    storage.validate_rows(rows)
                except ValueError as error:
                    raise RequestError(400, str(error)) from error
                rows = [row for row in rows if any(cell.strip() for cell in row)]
                if rows != state['rows']:
                    state['history'].append({'revision': storage.revision(state['rows']), 'rows': state['rows'], 'updated': state['updated']})
                    state['last_editor'] = {'username': actor['username'], 'email': actor.get('email', ''), 'subject': actor['id']}
                    state['rows'] = rows
                    state['updated'] = now
                state['lease'] = None
                result = storage.snapshot(state)
        else:
            raise RequestError(404, 'Not found')
    # The file is durably committed before acknowledging a successful operation.
    return result
