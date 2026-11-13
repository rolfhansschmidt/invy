"""Durable session revocation and login throttling, separate from inventory history."""
import fcntl
import hashlib
import json
import os
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path


class SecurityState:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.path = self.directory / '.security.json'

    @contextmanager
    def transaction(self):
        self.directory.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            state = json.loads(self.path.read_text()) if self.path.exists() else {'sessions': {}, 'attempts': {}}
            before = json.dumps(state, sort_keys=True)
            now = time.time()
            state['sessions'] = {key: value for key, value in state['sessions'].items() if value['expires'] > now}
            yield state
            raw = json.dumps(state, sort_keys=True)
            if raw != before:
                fd, name = tempfile.mkstemp(prefix='.security-', dir=self.directory)
                try:
                    with os.fdopen(fd, 'w') as stream:
                        stream.write(raw)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.replace(name, self.path)
                    os.fsync(descriptor)
                finally:
                    if os.path.exists(name):
                        os.unlink(name)
        finally:
            os.close(descriptor)

    @staticmethod
    def key(session_id):
        return hashlib.sha256(session_id.encode()).hexdigest()

    def issue(self, session_id, fingerprint, lifetime):
        with self.transaction() as state:
            state['sessions'][self.key(session_id)] = {'fingerprint': fingerprint, 'expires': time.time() + lifetime}

    def active(self, session_id, fingerprint):
        with self.transaction() as state:
            record = state['sessions'].get(self.key(session_id))
            return bool(record and record['fingerprint'] == fingerprint)

    def revoke(self, session_id):
        with self.transaction() as state:
            state['sessions'].pop(self.key(session_id), None)

    def attempt(self, key, limit, window):
        with self.transaction() as state:
            now = time.time()
            buckets = {bucket: [stamp for stamp in stamps if now - stamp < window] for bucket, stamps in state['attempts'].items()}
            state['attempts'] = {bucket: stamps for bucket, stamps in buckets.items() if stamps}
            if len(buckets.get(key, [])) >= limit or len(buckets.get('global', [])) >= 100:
                return False
            state['attempts'].setdefault(key, []).append(now)
            state['attempts'].setdefault('global', []).append(now)
            return True

    def clear_attempts(self, key):
        with self.transaction() as state:
            state['attempts'].pop(key, None)
