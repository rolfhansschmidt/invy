"""A single ODF spreadsheet, protected with an advisory directory lock on Linux."""
import copy
import fcntl
import hashlib
import io
import json
import os
import re
import secrets
import tempfile
import time
from defusedxml.ElementTree import fromstring as parse_xml
from xml.etree import ElementTree as ET  # nosec B405 - serialization only; all reads use defusedxml
import zipfile
from contextlib import contextmanager
from pathlib import Path
from dulwich.objects import Blob, Commit, Tree
from dulwich.repo import Repo
from dulwich import porcelain

COLUMNS = ['Name', 'Description', 'Storage Location', 'Inventory-Number', 'Additional info', 'Removal Cause']
ORDER = [3, 0, 1, 2, 4, 5]
HEADERS = [COLUMNS[i] for i in ORDER]
MIME = 'application/vnd.oasis.opendocument.spreadsheet'
NS = {
    'office': 'urn:oasis:names:tc:opendocument:xmlns:office:1.0',
    'table': 'urn:oasis:names:tc:opendocument:xmlns:table:1.0',
    'text': 'urn:oasis:names:tc:opendocument:xmlns:text:1.0',
    'meta': 'urn:oasis:names:tc:opendocument:xmlns:meta:1.0',
    'style': 'urn:oasis:names:tc:opendocument:xmlns:style:1.0',
    'fo': 'urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0',
    'manifest': 'urn:oasis:names:tc:opendocument:xmlns:manifest:1.0',
}
for prefix, uri in NS.items():
    ET.register_namespace(prefix, uri)

def q(name):
    prefix, local = name.split(':')
    return '{' + NS[prefix] + '}' + local

def element(parent, name, attrs=None):
    return ET.SubElement(parent, q(name), {q(key): str(value) for key, value in (attrs or {}).items()})

def xml(root):
    return ET.tostring(root, encoding='utf-8', xml_declaration=True).replace(b'\r', b'&#13;')

def validate_rows(rows):
    if not isinstance(rows, list) or len(rows) > 10000:
        raise ValueError('Use at most 10,000 rows.')
    for row in rows:
        if not isinstance(row, list) or len(row) != 6:
            raise ValueError('Use exactly the six fixed columns.')
        for cell in row:
            if not isinstance(cell, str) or len(cell) > 50000:
                raise ValueError('Each cell must be text, up to 50,000 characters.')
            if any(not (char in '\t\n\r' or '\u0020' <= char <= '\ud7ff' or '\ue000' <= char <= '\ufffd' or '\U00010000' <= char <= '\U0010ffff') for char in cell):
                raise ValueError('Cells contain characters that cannot be stored in an ODS file.')

def revision(rows):
    return hashlib.sha256(json.dumps(rows, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()

def paragraph_text(node):
    output = node.text or ''
    for child in node:
        if child.tag == q('text:s'):
            count = int(child.get(q('text:c'), '1'))
            if not 1 <= count <= 50000:
                raise ValueError('Invalid repeated whitespace in ODS.')
            output += ' ' * count
        elif child.tag == q('text:tab'):
            output += '\t'
        elif child.tag == q('text:line-break'):
            output += '\n'
        else:
            output += paragraph_text(child)
        output += child.tail or ''
        if len(output) > 50000:
            raise ValueError('ODS cell is too long.')
    return output

def cell_text(cell):
    if cell.tag == q('table:covered-table-cell'):
        raise ValueError('Merged cells are not supported; keep the six fixed columns.')
    if cell.get(q('table:formula')):
        raise ValueError('Use text values instead of formulas in the inventory file.')
    paragraphs = cell.findall('text:p', NS)
    if paragraphs:
        return '\n'.join(paragraph_text(p) for p in paragraphs)
    for name in ['office:string-value', 'office:value', 'office:date-value', 'office:boolean-value']:
        if cell.get(q(name)) is not None:
            return cell.get(q(name))
    return ''

def read(path):
    with zipfile.ZipFile(path) as archive:
        if sum(info.file_size for info in archive.infolist()) > 128_000_000:
            raise ValueError('ODS file is too large.')
        if archive.read('mimetype').decode().strip() != MIME:
            raise ValueError('Expected an ODS spreadsheet.')
        root = parse_xml(archive.read('content.xml'))
        tables = root.findall('office:body/office:spreadsheet/table:table', NS)
        table = next((t for t in tables if t.get(q('table:name')) == 'Inventory'), None)
        if table is None:
            if len(tables) != 1:
                raise ValueError('ODS must contain an Inventory sheet.')
            table = tables[0]
        grid = []
        for row in table.iter(q('table:table-row')):
            values = []
            for cell in row:
                if cell.tag not in [q('table:table-cell'), q('table:covered-table-cell')]:
                    continue
                value = cell_text(cell)
                count = int(cell.get(q('table:number-columns-repeated'), '1'))
                if count < 1 or (value and len(values) + count > 6):
                    raise ValueError('ODS has data outside the six fixed columns.')
                if len(values) < 6:
                    values.extend([value] * min(count, 6 - len(values)))
            values += [''] * (6 - len(values))
            count = int(row.get(q('table:number-rows-repeated'), '1'))
            if count < 1:
                raise ValueError('Invalid repeated row count.')
            if not any(values):
                continue
            if len(grid) + count > 10001:
                raise ValueError('ODS has more than 10,000 inventory rows.')
            grid.extend([values[: ] for _ in range(count)])
        if not grid or grid[0] != HEADERS:
            raise ValueError('ODS column headers must be: ' + ', '.join(HEADERS))
        rows = []
        for values in grid[1:]:
            canonical = [''] * 6
            for index, value in zip(ORDER, values):
                canonical[index] = value
            rows.append(canonical)
        validate_rows(rows)
        metadata = {}
        if 'meta.xml' in archive.namelist():
            meta_root = parse_xml(archive.read('meta.xml'))
            for entry in meta_root.findall('office:meta/meta:user-defined', NS):
                metadata[entry.get(q('meta:name'))] = entry.text or ''
        return {'rows': rows, 'updated': float(metadata.get('invy.updated', path.stat().st_mtime if isinstance(path, Path) else 0)),
                'lease': json.loads(metadata.get('invy.lease', 'null')),
                'history': json.loads(metadata.get('invy.history', '[]')),
                'last_editor': json.loads(metadata.get('invy.last_editor', metadata.get('invy.audit', 'null')))}

def append_text(parent, value):
    for line in value.split('\n'):
        paragraph = element(parent, 'text:p')
        last = None
        for part in re.split(r'( +|\t)', line):
            if not part:
                continue
            if part.isspace() and part[0] == ' ':
                last = element(paragraph, 'text:s', {'text:c': len(part)})
            elif part == '\t':
                last = element(paragraph, 'text:tab')
            elif last is None:
                paragraph.text = (paragraph.text or '') + part
            else:
                last.tail = (last.tail or '') + part

def encode(state):
    validate_rows(state['rows'])
    root = ET.Element(q('office:document-content'), {q('office:version'): '1.3'})
    styles = element(root, 'office:automatic-styles')
    wrap = element(styles, 'style:style', {'style:name': 'Cell', 'style:family': 'table-cell'})
    element(wrap, 'style:table-cell-properties', {'fo:wrap-option': 'wrap', 'style:vertical-align': 'top'})
    header = element(styles, 'style:style', {'style:name': 'Header', 'style:family': 'table-cell'})
    element(header, 'style:table-cell-properties', {'fo:background-color': '#e7eee7', 'fo:wrap-option': 'wrap'})
    element(header, 'style:text-properties', {'fo:font-weight': 'bold'})
    for i, width in enumerate(['3.5cm', '4.5cm', '4.5cm', '4cm', '12cm', '4.5cm']):
        style = element(styles, 'style:style', {'style:name': 'Col' + str(i), 'style:family': 'table-column'})
        element(style, 'style:table-column-properties', {'style:column-width': width})
    table = element(element(element(root, 'office:body'), 'office:spreadsheet'), 'table:table', {'table:name': 'Inventory'})
    for i in range(6):
        element(table, 'table:table-column', {'table:style-name': 'Col' + str(i), 'table:default-cell-style-name': 'Cell'})
    header_rows = element(table, 'table:table-header-rows')
    for index, values in enumerate([HEADERS] + [[row[i] for i in ORDER] for row in state['rows']]):
        row = element(header_rows if index == 0 else table, 'table:table-row')
        for value in values:
            cell = element(row, 'table:table-cell', {'office:value-type': 'string', 'table:style-name': 'Header' if index == 0 else 'Cell'})
            append_text(cell, value)
    meta = ET.Element(q('office:document-meta'), {q('office:version'): '1.3'})
    meta_body = element(meta, 'office:meta')
    element(meta_body, 'meta:generator').text = 'Invy'
    for name in ['updated', 'lease', 'history', 'last_editor']:
        element(meta_body, 'meta:user-defined', {'meta:name': 'invy.' + name, 'meta:value-type': 'string'}).text = json.dumps(state.get(name), ensure_ascii=False)
    manifest = ET.Element(q('manifest:manifest'), {q('manifest:version'): '1.3'})
    element(manifest, 'manifest:file-entry', {'manifest:full-path': '/', 'manifest:media-type': MIME, 'manifest:version': '1.3'})
    for name in ['content.xml', 'meta.xml']:
        element(manifest, 'manifest:file-entry', {'manifest:full-path': name, 'manifest:media-type': 'text/xml'})
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as archive:
        for name, content in [('mimetype', MIME.encode()), ('content.xml', xml(root)), ('meta.xml', xml(meta)), ('META-INF/manifest.xml', xml(manifest))]:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED if name == 'mimetype' else zipfile.ZIP_DEFLATED
            archive.writestr(info, content)
    raw = stream.getvalue()
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        if sum(info.file_size for info in archive.infolist()) > 128_000_000:
            raise ValueError('ODS history would exceed the storage limit. Archive history before saving more changes.')
    return raw


def write(path, state):
    raw = encode(state)
    fd, temporary = tempfile.mkstemp(prefix='.invy-', suffix='.tmp', dir=path.parent)
    try:
        with os.fdopen(fd, 'w+b') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)

@contextmanager
def transaction(path, commit_changes=False):
    """Lock the parent directory inode, which survives atomic ODS replacements.

    The lock survives atomic replacement without a separate lock file.
    Separate opens serialize threads, processes and containers sharing the mount.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        state = read(path) if path.exists() else None
        previous = copy.deepcopy(state)
        yield state
        if state is not None and state != previous:
            needs_commit = commit_changes and previous is not None and state['rows'] != previous['rows']
            rollback = None
            try:
                if needs_commit:
                    rollback = path.with_name('.invy-rollback-' + secrets.token_hex(16))
                    # Keep the old inode, so a failed Git write can be rolled
                    # back by rename even when there is no space for a new copy.
                    os.link(path, rollback)
                write(path, state)
                if needs_commit:
                    ensure_committed(path, state)
            except Exception:
                if rollback is not None and rollback.exists():
                    os.replace(rollback, path)
                    os.fsync(descriptor)
                raise
            finally:
                if rollback is not None and rollback.exists():
                    rollback.unlink()
    finally:
        os.close(descriptor)

def initialize(path, rows):
    path = Path(path)
    with transaction(path) as current:
        if current is None:
            write(path, {'rows': rows, 'updated': time.time(), 'lease': None, 'history': []})

def snapshot(state):
    lease = state.get('lease')
    active = lease and lease['expires'] > time.time()
    return {'columns': COLUMNS, 'rows': state['rows'], 'revision': revision(state['rows']),
            'updated': state['updated'], 'locked': bool(active), 'expires': lease['expires'] if active else None}


def safe_username(value):
    name = re.sub(r'[\x00-\x1f\x7f<>]', '', str(value)).strip()[:120]
    if not name:
        raise ValueError('The identity provider did not supply a usable username.')
    return name


def ensure_committed(path, state):
    """Call only while holding the data directory lock.

    A canonical blob excludes lease churn and uses deterministic ZIP timestamps.
    The last saver is embedded in the ODS, allowing crash recovery attribution.
    """
    actor = state.get('last_editor') or {'username': 'system', 'email': 'system@invy.local'}
    username = safe_username(actor['username'])
    email = str(actor.get('email') or 'user@invy.local')
    if len(email) > 254 or not re.fullmatch(r'[^\x00-\x20\x7f<>@]+@[^\x00-\x20\x7f<>@]+', email):
        email = 'user@invy.local'
    identity = f'{username} <{email}>'.encode()
    if not (path.parent / '.git').exists():
        repo = Repo.init(str(path.parent), default_branch=b'main')
        (path.parent / '.git' / 'info' / 'exclude').write_text('*\n!inventory.ods\n')
    else:
        repo = Repo(str(path.parent))
    with repo:
        config = repo.get_config()
        config.set((b'user',), b'name', b'Invy history')
        config.set((b'user',), b'email', b'history@invy.local')
        config.write_to_path()
        clean = dict(state, lease=None)
        blob = Blob.from_string(encode(clean))
        tree = Tree()
        tree.add(path.name.encode(), 0o100644, blob.id)
        try:
            previous = repo.head()
        except KeyError:
            previous = None
        if previous:
            previous_tree = repo[repo[previous].tree]
            if previous_tree.id == tree.id:
                return
            previous_blob = repo[previous_tree[path.name.encode()][1]]
            if read(io.BytesIO(previous_blob.data)) == clean:
                return
        repo.object_store.add_object(blob)
        repo.object_store.add_object(tree)
        commit = Commit()
        commit.tree = tree.id
        commit.parents = [previous] if previous else []
        commit.author = commit.committer = identity
        commit.author_time = commit.commit_time = int(time.time())
        commit.author_timezone = commit.commit_timezone = 0
        commit.encoding = b'UTF-8'
        commit.message = username.encode() + b'\n'
        repo.object_store.add_object(commit)
        if not repo.refs.set_if_equals(b'HEAD', previous, commit.id):
            raise RuntimeError('Inventory Git history was modified concurrently.')
        try:
            porcelain.reset(repo, mode='mixed', treeish=commit.id)
        except Exception:
            if previous:
                repo.refs.set_if_equals(b'HEAD', commit.id, previous)
            else:
                repo.refs.remove_if_equals(b'HEAD', commit.id)
            raise
