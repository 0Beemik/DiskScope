#!/usr/bin/env python3
"""DiskScope: one app for disk usage, big files, file types, duplicates and cleanup.

Standard library only. Serves a local web UI on 127.0.0.1 and opens it in your browser.

    diskscope [path]          # scan path (default: the whole drive, /)
    sudo diskscope [path]     # also see root-owned folders (/timeshift, /var, ...)

https://github.com/0Beemik/DiskScope
"""
import hashlib
import heapq
import json
import os
import pwd
import secrets
import shutil
import stat
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

IS_ROOT = os.geteuid() == 0
if IS_ROOT and os.environ.get('SUDO_USER'):
    _pw = pwd.getpwnam(os.environ['SUDO_USER'])
elif IS_ROOT and os.environ.get('PKEXEC_UID'):
    _pw = pwd.getpwuid(int(os.environ['PKEXEC_UID']))
else:
    _pw = pwd.getpwuid(os.getuid())
USER_NAME, USER_UID, HOME = _pw.pw_name, _pw.pw_uid, _pw.pw_dir

VERSION = '0.1.0'
TOKEN = secrets.token_urlsafe(16)
TOP_N = 2000            # largest files kept
DUPE_MIN = 1 << 20      # duplicates: ignore files under 1 MiB
LOCK = threading.Lock()

EXT_CATS = {
    'model': '.safetensors .gguf .ggml .ckpt .pt .pth .onnx .h5 .tflite .pb .mlmodel .nemo'.split(),
    'video': '.mp4 .mkv .mov .avi .webm .m4v .wmv .flv .mts .3gp'.split(),
    'image': '.jpg .jpeg .png .gif .webp .heic .heif .bmp .tif .tiff .raw .dng .cr2 .nef .arw .psd'.split(),
    'audio': '.mp3 .flac .wav .ogg .m4a .aac .opus .wma'.split(),
    'archive': '.zip .tar .gz .tgz .xz .zst .bz2 .7z .rar .deb .rpm .appimage .whl .snap .jar'.split(),
    'diskimg': '.iso .img .qcow2 .vdi .vmdk .vhd .vhdx'.split(),
}
EXT_TO_CAT = {e: c for c, es in EXT_CATS.items() for e in es}
CAT_LABEL = {'model': 'AI models', 'video': 'Video', 'image': 'Images', 'audio': 'Audio',
             'archive': 'Archives & packages', 'diskimg': 'Disk images & VMs', 'other': 'Everything else'}

# Never trash/delete these (or anything inside the system prefixes).
PROTECTED = {'/', '/home', HOME, '/usr', '/etc', '/boot', '/bin', '/sbin', '/lib', '/lib32', '/lib64',
             '/var', '/opt', '/root', '/snap', '/timeshift', '/proc', '/sys', '/dev', '/run', '/tmp'}
SYSTEM_PREFIXES = ('/usr/', '/etc/', '/boot/', '/bin/', '/sbin/', '/lib/', '/lib32/', '/lib64/',
                   '/proc/', '/sys/', '/dev/', '/run/', '/var/lib/dpkg/', '/var/lib/apt/', '/timeshift/')


def ext_of(name):
    name = name.lower()
    i = name.rfind('.')
    return name[i:] if i > 0 else ''


def category(path, ext, size):
    c = EXT_TO_CAT.get(ext)
    if c:
        return c
    if ext == '.bin' and size >= 100 << 20:
        return 'model'
    if '/blobs/' in path and ('/models--' in path or 'huggingface' in path or 'ollama' in path):
        return 'model'
    return 'other'


def mount_info(path):
    p = os.path.realpath(path)
    while not os.path.ismount(p):
        p = os.path.dirname(p)
    dev = fstype = ''
    try:
        with open('/proc/self/mounts') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3 and parts[1] == p:
                    dev, fstype = parts[0], parts[2]
    except OSError:
        pass
    st = os.statvfs(p)
    fr = st.f_frsize
    return {'mount': p, 'device': dev, 'fstype': fstype, 'total': st.f_blocks * fr,
            'free': st.f_bavail * fr, 'reserved': (st.f_bfree - st.f_bavail) * fr,
            'used': (st.f_blocks - st.f_bfree) * fr}


def as_user(cmd):
    """When running as root, run GUI helpers (xdg-open, gio) as the real desktop user."""
    if not IS_ROOT or USER_UID == 0:
        return cmd
    env = ['env', f'DISPLAY={os.environ.get("DISPLAY", ":0")}', f'XDG_RUNTIME_DIR=/run/user/{USER_UID}',
           f'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{USER_UID}/bus']
    if os.environ.get('WAYLAND_DISPLAY'):
        env.append(f'WAYLAND_DISPLAY={os.environ["WAYLAND_DISPLAY"]}')
    return ['sudo', '-u', USER_NAME] + env + cmd


# ---------------------------------------------------------------- scanning

class Scan:
    def __init__(self, root):
        self.root = os.path.abspath(root)
        self.state = 'scanning'
        self.files = self.dirs = self.bytes = 0
        self.current = ''
        self.err_count = 0
        self.errors = []
        self.dir_size, self.dir_files = {}, {}
        self.top = []                      # min-heap of (size, path, mtime)
        self.types = {}                    # ext -> [count, bytes]
        self.cats = {}                     # category -> [count, bytes]
        self.by_size = {}                  # apparent size -> [path, ...]  (duplicate candidates)
        self.empty_dirs = []
        self.started, self.finished = time.time(), None
        self.disk = mount_info(self.root)

    def _err(self, path, e):
        self.err_count += 1
        if len(self.errors) < 200:
            self.errors.append(f'{path}: {e.strerror or e}')

    def run(self):
        try:
            self._walk()
            self.state = 'done'
        except Exception as e:  # keep the UI alive and show what happened
            self.state = 'error'
            self.errors.insert(0, f'scan failed: {e!r}')
        self.finished = time.time()

    def _walk(self):
        root_dev = os.lstat(self.root).st_dev
        seen_links = set()
        own, nfiles, order = {}, {}, []
        stack = [self.root]
        while stack:
            d = stack.pop()
            order.append(d)
            self.dirs += 1
            self.current = d
            size = count = 0
            empty = True
            try:
                it = os.scandir(d)
            except OSError as e:
                self._err(d, e)
                own[d] = nfiles[d] = 0
                continue
            with it:
                for e in it:
                    empty = False
                    try:
                        st = e.stat(follow_symlinks=False)
                    except OSError as ex:
                        self._err(e.path, ex)
                        continue
                    if stat.S_ISDIR(st.st_mode):
                        if st.st_dev == root_dev:    # stay on this filesystem
                            stack.append(e.path)
                        continue
                    if not stat.S_ISREG(st.st_mode):
                        continue
                    if st.st_nlink > 1:              # count hard links once
                        key = (st.st_dev, st.st_ino)
                        if key in seen_links:
                            continue
                        seen_links.add(key)
                    du = st.st_blocks * 512          # real space on disk
                    size += du
                    count += 1
                    ext = ext_of(e.name)
                    cat = category(e.path, ext, du)
                    t = self.types.setdefault(ext or '(none)', [0, 0])
                    t[0] += 1
                    t[1] += du
                    c = self.cats.setdefault(cat, [0, 0])
                    c[0] += 1
                    c[1] += du
                    item = (du, e.path, st.st_mtime)
                    if len(self.top) < TOP_N:
                        heapq.heappush(self.top, item)
                    elif du > self.top[0][0]:
                        heapq.heappushpop(self.top, item)
                    if st.st_size >= DUPE_MIN and not e.path.startswith(SYSTEM_PREFIXES):
                        self.by_size.setdefault(st.st_size, []).append(e.path)
            own[d], nfiles[d] = size, count
            self.files += count
            self.bytes += size
            if empty:
                self.empty_dirs.append(d)
        # order is a pre-order walk, so reversed() visits children before parents
        for d in reversed(order):
            if d != self.root:
                p = os.path.dirname(d)
                own[p] = own.get(p, 0) + own[d]
                nfiles[p] = nfiles.get(p, 0) + nfiles[d]
        self.dir_size, self.dir_files = own, nfiles
        self.current = ''

    def contains(self, path):
        return path == self.root or path.startswith(self.root.rstrip('/') + '/')

    def forget(self, path, size, nfiles, is_dir):
        """Update totals after something was removed so the UI stays truthful without a rescan."""
        with LOCK:
            if is_dir:
                pref = path + '/'
                for d in [d for d in self.dir_size if d == path or d.startswith(pref)]:
                    del self.dir_size[d]
                    self.dir_files.pop(d, None)
            p = os.path.dirname(path)
            while self.contains(p):
                if p in self.dir_size:
                    self.dir_size[p] -= size
                    self.dir_files[p] -= nfiles
                if p == self.root:
                    break
                p = os.path.dirname(p)
            pref = path + '/'
            self.top = [t for t in self.top if t[1] != path and not t[1].startswith(pref)]
            heapq.heapify(self.top)
            self.bytes -= size
            self.files -= nfiles
            if DUPES.groups:
                for g in DUPES.groups:
                    g['paths'] = [q for q in g['paths'] if q != path and not q.startswith(pref)]
                DUPES.groups = [g for g in DUPES.groups if len(g['paths']) > 1]
                for g in DUPES.groups:
                    g['wasted'] = g['size'] * (len(g['paths']) - 1)


class Dupes:
    def __init__(self):
        self.state = 'idle'
        self.done = self.total = 0
        self.groups = []

    def run(self, scan):
        self.state = 'running'
        self.groups = []
        cands = [(s, ps) for s, ps in scan.by_size.items() if len(ps) > 1]
        self.total = sum(s * len(ps) for s, ps in cands)
        self.done = 0
        groups = []
        for size, paths in cands:
            heads = {}
            for p in paths:
                h = self._hash(p, size, partial=True)
                if h:
                    heads.setdefault(h, []).append(p)
            for ps in heads.values():
                if len(ps) < 2:
                    self.done += size * len(ps)
                    continue
                full = {}
                for p in ps:
                    h = self._hash(p, size, partial=False)
                    if h:
                        full.setdefault(h, []).append(p)
                for same in full.values():
                    if len(same) > 1:
                        same.sort(key=lambda q: (not q.startswith(HOME + '/.cache/'), q))
                        groups.append({'size': size, 'paths': same, 'wasted': size * (len(same) - 1)})
            self.done = min(self.done, self.total)
        groups.sort(key=lambda g: -g['wasted'])
        self.groups = groups
        self.done = self.total
        self.state = 'done'

    def _hash(self, path, size, partial):
        h = hashlib.blake2b(digest_size=20)
        try:
            with open(path, 'rb') as f:
                if partial:
                    h.update(f.read(65536))
                    if size > 131072:
                        f.seek(-65536, 2)
                        h.update(f.read(65536))
                else:
                    while chunk := f.read(4 << 20):
                        h.update(chunk)
                        self.done += len(chunk)
        except OSError:
            return None
        return h.hexdigest()


SCAN = None
DUPES = Dupes()


def start_scan(path):
    global SCAN, DUPES
    path = os.path.abspath(os.path.expanduser(path))
    if not os.path.isdir(path):
        raise ValueError(f'not a folder: {path}')
    if SCAN and SCAN.state == 'scanning':
        raise ValueError('a scan is already running')
    SCAN = Scan(path)
    DUPES = Dupes()
    threading.Thread(target=SCAN.run, daemon=True).start()


# ---------------------------------------------------------------- cleanup spots

def spots():
    h = HOME
    return [
        dict(name='Trash', path=f'{h}/.local/share/Trash', how='empty', subdirs=['files', 'info'],
             note='Files you "Move to Trash" still use space until the Trash is emptied.'),
        dict(name='uv package cache', path=f'{h}/.cache/uv', how='empty',
             note='Python packages uv re-downloads when needed. Same as `uv cache clean`.'),
        dict(name='pip cache', path=f'{h}/.cache/pip', how='empty', note='Same as `pip cache purge`.'),
        dict(name='npm cache', path=f'{h}/.npm/_cacache', how='empty', note='Same as `npm cache clean --force`.'),
        dict(name='Gradle caches', path=f'{h}/.gradle/caches', how='empty',
             note='Android/Java builds re-download these (first build afterwards is slower).'),
        dict(name='Playwright browsers', path=f'{h}/.cache/ms-playwright', how='empty',
             note='Re-install with `npx playwright install` if a project needs them.'),
        dict(name='Thumbnail cache', path=f'{h}/.cache/thumbnails', how='empty', note='Regenerated automatically.'),
        dict(name='Hugging Face models', path=f'{h}/.cache/huggingface/hub', how='browse',
             note='Remove whole models--* folders, never single blobs. Or run `hf cache ls` / `hf cache rm`.'),
        dict(name='Ollama models', path=f'{h}/.ollama/models', how='cmd', cmd='ollama list   # then: ollama rm <name>',
             note='Remove models with Ollama itself so its index stays correct.'),
        dict(name='Ollama models (system install)', path='/usr/share/ollama/.ollama/models', how='cmd',
             cmd='ollama list   # then: ollama rm <name>',
             note='Remove models with Ollama itself so its index stays correct.'),
        dict(name='LM Studio models', path=f'{h}/.lmstudio/models', how='browse', note=''),
        dict(name='Android emulators', path=f'{h}/.android/avd', how='browse',
             note='Delete unused virtual devices from Android Studio > Device Manager.'),
        dict(name='Steam games', path=f'{h}/.local/share/Steam/steamapps', how='browse',
             note='Uninstall games from inside Steam.'),
        dict(name='Timeshift snapshots', path='/timeshift', how='cmd', cmd='sudo timeshift --list',
             note='System backups. Delete old ones in the Timeshift app or lower how many it keeps.'),
        dict(name='System logs (journal)', path='/var/log/journal', how='cmd',
             cmd='sudo journalctl --vacuum-size=200M', note='Shrinks old system logs to 200 MB.'),
        dict(name='apt package cache', path='/var/cache/apt', how='cmd', cmd='sudo apt clean',
             note='Downloaded .deb installers that are already installed.'),
        dict(name='Docker', path='/var/lib/docker', how='cmd', cmd='docker system df   # then: docker system prune',
             note='Images, containers and build cache.'),
        dict(name='Flatpak runtimes', path='/var/lib/flatpak', how='cmd', cmd='flatpak uninstall --unused',
             note='Removes runtimes no installed app uses.'),
        dict(name='Snap packages', path='/var/lib/snapd/snaps', how='cmd',
             cmd='sudo snap set system refresh.retain=2', note='Keep only 2 old revisions of each snap.'),
    ]


SPOT_SIZES = {}   # path -> (bytes, partial) for spots outside the scan


def spot_size(path):
    if SCAN and SCAN.state == 'done' and path in SCAN.dir_size:
        return SCAN.dir_size[path], not os.access(path, os.R_OK | os.X_OK), 'ok'
    if path in SPOT_SIZES:
        v = SPOT_SIZES[path]
        return (None, False, 'pending') if v is None else (v[0], v[1], 'ok')
    SPOT_SIZES[path] = None

    def work():
        try:
            r = subprocess.run(['du', '-sxB1', path], capture_output=True, text=True, timeout=600)
            SPOT_SIZES[path] = (int(r.stdout.split()[0]) if r.stdout else 0, r.returncode != 0)
        except Exception:
            SPOT_SIZES[path] = (0, True)
    threading.Thread(target=work, daemon=True).start()
    return None, False, 'pending'


# ---------------------------------------------------------------- actions

def check_target(path):
    path = os.path.abspath(path)
    if path in PROTECTED or path.startswith(SYSTEM_PREFIXES):
        raise ValueError(f'refusing to touch system path {path}')
    if not os.path.lexists(path):
        raise ValueError('no longer exists')
    return path


def measure(path):
    """(bytes, files) of a path, using scan data when available."""
    if os.path.isdir(path) and not os.path.islink(path):
        if SCAN and path in SCAN.dir_size:
            return SCAN.dir_size[path], SCAN.dir_files.get(path, 0), True
        total = n = 0
        for dp, _, fs in os.walk(path):
            for f in fs:
                try:
                    total += os.lstat(os.path.join(dp, f)).st_blocks * 512
                    n += 1
                except OSError:
                    pass
        return total, n, True
    st = os.lstat(path)
    return st.st_blocks * 512, (1 if stat.S_ISREG(st.st_mode) else 0), False


def remove(path, permanent):
    path = check_target(path)
    size, n, is_dir = measure(path)
    if permanent:
        if is_dir:
            shutil.rmtree(path)
        else:
            os.remove(path)
    else:
        cmd = ['gio', 'trash', '--', path]
        if IS_ROOT and path.startswith(HOME + '/'):
            cmd = as_user(cmd)
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if r.returncode:
            raise OSError(r.stderr.strip() or 'gio trash failed')
    if SCAN and SCAN.state == 'done' and SCAN.contains(path):
        SCAN.forget(path, size, n, is_dir)
    return size


def empty_spot(path):
    spot = next((s for s in spots() if s['path'] == path and s['how'] == 'empty'), None)
    if not spot:
        raise ValueError('not a known cache folder')
    targets = [os.path.join(path, s) for s in spot.get('subdirs', [])] or [path]
    freed = 0
    for t in targets:
        if not os.path.isdir(t):
            continue
        for e in os.scandir(t):
            try:
                size, n, is_dir = measure(e.path)
                if is_dir:
                    shutil.rmtree(e.path)
                else:
                    os.remove(e.path)
                freed += size
                if SCAN and SCAN.state == 'done' and SCAN.contains(e.path):
                    SCAN.forget(e.path, size, n, is_dir)
            except OSError:
                pass
    SPOT_SIZES.pop(path, None)
    return freed


def user_empty_dirs():
    """Empty folders under home, skipping hidden/app folders where empty dirs are often intentional."""
    if not SCAN or SCAN.state != 'done':
        return []
    out = []
    for d in SCAN.empty_dirs:
        if d.startswith(HOME + '/') and '/.' not in d[len(HOME):] and os.path.isdir(d):
            out.append(d)
    return out


# ---------------------------------------------------------------- API

def api_status():
    s = SCAN
    return {
        'scan': s.state if s else 'idle', 'root': s.root if s else None,
        'files': s.files if s else 0, 'dirs': s.dirs if s else 0, 'bytes': s.bytes if s else 0,
        'current': s.current if s else '', 'used': s.disk['used'] if s else 0,
        'elapsed': ((s.finished or time.time()) - s.started) if s else 0,
        'dupes': {'state': DUPES.state, 'done': DUPES.done, 'total': DUPES.total},
        'is_root': IS_ROOT, 'home': HOME,
    }


def need_scan():
    if not SCAN or SCAN.state != 'done':
        raise LookupError('scan not finished')
    return SCAN


def api_overview():
    s = need_scan()
    disk = mount_info(s.root)
    kids = api_ls(s.root)['entries'][:14]
    cats = sorted(({'cat': c, 'label': CAT_LABEL[c], 'count': v[0], 'bytes': v[1]} for c, v in s.cats.items()),
                  key=lambda x: -x['bytes'])
    return {'root': s.root, 'disk': disk, 'scanned': s.bytes, 'files': s.files, 'dirs': s.dirs,
            'elapsed': s.finished - s.started, 'err_count': s.err_count, 'errors': s.errors[:40],
            'children': kids, 'cats': cats, 'is_root': IS_ROOT}


def api_ls(path):
    s = need_scan()
    path = os.path.abspath(path)
    if not s.contains(path):
        raise ValueError('outside the scanned folder')
    entries = []
    try:
        with os.scandir(path) as it:
            for e in it:
                try:
                    st = e.stat(follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISDIR(st.st_mode):
                    size = s.dir_size.get(e.path)
                    entries.append({'name': e.name, 'path': e.path, 'dir': True, 'size': size or 0,
                                    'files': s.dir_files.get(e.path, 0), 'mtime': st.st_mtime,
                                    'unscanned': size is None, 'cat': 'dir'})
                elif stat.S_ISREG(st.st_mode):
                    du = st.st_blocks * 512
                    entries.append({'name': e.name, 'path': e.path, 'dir': False, 'size': du, 'files': 1,
                                    'mtime': st.st_mtime, 'cat': category(e.path, ext_of(e.name), du)})
    except OSError as e:
        raise ValueError(f'cannot read {path}: {e.strerror}')
    entries.sort(key=lambda x: -x['size'])
    return {'path': path, 'size': s.dir_size.get(path, 0), 'files': s.dir_files.get(path, 0), 'entries': entries}


def api_top(cat):
    s = need_scan()
    rows = sorted(s.top, reverse=True)
    out = []
    for size, path, mtime in rows:
        c = category(path, ext_of(os.path.basename(path)), size)
        if cat in ('all', c):
            out.append({'path': path, 'size': size, 'mtime': mtime, 'cat': c})
        if len(out) >= 500:
            break
    return {'files': out}


def api_types():
    s = need_scan()
    rows = sorted(({'ext': k, 'count': v[0], 'bytes': v[1], 'cat': EXT_TO_CAT.get(k, 'other')}
                   for k, v in s.types.items()), key=lambda x: -x['bytes'])
    return {'types': rows[:150], 'total': s.bytes}


def api_dupes():
    return {'state': DUPES.state, 'done': DUPES.done, 'total': DUPES.total,
            'groups': DUPES.groups[:400], 'wasted': sum(g['wasted'] for g in DUPES.groups),
            'count': len(DUPES.groups)}


def api_cleanup():
    out = []
    for sp in spots():
        if not os.path.exists(sp['path']):
            continue
        size, partial, status = spot_size(sp['path'])
        out.append({**sp, 'size': size, 'partial': partial, 'status': status,
                    'browsable': bool(SCAN and SCAN.state == 'done' and SCAN.contains(sp['path']))})
    out.sort(key=lambda x: -(x['size'] or 0))
    dirs = user_empty_dirs()
    root = SCAN.root if SCAN else '/'
    return {'spots': out, 'empty_dirs': dirs[:300], 'empty_count': len(dirs), 'disk': mount_info(root),
            'is_root': IS_ROOT}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype='application/json'):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _guard(self):
        if self.headers.get('X-Token') != TOKEN:
            self._send(403, {'error': 'bad token'})
            return False
        return True

    def _run(self, fn):
        try:
            self._send(200, fn())
        except LookupError as e:
            self._send(409, {'error': str(e)})
        except (ValueError, OSError) as e:
            self._send(400, {'error': str(e)})

    def _host_ok(self):
        port = self.server.server_address[1]
        if self.headers.get('Host') in (f'127.0.0.1:{port}', f'localhost:{port}'):
            return True
        self._send(403, {'error': 'bad host'})
        return False

    def do_GET(self):
        if not self._host_ok():
            return
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if u.path == '/':
            return self._send(200, PAGE.replace('__TOKEN__', TOKEN).replace('__SCRIPT__', os.path.abspath(__file__)).encode(), 'text/html; charset=utf-8')
        if not u.path.startswith('/api/') or not self._guard():
            return None if u.path.startswith('/api/') else self._send(404, {'error': 'not found'})
        routes = {
            '/api/status': api_status,
            '/api/overview': api_overview,
            '/api/ls': lambda: api_ls(q.get('path') or need_scan().root),
            '/api/top': lambda: api_top(q.get('cat', 'all')),
            '/api/types': api_types,
            '/api/dupes': api_dupes,
            '/api/cleanup': api_cleanup,
        }
        fn = routes.get(u.path)
        return self._run(fn) if fn else self._send(404, {'error': 'not found'})

    def do_POST(self):
        if not self._host_ok() or not self._guard():
            return
        n = int(self.headers.get('Content-Length') or 0)
        body = json.loads(self.rfile.read(n) or b'{}')
        p = urlparse(self.path).path

        def scan():
            start_scan(body.get('path') or '/')
            return {'ok': True}

        def dupes():
            s = need_scan()
            if DUPES.state == 'running':
                raise ValueError('already running')
            threading.Thread(target=DUPES.run, args=(s,), daemon=True).start()
            return {'ok': True}

        def trash():
            ok, failed, freed = [], [], 0
            for path in body.get('paths', []):
                try:
                    freed += remove(path, bool(body.get('permanent')))
                    ok.append(path)
                except (ValueError, OSError, subprocess.SubprocessError) as e:
                    failed.append({'path': path, 'error': str(e)})
            return {'ok': ok, 'failed': failed, 'freed': freed}

        def empty():
            return {'freed': empty_spot(body.get('path', ''))}

        def rmempty():
            n = 0
            for d in user_empty_dirs():
                try:
                    os.rmdir(d)
                    n += 1
                except OSError:
                    pass
            if SCAN:
                SCAN.empty_dirs = [d for d in SCAN.empty_dirs if os.path.isdir(d)]
            return {'removed': n}

        def open_():
            path = os.path.abspath(body.get('path', ''))
            target = path if os.path.isdir(path) else os.path.dirname(path)
            subprocess.Popen(as_user(['xdg-open', target]), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return {'ok': True}

        def quit_():
            threading.Timer(0.3, self.server.shutdown).start()
            return {'ok': True}

        routes = {'/api/scan': scan, '/api/dupes': dupes, '/api/trash': trash, '/api/empty': empty,
                  '/api/rmempty': rmempty, '/api/open': open_, '/api/quit': quit_}
        fn = routes.get(p)
        return self._run(fn) if fn else self._send(404, {'error': 'not found'})


PAGE = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DiskScope</title>
<style>
:root{--bg:#f4f6f8;--panel:#fff;--text:#1a1f26;--muted:#5d6876;--line:#e1e6eb;--accent:#2f6fde;--accent-ink:#fff;
--danger:#c63b35;--warn-bg:#fff4dc;--warn-ink:#7a5200;
--c-dir:#4b84d6;--c-model:#7c5cd6;--c-video:#d9622b;--c-image:#22998b;--c-audio:#c29a17;--c-archive:#8c6b3c;
--c-diskimg:#cf4777;--c-other:#7f8c99;--c-free:#bfe3c8;--c-reserved:#f0cf8f;--c-unread:#e7aaa6;--c-scanned:#4b84d6}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#12161b;--panel:#1b2128;--text:#e6ebf0;--muted:#97a3b0;
--line:#2c343d;--accent:#5b93ef;--accent-ink:#0d1117;--danger:#ef6b65;--warn-bg:#3a2e14;--warn-ink:#f3cf83;
--c-dir:#4f86d6;--c-model:#8f73e6;--c-video:#e07443;--c-image:#33ab9c;--c-audio:#cfa830;--c-archive:#a07f4e;
--c-diskimg:#de5d8b;--c-other:#6f7c89;--c-free:#2f6b44;--c-reserved:#8a6d2e;--c-unread:#8c3f3b;--c-scanned:#4f86d6}}
:root[data-theme="dark"]{--bg:#12161b;--panel:#1b2128;--text:#e6ebf0;--muted:#97a3b0;--line:#2c343d;--accent:#5b93ef;
--accent-ink:#0d1117;--danger:#ef6b65;--warn-bg:#3a2e14;--warn-ink:#f3cf83}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 system-ui,-apple-system,"Segoe UI",Ubuntu,sans-serif}
header{display:flex;gap:16px;align-items:center;flex-wrap:wrap;padding:14px 20px;background:var(--panel);border-bottom:1px solid var(--line)}
.brand{font-weight:700;font-size:17px;letter-spacing:.2px}
#scanform{display:flex;gap:8px;flex:1;min-width:260px;max-width:620px}
input[type=text]{flex:1;min-width:0;padding:7px 10px;border:1px solid var(--line);border-radius:7px;background:var(--bg);color:var(--text);font:inherit}
button{font:inherit;padding:7px 13px;border-radius:7px;border:1px solid var(--line);background:var(--panel);color:var(--text);cursor:pointer}
button:hover{border-color:var(--accent)}
button.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-ink)}
button.danger{color:var(--danger);border-color:color-mix(in srgb,var(--danger) 40%,var(--line))}
button.small{padding:3px 8px;font-size:12.5px}
button:disabled{opacity:.5;cursor:default}
.who{margin-left:auto;color:var(--muted);font-size:12.5px}
nav{display:flex;gap:2px;padding:0 20px;background:var(--panel);border-bottom:1px solid var(--line);overflow-x:auto}
nav button{border:0;border-bottom:2px solid transparent;border-radius:0;background:none;padding:10px 14px;color:var(--muted);white-space:nowrap}
nav button.on{color:var(--text);border-bottom-color:var(--accent);font-weight:600}
main{max-width:1200px;margin:0 auto;padding:20px}
section{display:none}section.on{display:block}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:16px}
h2{font-size:15px;margin:0 0 12px}
.muted{color:var(--muted)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:16px}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.tile .k{color:var(--muted);font-size:12px}.tile .v{font-size:20px;font-weight:650;margin-top:2px}
.stack{display:flex;height:26px;border-radius:6px;overflow:hidden;background:var(--line)}
.stack i{display:block;height:100%}
.legend{display:flex;flex-wrap:wrap;gap:6px 18px;margin-top:10px;font-size:13px}
.legend span::before{content:"";display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px;background:var(--sw)}
.note{background:var(--warn-bg);color:var(--warn-ink);border-radius:8px;padding:10px 12px;margin-top:12px;font-size:13px}
code{font-family:ui-monospace,"JetBrains Mono",Menlo,monospace;font-size:12.5px;background:var(--bg);padding:1px 5px;border-radius:4px}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:middle}
th{font-size:12px;color:var(--muted);font-weight:600}
td.num,th.num{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums}
td.path{word-break:break-all}
tr.clickable{cursor:pointer}tr.clickable:hover td{background:color-mix(in srgb,var(--accent) 7%,transparent)}
.bar{height:8px;border-radius:4px;background:var(--line);min-width:80px}
.bar i{display:block;height:100%;border-radius:4px;background:var(--c-dir)}
.dot{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:7px;vertical-align:middle}
.acts{white-space:nowrap;text-align:right}
.crumbs{display:flex;flex-wrap:wrap;gap:4px;align-items:center;margin-bottom:12px}
.crumbs a{color:var(--accent);cursor:pointer;text-decoration:none}
#treemap{position:relative;height:440px;border-radius:8px;overflow:hidden;background:var(--line);margin-bottom:14px}
.tm{position:absolute;overflow:hidden;color:#fff;font-size:12px;padding:4px 6px;line-height:1.25;
box-shadow:inset 0 0 0 1px var(--panel);text-shadow:0 1px 2px rgba(0,0,0,.45);cursor:default}
.tm.dir{cursor:pointer}.tm:hover{filter:brightness(1.12)}
.tm b{display:block;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.chips{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px}
.chips button.on{background:var(--accent);color:var(--accent-ink);border-color:var(--accent)}
.toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:12px}
.group{border:1px solid var(--line);border-radius:8px;padding:10px 12px;margin-bottom:10px}
.group .hd{display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-bottom:6px;font-weight:600}
.group label{display:flex;gap:8px;align-items:flex-start;padding:3px 0;word-break:break-all;font-size:13px}
.tag{display:inline-block;font-size:11px;padding:1px 6px;border-radius:9px;background:var(--warn-bg);color:var(--warn-ink);margin-left:6px;white-space:nowrap}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(270px,1fr));gap:12px}
.card{border:1px solid var(--line);border-radius:10px;padding:12px 14px;display:flex;flex-direction:column;gap:6px}
.card .sz{font-size:19px;font-weight:650}
.card .p{font-size:12px;color:var(--muted);word-break:break-all}
.card .n{font-size:13px;flex:1}
.progress{padding:10px 20px;background:var(--panel);border-bottom:1px solid var(--line);font-size:13px}
.progress .pbar{height:6px;background:var(--line);border-radius:3px;margin-top:6px;overflow:hidden}
.progress .pbar i{display:block;height:100%;background:var(--accent);width:0;transition:width .4s}
.hidden{display:none!important}
#toast{position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:var(--text);color:var(--bg);padding:9px 16px;border-radius:8px;font-size:13px;opacity:0;transition:opacity .25s;pointer-events:none;max-width:90vw}
#toast.on{opacity:1}
.empty{padding:30px;text-align:center;color:var(--muted)}
@media (max-width:640px){main{padding:12px 16px}header{padding:12px 16px}#treemap{height:300px}.hide-sm{display:none}}
</style></head><body>
<header>
  <div class="brand">DiskScope</div>
  <form id="scanform"><input type="text" id="scanpath" spellcheck="false"><button class="primary">Scan</button></form>
  <span class="who" id="who"></span>
  <button class="small" id="quit" title="Stop the DiskScope server">Quit</button>
</header>
<div class="progress hidden" id="progress"><div id="ptext"></div><div class="pbar"><i id="pfill"></i></div></div>
<nav id="tabs">
  <button data-tab="overview" class="on">Overview</button><button data-tab="browse">Browse</button>
  <button data-tab="largest">Largest files</button><button data-tab="types">File types</button>
  <button data-tab="dupes">Duplicates</button><button data-tab="cleanup">Cleanup</button>
</nav>
<main>
  <section id="overview" class="on"></section>
  <section id="browse"></section>
  <section id="largest"></section>
  <section id="types"></section>
  <section id="dupes"></section>
  <section id="cleanup"></section>
</main>
<div id="toast"></div>
<script>
const TOKEN='__TOKEN__';
const $=s=>document.querySelector(s);
const st={tab:'overview',cwd:null,root:null,cat:'all',loaded:false,status:null};
const CATS={dir:'Folder',model:'AI models',video:'Video',image:'Images',audio:'Audio',archive:'Archives & packages',diskimg:'Disk images & VMs',other:'Everything else'};

async function api(path,body){
  const r=await fetch(path,{method:body?'POST':'GET',headers:{'X-Token':TOKEN,'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});
  const j=await r.json().catch(()=>({error:r.statusText}));
  if(!r.ok) throw new Error(j.error||r.statusText);
  return j;
}
function fmt(b){if(b==null)return '…';const u=['B','KB','MB','GB','TB'];let i=0;while(Math.abs(b)>=1024&&i<4){b/=1024;i++}return (i?b.toFixed(b<10?2:b<100?1:0):b)+' '+u[i]}
const num=n=>Number(n).toLocaleString();
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const date=t=>new Date(t*1000).toLocaleDateString();
const col=c=>`var(--c-${c})`;
function toast(msg){const t=$('#toast');t.textContent=msg;t.classList.add('on');clearTimeout(t._h);t._h=setTimeout(()=>t.classList.remove('on'),3500)}
function rel(p){return st.root&&p.startsWith(st.root)&&st.root!=='/'?'…'+p.slice(st.root.length):p}

// ---------- status / scanning
async function poll(){
  let s;try{s=await api('/api/status')}catch(e){$('#ptext').textContent='DiskScope stopped.';return}
  st.status=s;
  $('#who').textContent=s.is_root?'running as admin (sees everything)':'running as you (some system folders hidden)';
  const prog=$('#progress');
  if(s.scan==='scanning'){
    prog.classList.remove('hidden');
    $('#ptext').innerHTML=`Scanning <b>${esc(s.root)}</b> — ${num(s.files)} files, ${fmt(s.bytes)} <span class="muted">· ${esc(s.current)}</span>`;
    $('#pfill').style.width=Math.min(100,s.bytes/Math.max(1,s.used)*100)+'%';
    setTimeout(poll,600);return;
  }
  if(s.dupes.state==='running'){
    prog.classList.remove('hidden');
    $('#ptext').textContent=`Checking duplicates — ${fmt(s.dupes.done)} of up to ${fmt(s.dupes.total)} read`;
    $('#pfill').style.width=(s.dupes.total?s.dupes.done/s.dupes.total*100:0)+'%';
    st.dupesRunning=true;setTimeout(poll,700);return;
  }
  prog.classList.add('hidden');
  if(st.dupesRunning){st.dupesRunning=false;if(st.tab==='dupes')load()}
  if(s.scan==='done'&&!st.loaded){st.loaded=true;st.root=s.root;st.cwd=s.root;$('#scanpath').value=s.root;load()}
  if(s.scan==='error'){$('#overview').innerHTML='<div class="panel">Scan failed. Try another folder.</div>'}
}
$('#scanform').onsubmit=async e=>{
  e.preventDefault();
  try{await api('/api/scan',{path:$('#scanpath').value.trim()||'/'});st.loaded=false;
    document.querySelectorAll('section').forEach(s=>s.innerHTML='<div class="empty">Scanning…</div>');poll()}
  catch(err){toast(err.message)}
};
$('#quit').onclick=async()=>{if(!confirm('Stop DiskScope?'))return;await api('/api/quit',{});document.body.innerHTML='<div class="empty">DiskScope has stopped. You can close this tab.</div>'};
$('#tabs').onclick=e=>{const b=e.target.closest('button');if(!b)return;
  document.querySelectorAll('#tabs button').forEach(x=>x.classList.toggle('on',x===b));
  document.querySelectorAll('section').forEach(x=>x.classList.toggle('on',x.id===b.dataset.tab));
  st.tab=b.dataset.tab;load()};
function go(tab){document.querySelector(`#tabs [data-tab="${tab}"]`).click()}

async function load(){
  if(!st.loaded)return;
  const el=$('#'+st.tab);
  try{await ({overview:loadOverview,browse:loadBrowse,largest:loadLargest,types:loadTypes,dupes:loadDupes,cleanup:loadCleanup})[st.tab](el)}
  catch(e){el.innerHTML=`<div class="panel">${esc(e.message)}</div>`}
}

// ---------- shared actions
async function removePaths(paths,permanent,label){
  if(!paths.length)return;
  const what=paths.length===1?paths[0]:paths.length+' items';
  const msg=permanent?`PERMANENTLY delete ${what}${label?' ('+label+')':''}?\n\nThis cannot be undone.`
    :`Move ${what}${label?' ('+label+')':''} to the Trash?\n\nSpace is freed when you empty the Trash (Cleanup tab).`;
  if(!confirm(msg))return;
  try{const r=await api('/api/trash',{paths,permanent});
    toast(`${permanent?'Deleted':'Trashed'} ${r.ok.length} item(s), ${fmt(r.freed)}`+(r.failed.length?` — ${r.failed.length} failed: ${r.failed[0].error}`:''));
    load()}catch(e){toast(e.message)}
}
document.addEventListener('click',async e=>{
  const b=e.target.closest('[data-act]');if(!b)return;
  e.stopPropagation();
  const p=b.dataset.path;
  if(b.dataset.act==='open')api('/api/open',{path:p}).catch(err=>toast(err.message));
  if(b.dataset.act==='trash')removePaths([p],false,b.dataset.size);
  if(b.dataset.act==='browse'){st.cwd=p;go('browse')}
});
const actBtns=(p,size,dir)=>`<button class="small" data-act="open" data-path="${esc(p)}" title="Open in file manager">Open</button>
 ${dir?`<button class="small" data-act="browse" data-path="${esc(p)}">Browse</button>`:''}
 <button class="small danger" data-act="trash" data-path="${esc(p)}" data-size="${fmt(size)}">Trash</button>`;

// ---------- overview
async function loadOverview(el){
  const o=await api('/api/overview');const d=o.disk;
  const isMount=o.root===d.mount;
  const hidden=Math.max(0,d.used-o.scanned);
  const hiddenLabel=isMount?(o.is_root?'Not seen by scan':'Unreadable without admin'):`Rest of drive (outside ${o.root})`;
  const segs=[['Scanned',o.scanned,'scanned'],[hiddenLabel,hidden,'unread'],['Reserved for root',d.reserved,'reserved'],['Free',d.free,'free']];
  const maxKid=Math.max(1,...o.children.map(c=>c.size));
  const maxCat=Math.max(1,...o.cats.map(c=>c.bytes));
  let notes='';
  if(isMount&&!o.is_root&&hidden>d.total*0.02)notes+=`<div class="note"><b>${fmt(hidden)}</b> is in folders you don't have permission to read (usually <code>/timeshift</code> backups, Docker, or system logs). To see it, quit and run: <code>sudo python3 __SCRIPT__ /</code> — or use the "DiskScope (admin)" launcher.</div>`;
  if(d.reserved>0)notes+=`<div class="note"><b>${fmt(d.reserved)}</b> is reserved by the filesystem so the system can still work when the disk fills up. It shows as neither used nor free.${d.fstype.startsWith('ext')?` On a desktop drive you can shrink it from 5% to 1% safely: <code>sudo tune2fs -m 1 ${esc(d.device)}</code>`:''}</div>`;
  if(o.err_count)notes+=`<details style="margin-top:10px"><summary class="muted">${num(o.err_count)} folders/files couldn't be read</summary><pre style="white-space:pre-wrap;font-size:12px">${esc(o.errors.join('\n'))}</pre></details>`;
  el.innerHTML=`
  <div class="tiles">
    <div class="tile"><div class="k">Drive size</div><div class="v">${fmt(d.total)}</div></div>
    <div class="tile"><div class="k">Used</div><div class="v">${fmt(d.used)}</div></div>
    <div class="tile"><div class="k">Free</div><div class="v">${fmt(d.free)}</div></div>
    <div class="tile"><div class="k">Files scanned</div><div class="v">${num(o.files)}</div></div>
    <div class="tile"><div class="k">Scan time</div><div class="v">${o.elapsed.toFixed(1)} s</div></div>
  </div>
  <div class="panel"><h2>Where the drive's space goes <span class="muted" style="font-weight:400">· ${esc(d.mount)} (${esc(d.device)})</span></h2>
    <div class="stack">${segs.map(s=>`<i style="width:${s[1]/d.total*100}%;background:${col(s[2])}" title="${esc(s[0])}: ${fmt(s[1])}"></i>`).join('')}</div>
    <div class="legend">${segs.map(s=>`<span style="--sw:${col(s[2])}">${esc(s[0])} <b>${fmt(s[1])}</b></span>`).join('')}</div>
    ${notes}
  </div>
  <div class="panel"><h2>Biggest folders in ${esc(o.root)}</h2><table>
    ${o.children.map(c=>`<tr class="clickable" data-go="${esc(c.path)}" data-dir="${c.dir?1:0}"><td><span class="dot" style="background:${col(c.dir?'dir':c.cat)}"></span>${esc(c.name)}${c.unscanned?' <span class="tag">other drive / not scanned</span>':''}</td>
    <td style="width:40%"><div class="bar"><i style="width:${c.size/maxKid*100}%"></i></div></td><td class="num">${fmt(c.size)}</td></tr>`).join('')}
  </table></div>
  <div class="panel"><h2>By kind of file</h2><table>
    ${o.cats.map(c=>`<tr class="clickable" data-cat="${c.cat}"><td><span class="dot" style="background:${col(c.cat)}"></span>${esc(c.label)}</td><td class="num hide-sm">${num(c.count)} files</td>
    <td style="width:40%"><div class="bar"><i style="width:${c.bytes/maxCat*100}%;background:${col(c.cat)}"></i></div></td><td class="num">${fmt(c.bytes)}</td></tr>`).join('')}
  </table></div>`;
  el.querySelectorAll('[data-go]').forEach(r=>r.onclick=()=>{if(r.dataset.dir==='1'){st.cwd=r.dataset.go;go('browse')}});
  el.querySelectorAll('[data-cat]').forEach(r=>r.onclick=()=>{st.cat=r.dataset.cat;go('largest')});
}

// ---------- browse (treemap + list)
function squarify(items,x,y,w,h,out){
  while(items.length){
    if(items.length===1||w<=0||h<=0){out.push(...items.map((it,i)=>i?{...it,x,y,w:0,h:0}:{...it,x,y,w,h}));return}
    const total=items.reduce((s,i)=>s+i.v,0),scale=w*h/total,short=Math.min(w,h);
    let row=[],sum=0,best=Infinity,i=0;
    while(i<items.length){
      const r=[...row,items[i]],s=sum+items[i].v,area=s*scale;
      let mx=0,mn=Infinity;for(const it of r){const a=it.v*scale;mx=Math.max(mx,a);mn=Math.min(mn,a)}
      const worst=Math.max(short*short*mx/(area*area),area*area/(short*short*mn));
      if(row.length&&worst>best)break;
      row=r;sum=s;best=worst;i++;
    }
    const area=sum*scale;
    if(w>=h){const rw=area/h;let yy=y;for(const it of row){const ih=it.v*scale/rw;out.push({...it,x,y:yy,w:rw,h:ih});yy+=ih}x+=rw;w-=rw}
    else{const rh=area/w;let xx=x;for(const it of row){const iw=it.v*scale/rh;out.push({...it,x:xx,y,w:iw,h:rh});xx+=iw}y+=rh;h-=rh}
    items=items.slice(i);
  }
}
async function loadBrowse(el){
  const r=await api('/api/ls?path='+encodeURIComponent(st.cwd));
  st.cwd=r.path;
  const parts=[];let p=r.path;
  while(true){parts.unshift(p);if(p===st.root||p==='/')break;p=p.replace(/\/[^/]+$/,'')||'/'}
  const crumbs=parts.map((q,i)=>`<a data-cd="${esc(q)}">${esc(i===0?q:q.split('/').pop())}</a>`).join(' <span class="muted">/</span> ');
  const ents=r.entries.filter(e=>e.size>0);
  el.innerHTML=`<div class="panel">
    <div class="crumbs">${crumbs} <span class="muted" style="margin-left:8px">${fmt(r.size)} · ${num(r.files)} files</span>
      <span style="margin-left:auto"><button class="small" data-act="open" data-path="${esc(r.path)}">Open folder</button></span></div>
    <div id="treemap"></div>
    <div class="legend" style="margin:-4px 0 12px">${Object.entries(CATS).map(([k,v])=>`<span style="--sw:${col(k)}">${v}</span>`).join('')}</div>
    ${r.entries.length?`<table><thead><tr><th>Name</th><th class="hide-sm" style="width:22%"></th><th class="num">Size</th><th class="num hide-sm">Files</th><th class="num hide-sm">Modified</th><th></th></tr></thead><tbody>
    ${r.entries.slice(0,400).map(e=>`<tr class="${e.dir?'clickable':''}" data-cd="${e.dir?esc(e.path):''}">
      <td class="path"><span class="dot" style="background:${col(e.dir?'dir':e.cat)}"></span>${esc(e.name)}${e.dir?'/':''}${e.unscanned?' <span class="tag">not scanned</span>':''}</td>
      <td class="hide-sm"><div class="bar"><i style="width:${r.size?e.size/r.size*100:0}%;background:${col(e.dir?'dir':e.cat)}"></i></div></td>
      <td class="num">${fmt(e.size)}</td><td class="num hide-sm">${e.dir?num(e.files):''}</td><td class="num hide-sm">${date(e.mtime)}</td>
      <td class="acts">${actBtns(e.path,e.size,false)}</td></tr>`).join('')}</tbody></table>`:'<div class="empty">Empty folder</div>'}
  </div>`;
  el.querySelectorAll('[data-cd]').forEach(a=>a.onclick=()=>{if(a.dataset.cd){st.cwd=a.dataset.cd;loadBrowse(el)}});
  // treemap
  const tm=$('#treemap'),W=tm.clientWidth,H=tm.clientHeight;
  let items=ents.slice(0,150).map(e=>({...e,v:e.size}));
  const rest=ents.slice(150).reduce((s,e)=>s+e.size,0);
  if(rest>0)items.push({name:`${ents.length-150} smaller items`,v:rest,cat:'other',other:true,size:rest});
  if(!items.length){tm.innerHTML='<div class="empty">Nothing to show</div>';return}
  const out=[];squarify(items,0,0,W,H,out);
  tm.innerHTML=out.filter(t=>t.w>=1&&t.h>=1).map(t=>`<div class="tm ${t.dir?'dir':''}" ${t.dir?`data-cd="${esc(t.path)}"`:''}
    style="left:${t.x}px;top:${t.y}px;width:${t.w}px;height:${t.h}px;background:${col(t.dir?'dir':t.cat)}"
    title="${esc(t.name)} — ${fmt(t.size)}">${t.w>60&&t.h>30?`<b>${esc(t.name)}</b>${fmt(t.size)}`:''}</div>`).join('');
  tm.querySelectorAll('[data-cd]').forEach(a=>a.onclick=()=>{st.cwd=a.dataset.cd;loadBrowse(el)});
}
addEventListener('resize',()=>{clearTimeout(st._rs);st._rs=setTimeout(()=>{if(st.tab==='browse')load()},250)});

// ---------- largest files
function selected(el){return [...el.querySelectorAll('input[data-p]:checked')].map(c=>c.dataset.p)}
async function loadLargest(el){
  const r=await api('/api/top?cat='+st.cat);
  const chips=['all','model','video','image','audio','archive','diskimg','other'];
  el.innerHTML=`<div class="panel">
    <div class="chips">${chips.map(c=>`<button class="${st.cat===c?'on':''}" data-c="${c}">${c==='all'?'All':CATS[c]}</button>`).join('')}</div>
    <div class="toolbar"><span class="muted" id="selinfo">Select files to remove them.</span>
      <button class="small" id="t-trash" disabled>Move to Trash</button><button class="small danger" id="t-del" disabled>Delete permanently</button></div>
    ${r.files.length?`<table><thead><tr><th style="width:24px"><input type="checkbox" id="all"></th><th>File</th><th class="num">Size</th><th class="num hide-sm">Modified</th><th></th></tr></thead><tbody>
    ${r.files.map(f=>`<tr><td><input type="checkbox" data-p="${esc(f.path)}" data-s="${f.size}"></td>
      <td class="path"><span class="dot" style="background:${col(f.cat)}"></span>${esc(rel(f.path))}</td>
      <td class="num">${fmt(f.size)}</td><td class="num hide-sm">${date(f.mtime)}</td>
      <td class="acts"><button class="small" data-act="open" data-path="${esc(f.path)}">Open</button></td></tr>`).join('')}</tbody></table>`
    :'<div class="empty">No large files of this kind.</div>'}</div>`;
  el.querySelectorAll('[data-c]').forEach(b=>b.onclick=()=>{st.cat=b.dataset.c;loadLargest(el)});
  const upd=()=>{const s=[...el.querySelectorAll('input[data-p]:checked')];const tot=s.reduce((a,c)=>a+ +c.dataset.s,0);
    $('#selinfo').textContent=s.length?`${s.length} selected · ${fmt(tot)}`:'Select files to remove them.';
    $('#t-trash').disabled=$('#t-del').disabled=!s.length};
  el.querySelectorAll('input[data-p]').forEach(c=>c.onchange=upd);
  const all=$('#all');if(all)all.onchange=()=>{el.querySelectorAll('input[data-p]').forEach(c=>c.checked=all.checked);upd()};
  $('#t-trash').onclick=()=>removePaths(selected(el),false);
  $('#t-del').onclick=()=>removePaths(selected(el),true);
}

// ---------- types
async function loadTypes(el){
  const r=await api('/api/types');const mx=Math.max(1,...r.types.map(t=>t.bytes));
  el.innerHTML=`<div class="panel"><h2>Space by file extension</h2><table><thead><tr><th>Extension</th><th class="num">Files</th><th class="hide-sm" style="width:40%"></th><th class="num">Size</th><th class="num">Share</th></tr></thead><tbody>
  ${r.types.map(t=>`<tr><td><span class="dot" style="background:${col(t.cat)}"></span>${esc(t.ext)}</td><td class="num">${num(t.count)}</td>
  <td class="hide-sm"><div class="bar"><i style="width:${t.bytes/mx*100}%;background:${col(t.cat)}"></i></div></td>
  <td class="num">${fmt(t.bytes)}</td><td class="num">${(t.bytes/Math.max(1,r.total)*100).toFixed(1)}%</td></tr>`).join('')}</tbody></table></div>`;
}

// ---------- duplicates
async function loadDupes(el){
  const r=await api('/api/dupes');
  if(r.state==='idle'){el.innerHTML=`<div class="panel"><h2>Duplicate files</h2><p class="muted">Finds files over 1 MB with identical contents (compares size, then a quick fingerprint, then a full checksum). Reading big model files takes a little while.</p>
    <button class="primary" id="dstart">Find duplicates</button></div>`;
    $('#dstart').onclick=async()=>{try{await api('/api/dupes',{});el.innerHTML='<div class="empty">Checking…</div>';poll()}catch(e){toast(e.message)}};return}
  if(r.state==='running'){el.innerHTML='<div class="empty">Checking for duplicates… (progress at the top)</div>';return}
  const blob=p=>/\/blobs\/[0-9a-f]{20,}/.test(p);
  el.innerHTML=`<div class="panel"><h2>${num(r.count)} sets of duplicates · ${fmt(r.wasted)} could be freed</h2>
    <div class="toolbar"><button class="small" id="d-pick">Select all extra copies (keep first in each set)</button>
      <span class="muted" id="dsel"></span><button class="small" id="d-trash" disabled>Move to Trash</button><button class="small danger" id="d-del" disabled>Delete permanently</button>
      <button class="small" id="d-re" style="margin-left:auto">Re-check</button></div>
    ${r.groups.some(g=>g.paths.some(blob))?`<div class="note" style="margin-bottom:12px">Items tagged <b>model cache blob</b> live inside a Hugging Face–style cache (<code>…/blobs/…</code>). Deleting one breaks that copy of the model; prefer deleting the whole other model folder, or keep the cache copy.</div>`:''}
    ${r.groups.map(g=>`<div class="group"><div class="hd"><span>${g.paths.length} copies × ${fmt(g.size)}</span><span class="muted">${fmt(g.wasted)} extra</span></div>
      ${g.paths.map(p=>`<label><input type="checkbox" data-p="${esc(p)}" data-s="${g.size}"><span>${esc(p)}${blob(p)?'<span class="tag">model cache blob</span>':''}</span>
      <button class="small" data-act="open" data-path="${esc(p)}" style="margin-left:auto">Open</button></label>`).join('')}</div>`).join('')||'<div class="empty">No duplicates found.</div>'}
  </div>`;
  const upd=()=>{const s=[...el.querySelectorAll('input[data-p]:checked')];
    $('#dsel').textContent=s.length?`${s.length} selected · ${fmt(s.reduce((a,c)=>a+ +c.dataset.s,0))}`:'';
    $('#d-trash').disabled=$('#d-del').disabled=!s.length};
  el.querySelectorAll('input[data-p]').forEach(c=>c.onchange=upd);
  $('#d-pick').onclick=()=>{el.querySelectorAll('.group').forEach(g=>g.querySelectorAll('input[data-p]').forEach((c,i)=>c.checked=i>0));upd()};
  $('#d-trash').onclick=()=>removePaths(selected(el),false);
  $('#d-del').onclick=()=>removePaths(selected(el),true);
  $('#d-re').onclick=async()=>{try{await api('/api/dupes',{});el.innerHTML='<div class="empty">Checking…</div>';poll()}catch(e){toast(e.message)}};
}

// ---------- cleanup
async function loadCleanup(el){
  const r=await api('/api/cleanup');const d=r.disk;
  const pending=r.spots.some(s=>s.status==='pending');
  el.innerHTML=`<div class="panel"><h2>Caches, model stores & system leftovers</h2>
    <p class="muted" style="margin-top:-6px">Known places that grow quietly. "Empty" only clears caches that are safe to re-download.</p>
    <div class="cards">${r.spots.map(s=>`<div class="card">
      <div style="display:flex;justify-content:space-between;gap:8px"><b>${esc(s.name)}</b><span class="sz">${s.status==='pending'?'<span class="muted" style="font-size:13px">measuring…</span>':fmt(s.size)+(s.partial?'<span class="tag" title="Some of it is unreadable without admin">≥</span>':'')}</span></div>
      <div class="p">${esc(s.path)}</div><div class="n">${esc(s.note)}</div>
      ${s.how==='cmd'?`<div><code>${esc(s.cmd)}</code></div>`:''}
      <div style="display:flex;gap:6px;flex-wrap:wrap">
        ${s.how==='empty'?`<button class="small danger" data-empty="${esc(s.path)}" data-name="${esc(s.name)}" ${s.size?'':'disabled'}>Empty</button>`:''}
        ${s.how==='cmd'?`<button class="small" data-copy="${esc(s.cmd)}">Copy command</button>`:''}
        ${s.browsable?`<button class="small" data-act="browse" data-path="${esc(s.path)}">Browse</button>`:''}
        <button class="small" data-act="open" data-path="${esc(s.path)}">Open</button>
      </div></div>`).join('')}</div></div>
  ${d.reserved>0&&d.fstype.startsWith('ext')?`<div class="panel"><h2>Reserved space · ${fmt(d.reserved)}</h2>
    <p>The ext4 filesystem keeps ${(d.reserved/d.total*100).toFixed(0)}% of the drive for the system. Lowering it to 1% on a desktop drive is safe and gives back about <b>${fmt(d.reserved-d.total*0.01)}</b>.</p>
    <code>sudo tune2fs -m 1 ${esc(d.device)}</code> <button class="small" data-copy="sudo tune2fs -m 1 ${esc(d.device)}">Copy</button></div>`:''}
  <div class="panel"><h2>Empty folders in your home · ${num(r.empty_count)}</h2>
    <p class="muted" style="margin-top:-6px">Hidden/app folders are skipped. These take almost no space; this is just tidying.</p>
    ${r.empty_count?`<button class="small danger" id="rmempty">Remove all ${num(r.empty_count)} empty folders</button>
    <details style="margin-top:8px"><summary class="muted">Show list</summary><pre style="white-space:pre-wrap;font-size:12px">${esc(r.empty_dirs.join('\n'))}</pre></details>`:'<div class="muted">None found.</div>'}
  </div>`;
  el.querySelectorAll('[data-copy]').forEach(b=>b.onclick=()=>navigator.clipboard.writeText(b.dataset.copy).then(()=>toast('Copied — paste it in a terminal'),()=>toast(b.dataset.copy)));
  el.querySelectorAll('[data-empty]').forEach(b=>b.onclick=async()=>{
    if(!confirm(`Empty "${b.dataset.name}"?\n\n${b.dataset.empty}\n\nThis permanently deletes its contents.`))return;
    try{const x=await api('/api/empty',{path:b.dataset.empty});toast(`Freed ${fmt(x.freed)}`);loadCleanup(el)}catch(e){toast(e.message)}});
  const rm=$('#rmempty');if(rm)rm.onclick=async()=>{if(!confirm('Remove all listed empty folders?'))return;
    const x=await api('/api/rmempty',{});toast(`Removed ${x.removed} folders`);loadCleanup(el)};
  if(pending)setTimeout(()=>{if(st.tab==='cleanup')loadCleanup(el)},2000);
}

poll();
</script></body></html>'''


def main():
    import argparse
    ap = argparse.ArgumentParser(prog='diskscope', description='See what is using your disk: folders, big files, '
                                 'file types, duplicates and caches, in a local web UI.')
    ap.add_argument('path', nargs='?', default='/', help='folder to scan (default: / , the whole drive)')
    ap.add_argument('--port', type=int, default=0, help='port to listen on (default: random)')
    ap.add_argument('--no-browser', action='store_true', help="don't open a browser, just print the URL")
    ap.add_argument('--version', action='version', version=f'DiskScope {VERSION}')
    args = ap.parse_args()
    try:
        start_scan(args.path)
    except ValueError as e:
        ap.error(str(e))
    srv = ThreadingHTTPServer(('127.0.0.1', args.port), Handler)
    url = f'http://127.0.0.1:{srv.server_address[1]}/'
    print(f'DiskScope {VERSION} running at {url}  (Ctrl+C or the Quit button to stop)', flush=True)
    if not args.no_browser and os.environ.get('DISKSCOPE_NO_BROWSER') != '1':
        if IS_ROOT:
            subprocess.Popen(as_user(['xdg-open', url]), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
