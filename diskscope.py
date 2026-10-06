#!/usr/bin/env python3
"""DiskScope: one app to see what's using your disk and clean it up.

Folders and treemap, largest and stale files, file types, AI models, duplicates (remove or merge with
hard links), similar photos/videos, developer junk, caches, Timeshift snapshots, change history,
undo, and low-space alerts. Standard library only; serves a local UI on 127.0.0.1.

    diskscope [path]          # scan path (default: the whole drive, /)
    sudo diskscope [path]     # also see root-owned folders (/timeshift, /var, ...)
    diskscope --check         # low-space check (used by the optional alert timer)

https://github.com/0Beemik/DiskScope
"""
import argparse
import concurrent.futures
import gzip
import hashlib
import heapq
import json
import os
import pwd
import re
import secrets
import shutil
import stat
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

VERSION = '0.3.0'
SCRIPT = os.path.abspath(__file__)

IS_ROOT = os.geteuid() == 0
if IS_ROOT and os.environ.get('SUDO_USER'):
    _pw = pwd.getpwnam(os.environ['SUDO_USER'])
elif IS_ROOT and os.environ.get('PKEXEC_UID'):
    _pw = pwd.getpwuid(int(os.environ['PKEXEC_UID']))
else:
    _pw = pwd.getpwuid(os.getuid())
USER_NAME, USER_UID, USER_GID, HOME = _pw.pw_name, _pw.pw_uid, _pw.pw_gid, _pw.pw_dir


def _xdg(var, default):
    # Under sudo/pkexec the environment belongs to root, so only trust XDG vars when running as the user.
    return (not IS_ROOT and os.environ.get(var)) or os.path.join(HOME, default)


CACHE_DIR = os.environ.get('DISKSCOPE_CACHE') or os.path.join(_xdg('XDG_CACHE_HOME', '.cache'), 'diskscope')
CONFIG_DIR = os.environ.get('DISKSCOPE_CONFIG') or os.path.join(_xdg('XDG_CONFIG_HOME', '.config'), 'diskscope')
UNIT_DIR = os.path.join(_xdg('XDG_CONFIG_HOME', '.config'), 'systemd', 'user')

TOKEN = secrets.token_urlsafe(16)
GB = 1 << 30
TOP_N = 2000              # largest files kept
DUPE_MIN = 1 << 20        # duplicates: ignore files under 1 MiB
MODEL_MIN = 50 << 20      # model files worth listing
STALE_MIN = 50 << 20      # "unused for a year" files worth listing
STALE_AGE = 365 * 86400
HIST_DIR_MIN = 10 << 20   # folders saved in scan history
HIST_FILE_MIN = 100 << 20
CHANGE_MIN = 50 << 20     # smallest change shown on the Changes tab
HIST_KEEP = 40
LOCK = threading.Lock()
ALOCK = threading.Lock()

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
             '/var', '/opt', '/root', '/snap', '/timeshift', '/proc', '/sys', '/dev', '/run', '/tmp',
             '/run/media', '/media', '/mnt'}
SYSTEM_PREFIXES = ('/usr/', '/etc/', '/boot/', '/bin/', '/sbin/', '/lib/', '/lib32/', '/lib64/',
                   '/proc/', '/sys/', '/dev/', '/var/lib/dpkg/', '/var/lib/apt/', '/timeshift/')
# Where people keep their own stuff (used for photos, dev junk and stale files).
NOT_USER_AREA = SYSTEM_PREFIXES + ('/var/', '/opt/', '/snap/', '/srv/', '/root/')

JUNK = {'node_modules': 'Node packages', '.venv': 'Python virtualenv', 'venv': 'Python virtualenv',
        'target': 'Rust build output', 'build': 'Build output', '.gradle': 'Gradle project cache',
        '.next': 'Next.js build', '.nuxt': 'Nuxt build', '.svelte-kit': 'SvelteKit build',
        '.parcel-cache': 'Parcel cache', '.turbo': 'Turborepo cache', '.angular': 'Angular cache',
        '.dart_tool': 'Dart tool cache', '.pytest_cache': 'pytest cache', '.mypy_cache': 'mypy cache',
        '.ruff_cache': 'Ruff cache', '.tox': 'tox environments'}
QUANT_RE = re.compile(r'(?i)(?<![a-z0-9])(i?q\d(?:_[a-z0-9]+)*|f16|fp16|bf16|fp8|fp4|f32|fp32|int8|int4|'
                      r'awq|gptq|exl2|mxfp4|nf4|\d+bit)(?![a-z0-9])')
MODELISH = re.compile(r'model|weight|ggml|checkpoint|lora|llm|whisper|diffusion|transformer|embedding')
CHROMES = ['google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser', 'brave-browser',
           'microsoft-edge', 'microsoft-edge-stable', 'vivaldi-stable']
FFMPEG = shutil.which('ffmpeg')
TS_ROOT = '/timeshift/snapshots'


# ---------------------------------------------------------------- helpers

def fmt(b):
    b = float(b)
    for u in ('B', 'KB', 'MB', 'GB', 'TB'):
        if abs(b) < 1024 or u == 'TB':
            return f'{int(b)} B' if u == 'B' else f'{b:.1f} {u}'
        b /= 1024


def ext_of(name):
    """'.so' for libfoo.so.1.2, '.gz' for a.tar.gz, '' for .bashrc or README."""
    parts = name.lower().rsplit('/', 1)[-1].split('.')[1:]
    if not parts or parts == [''] or name.rsplit('/', 1)[-1].startswith('.') and len(parts) == 1:
        return ''
    while len(parts) > 1 and parts[-1].isdigit():   # version suffixes: .so.1.2, .7z.001
        parts.pop()
    return '' if parts[-1].isdigit() else '.' + parts[-1]


def category(path, ext, size):
    c = EXT_TO_CAT.get(ext)
    if c:
        return c
    if ext == '.bin' and size >= 100 << 20 and MODELISH.search(path.lower()):
        return 'model'
    if '/blobs/' in path and ('/models--' in path or 'huggingface' in path or 'ollama' in path):
        return 'model'
    return 'other'


def open_noatime(path):
    """Open for reading without bumping the access time, so 'last used' stays truthful."""
    try:
        return os.fdopen(os.open(path, os.O_RDONLY | getattr(os, 'O_NOATIME', 0)), 'rb')
    except PermissionError:      # O_NOATIME is only allowed on files you own
        return open(path, 'rb')


class keep_atime:
    """Restore a file's access time after an external tool (ffmpeg) has read it."""
    def __init__(self, path):
        self.path = path
        try:
            self.st = os.stat(path)
        except OSError:
            self.st = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        if self.st:
            try:
                os.utime(self.path, ns=(self.st.st_atime_ns, self.st.st_mtime_ns))
            except OSError:
                pass


def is_system(path):
    return path.startswith(SYSTEM_PREFIXES) or (path.startswith('/run/') and not path.startswith('/run/media/'))


def quant_of(text):
    m = QUANT_RE.search(text)
    return m.group(1).upper() if m else ''


def chown_user(path):
    if IS_ROOT and USER_UID != 0:
        try:
            os.chown(path, USER_UID, USER_GID)
        except OSError:
            pass


def user_dir(path):
    """mkdir -p, owned by the desktop user even when running as root."""
    missing = []
    p = path
    while p and not os.path.isdir(p):
        missing.append(p)
        p = os.path.dirname(p)
    for d in reversed(missing):
        os.mkdir(d)
        chown_user(d)
    return path


def load_json(path, default):
    try:
        with (gzip.open(path, 'rt') if path.endswith('.gz') else open(path)) as f:
            return json.load(f)
    except (OSError, ValueError, EOFError):
        return default


def save_json(path, data):
    user_dir(os.path.dirname(path))
    tmp = path + '.tmp'
    with (gzip.open(tmp, 'wt') if path.endswith('.gz') else open(tmp, 'w')) as f:
        json.dump(data, f)
    os.replace(tmp, path)
    chown_user(path)


def settings():
    return {'alert_pct': 10, 'alert_drop_gb': 20, **load_json(os.path.join(CONFIG_DIR, 'settings.json'), {})}


def _unescape_mount(s):
    return re.sub(r'\\(\d{3})', lambda m: chr(int(m.group(1), 8)), s)


def mount_info(path):
    p = os.path.realpath(path)
    while not os.path.ismount(p):
        p = os.path.dirname(p)
    dev = fstype = ''
    try:
        with open('/proc/self/mounts') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3 and _unescape_mount(parts[1]) == p:
                    dev, fstype = parts[0], parts[2]
    except OSError:
        pass
    st = os.statvfs(p)
    fr = st.f_frsize
    return {'mount': p, 'device': dev, 'fstype': fstype, 'total': st.f_blocks * fr,
            'free': st.f_bavail * fr, 'reserved': (st.f_bfree - st.f_bavail) * fr,
            'used': (st.f_blocks - st.f_bfree) * fr}


REAL_FS = {'ext2', 'ext3', 'ext4', 'btrfs', 'xfs', 'vfat', 'exfat', 'ntfs', 'ntfs3', 'fuseblk', 'f2fs',
           'zfs', 'hfsplus', 'jfs', 'bcachefs'}


def list_mounts():
    labels = {}
    try:
        for name in os.listdir('/dev/disk/by-label'):
            labels[os.path.realpath('/dev/disk/by-label/' + name)] = _unescape_mount(name.replace('\\x20', ' '))
    except OSError:
        pass
    out, seen = [], set()
    try:
        with open('/proc/self/mounts') as f:
            lines = f.read().splitlines()
    except OSError:
        return [mount_info('/')]
    for line in lines:
        parts = line.split()
        if len(parts) < 3:
            continue
        dev, mnt, fs = parts[0], _unescape_mount(parts[1]), parts[2]
        if fs not in REAL_FS or dev in seen or mnt.startswith(('/snap/', '/boot', '/var/snap/')):
            continue
        seen.add(dev)
        try:
            info = mount_info(mnt)
        except OSError:
            continue
        if info['total'] < 256 << 20:
            continue
        label = labels.get(os.path.realpath(dev))
        name = os.path.basename(mnt)
        if not label and (not name or re.fullmatch(r'[0-9a-fA-F-]{8,}', name)):   # auto-mounted by UUID
            label = f'{fmt(info["total"]).replace(".0 ", " ")} drive ({os.path.basename(dev)})'
        info['label'] = 'System drive' if mnt == '/' else label or ('Home' if mnt == '/home' else name)
        out.append(info)
    return out


def as_user(cmd):
    """When running as root, run desktop helpers (browser, gio, systemctl --user) as the real user."""
    if not IS_ROOT or USER_UID == 0:
        return cmd
    env = ['env', f'HOME={HOME}', f'DISPLAY={os.environ.get("DISPLAY", ":0")}',
           f'XDG_RUNTIME_DIR=/run/user/{USER_UID}', f'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{USER_UID}/bus']
    for k in ('WAYLAND_DISPLAY', 'XAUTHORITY'):
        if os.environ.get(k):
            env.append(f'{k}={os.environ[k]}')
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
        self.top = []                      # min-heap (du, path, mtime, atime)
        self.stale = []                    # min-heap (du, path, last_used)
        self.types = {}                    # ext -> [count, bytes]
        self.cats = {}                     # category -> [count, bytes]
        self.by_size = {}                  # apparent size -> [path, ...]  (duplicate candidates)
        self.models = []                   # (path, du, size, atime, mtime)
        self.media = []                    # (path, size, mtime, kind)
        self.junk = []                     # (path, kind)
        self.ts_unique = {}                # timeshift snapshot -> bytes only it holds
        self.ts_prefix = {}                # path inside snapshots -> unique bytes across snapshots
        self.empty_dirs = []
        self.stale_data = False            # something changed outside the scan's knowledge
        self.started, self.finished = time.time(), None
        self.disk = mount_info(self.root)
        self.last = None
        self.cached = False                # opened from a saved scan instead of scanning

    def contains(self, path):
        return path == self.root or path.startswith(self.root.rstrip('/') + '/')

    def _err(self, path, e):
        self.err_count += 1
        if len(self.errors) < 200:
            self.errors.append(f'{path}: {e.strerror or e}')

    def run(self):
        try:
            self.last = last_scan_summary(self.root)
            self._walk()
            self.finished = time.time()
            self.disk = mount_info(self.root)
            for save in (save_history, save_scan):     # save before reporting done
                try:
                    save(self)
                except Exception as e:
                    print(f'could not save scan ({save.__name__}): {e!r}', file=sys.stderr)
            self.state = 'done'
        except Exception as e:  # keep the UI alive and show what happened
            self.state = 'error'
            self.errors.insert(0, f'scan failed: {e!r}')
        self.finished = self.finished or time.time()

    def load_saved(self):
        """Open the saved scan of this folder; fall back to scanning if it's missing or unreadable."""
        try:
            ok = restore_scan(self)
        except Exception as e:
            print(f'could not load saved scan: {e!r}', file=sys.stderr)
            ok = False
        if not ok:
            self.__init__(self.root)
            self.run()

    def _walk(self):
        root_dev = os.lstat(self.root).st_dev
        seen_links = set()
        own, nfiles, order = {}, {}, []
        stale_cut = time.time() - STALE_AGE
        stack = [(self.root, False)]
        while stack:
            d, in_junk = stack.pop()
            order.append(d)
            self.dirs += 1
            self.current = d
            user_area = d != '/' and not d.startswith(NOT_USER_AREA) and '/.' not in d
            ts_snap = ts_pref = None
            if d.startswith(TS_ROOT + '/'):
                parts = d.split('/')
                ts_snap = parts[3]
                ts_pref = '/' + '/'.join(parts[5:8])
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
                            junk = in_junk
                            if not in_junk and user_area and e.name in JUNK and junk_ok(d, e.name, e.path):
                                self.junk.append((e.path, JUNK[e.name]))
                                junk = True
                            stack.append((e.path, junk))
                        continue
                    if not stat.S_ISREG(st.st_mode):
                        continue
                    du = st.st_blocks * 512          # real space on disk
                    if ts_snap is not None and st.st_nlink == 1:
                        self.ts_unique[ts_snap] = self.ts_unique.get(ts_snap, 0) + du
                        self.ts_prefix[ts_pref] = self.ts_prefix.get(ts_pref, 0) + du
                    if st.st_nlink > 1:              # count hard links once
                        key = (st.st_dev, st.st_ino)
                        if key in seen_links:
                            continue
                        seen_links.add(key)
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
                    item = (du, e.path, st.st_mtime, st.st_atime)
                    if len(self.top) < TOP_N:
                        heapq.heappush(self.top, item)
                    elif du > self.top[0][0]:
                        heapq.heappushpop(self.top, item)
                    if st.st_size >= DUPE_MIN and not is_system(e.path):
                        self.by_size.setdefault(st.st_size, []).append(e.path)
                    if cat == 'model' and st.st_size >= MODEL_MIN and ts_snap is None:
                        self.models.append((e.path, du, st.st_size, st.st_atime, st.st_mtime))
                    if user_area:
                        used = max(st.st_atime, st.st_mtime)
                        if used < stale_cut and du >= STALE_MIN:
                            s_item = (du, e.path, used)
                            if len(self.stale) < 1000:
                                heapq.heappush(self.stale, s_item)
                            elif du > self.stale[0][0]:
                                heapq.heappushpop(self.stale, s_item)
                        if (cat == 'image' and st.st_size >= 30 << 10) or (cat == 'video' and st.st_size >= 500 << 10):
                            self.media.append((e.path, st.st_size, st.st_mtime, cat))
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

    def forget(self, path, size, nfiles, is_dir):
        """Update totals after something was removed so the UI stays truthful without a rescan."""
        pref = path + '/'
        gone = lambda q: q == path or q.startswith(pref)  # noqa: E731
        with LOCK:
            if is_dir:
                for d in [d for d in self.dir_size if gone(d)]:
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
            self.top = [t for t in self.top if not gone(t[1])]
            heapq.heapify(self.top)
            self.stale = [t for t in self.stale if not gone(t[1])]
            heapq.heapify(self.stale)
            self.models = [m for m in self.models if not gone(m[0])]
            self.media = [m for m in self.media if not gone(m[0])]
            self.junk = [j for j in self.junk if not gone(j[0])]
            self.empty_dirs = [d for d in self.empty_dirs if not gone(d)]
            self.bytes -= size
            self.files -= nfiles
            for job in (DUPES, SIMILAR):
                job.forget(gone)
        persist_later()


def junk_ok(parent, name, path):
    if name == 'target':
        return os.path.exists(parent + '/Cargo.toml')
    if name == 'build':
        return any(os.path.exists(f'{parent}/{f}') for f in ('build.gradle', 'build.gradle.kts', 'CMakeLists.txt'))
    if name == '.gradle':
        return any(os.path.exists(f'{parent}/{f}') for f in
                   ('build.gradle', 'build.gradle.kts', 'settings.gradle', 'settings.gradle.kts'))
    if name in ('venv', '.venv'):
        return os.path.exists(path + '/pyvenv.cfg')
    return True


# ---------------------------------------------------------------- scan history ("what changed")

def hist_dir(root):
    return os.path.join(CACHE_DIR, 'history', 'root' if root == '/' else root.strip('/').replace('/', '_'))


def list_history(root):
    d = hist_dir(root)
    try:
        names = [n for n in os.listdir(d) if n.endswith('.json.gz')]
    except OSError:
        return []
    out = []
    for n in names:
        try:
            out.append({'time': int(n.split('.')[0]), 'file': os.path.join(d, n)})
        except ValueError:
            pass
    return sorted(out, key=lambda h: -h['time'])


def save_history(scan):
    data = {'v': 1, 'root': scan.root, 'time': int(scan.finished), 'disk': scan.disk, 'scanned': scan.bytes,
            'files': scan.files, 'dirs': {p: s for p, s in scan.dir_size.items() if s >= HIST_DIR_MIN},
            'top': {t[1]: t[0] for t in scan.top if t[0] >= HIST_FILE_MIN}}
    save_json(os.path.join(hist_dir(scan.root), f'{data["time"]}.json.gz'), data)
    for old in list_history(scan.root)[HIST_KEEP:]:
        try:
            os.remove(old['file'])
        except OSError:
            pass


def last_scan_summary(root, hist=None):
    for h in (list_history(root) if hist is None else hist):
        d = load_json(h['file'], None)
        if d:
            return {'time': d['time'], 'scanned': d['scanned'], 'used': d['disk']['used']}
    return None


def api_changes(vs=None):
    s = need_scan()
    hist = [h for h in list_history(s.root) if h['time'] != int(s.finished)]
    if not hist:
        return {'first': True}
    pick = next((h for h in hist if str(h['time']) == str(vs)), hist[0])
    prev = load_json(pick['file'], None)
    if not prev:
        raise ValueError('could not read that saved scan')
    cur, pd = s.dir_size, prev['dirs']
    cands = {}
    for p, sz in cur.items():
        if sz >= HIST_DIR_MIN or p in pd:
            delta = sz - pd.get(p, 0)
            if abs(delta) >= CHANGE_MIN:
                cands[p] = delta
    for p, sz in pd.items():
        if p not in cur and sz >= CHANGE_MIN:
            cands[p] = -sz
    # Hide a folder when one of its sub-folders explains (>=80% of) the same change.
    best_child = {}
    for p, dl in cands.items():
        par = os.path.dirname(p)
        if p != s.root and par in cands and (dl > 0) == (cands[par] > 0):
            best_child[par] = max(best_child.get(par, 0), abs(dl))
    rows = [{'path': p, 'delta': dl, 'now': cur.get(p, 0), 'before': pd.get(p, 0),
             'state': 'new' if p not in pd else 'gone' if p not in cur else ''}
            for p, dl in cands.items() if best_child.get(p, 0) < 0.8 * abs(dl)]
    rows.sort(key=lambda r: -abs(r['delta']))
    cur_top = {t[1]: t[0] for t in s.top if t[0] >= HIST_FILE_MIN}
    new_files = sorted(({'path': p, 'size': sz} for p, sz in cur_top.items() if p not in prev['top']),
                       key=lambda r: -r['size'])
    gone_files = sorted(({'path': p, 'size': sz} for p, sz in prev['top'].items()
                         if p not in cur_top and not os.path.exists(p)), key=lambda r: -r['size'])
    return {'first': False, 'vs': pick['time'], 'history': [{'time': h['time']} for h in hist],
            'summary': {'time': prev['time'], 'used_delta': s.disk['used'] - prev['disk']['used'],
                        'scanned_delta': s.bytes - prev['scanned'], 'free': s.disk['free']},
            'dirs': rows[:80], 'new_files': new_files[:40], 'gone_files': gone_files[:40]}


# ---------------------------------------------------------------- saved scans (open instantly)

SCAN_FORMAT = 1
_SAVED_FIELDS = ('files', 'dirs', 'bytes', 'err_count', 'errors', 'types', 'cats', 'ts_unique', 'ts_prefix',
                 'empty_dirs', 'started', 'finished', 'disk', 'stale_data')
_persist = {'timer': None}


def scan_file(root):
    key = 'root' if root == '/' else root.strip('/').replace('/', '_')
    return os.path.join(CACHE_DIR, 'scans', key + '.json.gz')


def saved_scan_info(root):
    """Small summary of a saved scan, without loading it."""
    d = load_json(scan_file(root)[:-len('.json.gz')] + '.meta.json', None)
    return d if d and d.get('v') == SCAN_FORMAT and d.get('root') == root else None


def save_scan(scan):
    with LOCK:
        data = {'v': SCAN_FORMAT, 'root': scan.root,
                'dir_map': {p: [sz, scan.dir_files.get(p, 0)] for p, sz in scan.dir_size.items()},
                'top': list(scan.top), 'stale': list(scan.stale), 'models': list(scan.models),
                'media': list(scan.media), 'junk': list(scan.junk),
                'by_size': {str(k): v for k, v in scan.by_size.items() if len(v) > 1},
                **{f: getattr(scan, f) for f in _SAVED_FIELDS}}
        if DUPES.state == 'done':
            data['dupes'] = {'groups': DUPES.groups, 'total': DUPES.total}
        if SIMILAR.state == 'done':
            data['similar'] = {'groups': SIMILAR.groups, 'total': SIMILAR.total}
    path = scan_file(scan.root)
    user_dir(os.path.dirname(path))
    tmp = path + '.tmp'
    with gzip.open(tmp, 'wt', compresslevel=1) as f:
        json.dump(data, f, separators=(',', ':'))
    os.chmod(tmp, 0o600)             # file names are private
    os.replace(tmp, path)
    chown_user(path)
    save_json(path[:-len('.json.gz')] + '.meta.json',
              {'v': SCAN_FORMAT, 'root': scan.root, 'time': scan.finished, 'bytes': scan.bytes, 'files': scan.files})


def restore_scan(scan):
    d = load_json(scan_file(scan.root), None)
    if not d or d.get('v') != SCAN_FORMAT or d.get('root') != scan.root:
        return False
    for f in _SAVED_FIELDS:
        setattr(scan, f, d[f])
    scan.dir_size = {p: v[0] for p, v in d['dir_map'].items()}
    scan.dir_files = {p: v[1] for p, v in d['dir_map'].items()}
    scan.top = [tuple(t) for t in d['top']]
    scan.stale = [tuple(t) for t in d['stale']]
    heapq.heapify(scan.top)
    heapq.heapify(scan.stale)
    scan.models = [tuple(t) for t in d['models']]
    scan.media = [tuple(t) for t in d['media']]
    scan.junk = [tuple(t) for t in d['junk']]
    scan.by_size = {int(k): v for k, v in d['by_size'].items()}
    earlier = [h for h in list_history(scan.root) if h['time'] < int(scan.finished)]
    scan.last = last_scan_summary(scan.root, earlier)
    if d.get('dupes'):
        DUPES.groups, DUPES.total, DUPES.done, DUPES.state = d['dupes']['groups'], d['dupes']['total'], d['dupes']['total'], 'done'
    if d.get('similar'):
        SIMILAR.groups, SIMILAR.total, SIMILAR.done, SIMILAR.state = (d['similar']['groups'], d['similar']['total'],
                                                                       d['similar']['total'], 'done')
    scan.cached = True
    scan.current = ''
    scan.state = 'done'
    return True


def persist_later(delay=3):
    """Re-save the open scan shortly after a change (debounced), so reopening shows the current state."""
    if _persist['timer']:
        _persist['timer'].cancel()
    s = SCAN
    if not s or s.state != 'done':
        return

    def work():
        try:
            save_scan(s)
        except Exception as e:
            print(f'could not save scan: {e!r}', file=sys.stderr)
    _persist['timer'] = threading.Timer(delay, work)   # non-daemon: finishes even if DiskScope is quitting
    _persist['timer'].start()


# ---------------------------------------------------------------- duplicates

class Dupes:
    def __init__(self):
        self.state = 'idle'
        self.done = self.total = 0
        self.groups = []

    def forget(self, gone):
        if not self.groups:
            return
        for g in self.groups:
            g['paths'] = [q for q in g['paths'] if not gone(q)]
            g['wasted'] = g['size'] * (len(g['paths']) - 1)
        self.groups = [g for g in self.groups if len(g['paths']) > 1]

    def run(self, scan):
        self.state = 'running'
        self.groups = []
        cands = [(s, ps) for s, ps in scan.by_size.items() if len(ps) > 1]
        self.total = sum(s * len(ps) for s, ps in cands)
        self.done = 0
        groups = []
        for size, paths in cands:
            heads, meta = {}, {}
            for p in paths:
                h = self._hash(p, size, True, meta)
                if h:
                    heads.setdefault(h, []).append(p)
            for ps in heads.values():
                if len(ps) < 2:
                    self.done += size * len(ps)
                    continue
                full = {}
                for p in ps:
                    h = self._hash(p, size, False, meta)
                    if h:
                        full.setdefault(h, []).append(p)
                for same in full.values():
                    if len(same) > 1:
                        same.sort(key=lambda q: (not q.startswith(HOME + '/.cache/'), q))
                        groups.append({'size': size, 'paths': same, 'wasted': size * (len(same) - 1),
                                       'meta': {q: meta[q] for q in same},
                                       'samefs': len({meta[q][1] for q in same}) == 1})
        groups.sort(key=lambda g: -g['wasted'])
        self.groups = groups
        self.done = self.total
        self.state = 'done'
        persist_later(0)

    def _hash(self, path, size, partial, meta):
        h = hashlib.blake2b(digest_size=20)
        try:
            with open_noatime(path) as f:
                if partial:
                    st = os.fstat(f.fileno())
                    meta[path] = (st.st_mtime_ns, st.st_dev)
                    h.update(f.read(65536))
                    if size > 131072:
                        f.seek(-65536, 2)
                        h.update(f.read(65536))
                else:
                    while True:
                        chunk = f.read(4 << 20)
                        if not chunk:
                            break
                        h.update(chunk)
                        self.done += len(chunk)
        except OSError:
            return None
        return h.hexdigest()


def merge(keep, others):
    """Replace each duplicate with a hard link to `keep`: one copy on disk, every path keeps working."""
    g = next((g for g in DUPES.groups if keep in g['paths'] and all(o in g['paths'] for o in others)), None)
    if not g:
        raise ValueError('this set changed; run the duplicate check again')
    ks = os.stat(keep)
    if ks.st_size != g['size'] or ks.st_mtime_ns != g['meta'][keep][0]:
        raise ValueError(f'{keep} changed since it was checked')
    freed = 0
    for o in others:
        o = check_target(o)
        os_ = os.lstat(o)
        if not stat.S_ISREG(os_.st_mode) or os_.st_size != g['size'] or os_.st_mtime_ns != g['meta'][o][0]:
            raise ValueError(f'{o} changed since it was checked')
        if os_.st_dev != ks.st_dev:
            raise ValueError(f'{o} is on a different drive; hard links only work within one drive')
        if os_.st_ino == ks.st_ino:
            continue
        tmp = o + '.diskscope-tmp'
        os.link(keep, tmp)
        try:
            os.replace(tmp, o)
        except OSError:
            os.unlink(tmp)
            raise
        du = os_.st_blocks * 512
        freed += du
        log_activity('merge', o, du, keep=keep)
        if SCAN and SCAN.state == 'done' and SCAN.contains(o):
            SCAN.forget(o, du, 1, False)
        else:
            DUPES.forget(lambda q: q == o)
    return freed


def split(path):
    """Undo a merge: give `path` its own copy again."""
    path = check_target(path)
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink < 2:
        raise ValueError('this file is not hard-linked')
    tmp = path + '.diskscope-tmp'
    shutil.copy2(path, tmp)
    os.replace(tmp, path)
    log_activity('split', path, st.st_blocks * 512)
    if SCAN:
        SCAN.stale_data = True
        persist_later()


# ---------------------------------------------------------------- similar photos & videos

def dhash(path, kind):
    """64-bit difference hash of an image (or a frame 1s into a video), decoded by ffmpeg."""
    tries = [['-ss', '1'], []] if kind == 'video' else [[]]
    for pre in tries:
        try:
            with keep_atime(path):
                    r = subprocess.run([FFMPEG, '-v', 'error', '-nostdin', *pre, '-i', path, '-vf',
                                    'scale=9:8:flags=area,format=gray', '-frames:v', '1', '-f', 'rawvideo', '-'],
                                   capture_output=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            return None
        px = r.stdout
        if len(px) >= 72:
            v = 0
            for row in range(8):
                for c in range(8):
                    v = (v << 1) | (px[row * 9 + c] > px[row * 9 + c + 1])
            return v
    return None


class Similar:
    CHUNKS = [(0, 11), (11, 22), (22, 33), (33, 44), (44, 54), (54, 64)]   # 6 chunks: <=5 bit diffs share one
    MAX_DIST = 5

    def __init__(self):
        self.state = 'idle'
        self.done = self.total = 0
        self.groups = []

    def forget(self, gone):
        if not self.groups:
            return
        for g in self.groups:
            g['items'] = [it for it in g['items'] if not gone(it['path'])]
        self.groups = [g for g in self.groups if len(g['items']) > 1]

    def run(self, scan):
        self.state = 'running'
        items = list(scan.media)
        cache_file = os.path.join(CACHE_DIR, 'phash.json.gz')
        cache = load_json(cache_file, {})
        todo = [it for it in items if not (it[0] in cache and cache[it[0]][:2] == [it[1], it[2]])]
        self.total, self.done = len(items), len(items) - len(todo)
        workers = max(2, (os.cpu_count() or 4) // 2)
        with concurrent.futures.ThreadPoolExecutor(workers) as ex:
            for it, h in zip(todo, ex.map(lambda it: dhash(it[0], it[3]), todo)):
                cache[it[0]] = [it[1], it[2], h]
                self.done += 1
        keep = {it[0] for it in items}
        save_json(cache_file, {p: v for p, v in cache.items() if p in keep or not scan.contains(p)})
        # Skip near-blank images (almost all bits equal): they "match" everything.
        hashed = [(it, h) for it, h in ((it, (cache.get(it[0]) or [0, 0, None])[2]) for it in items)
                  if h is not None and 6 <= bin(h).count('1') <= 58]
        buckets = {}
        for i, (it, h) in enumerate(hashed):
            for ci, (a, b) in enumerate(self.CHUNKS):
                buckets.setdefault((it[3], ci, (h >> a) & ((1 << (b - a)) - 1)), []).append(i)
        nbrs = [set() for _ in hashed]
        for members in buckets.values():
            if len(members) < 2 or len(members) > 400:
                continue
            for x in range(len(members)):
                hx = hashed[members[x]][1]
                for y in range(x + 1, len(members)):
                    if bin(hx ^ hashed[members[y]][1]).count('1') <= self.MAX_DIST:
                        nbrs[members[x]].add(members[y])
                        nbrs[members[y]].add(members[x])
        # Greedy, no chaining: every member must be close to the set's largest file, not just to each other.
        taken, groups = set(), []
        for i in sorted(range(len(hashed)), key=lambda i: -hashed[i][0][1]):
            if i in taken:
                continue
            members = [i] + sorted((j for j in nbrs[i] if j not in taken), key=lambda j: -hashed[j][0][1])
            if len(members) < 2:
                continue
            taken.update(members)
            ms = [hashed[j][0] for j in members]
            groups.append({'kind': ms[0][3], 'total': sum(m[1] for m in ms),
                           'items': [{'path': m[0], 'size': m[1], 'mtime': m[2]} for m in ms]})
        groups.sort(key=lambda g: -g['total'])
        self.groups = groups
        self.state = 'done'
        persist_later(0)


def thumbnail(path):
    path = os.path.abspath(path)
    if not FFMPEG or not os.path.isfile(path):
        raise ValueError('no thumbnail')
    cat = EXT_TO_CAT.get(ext_of(path))
    if cat not in ('image', 'video'):
        raise ValueError('not a photo or video')
    for pre in ([['-ss', '1'], []] if cat == 'video' else [[]]):
        with keep_atime(path):
            r = subprocess.run([FFMPEG, '-v', 'error', '-nostdin', *pre, '-i', path, '-vf',
                                'scale=320:320:force_original_aspect_ratio=decrease', '-frames:v', '1',
                                '-f', 'image2pipe', '-vcodec', 'mjpeg', '-q:v', '6', '-'], capture_output=True, timeout=30)
        if r.stdout:
            return r.stdout
    raise ValueError('could not decode')


# ---------------------------------------------------------------- AI models

def model_tool(path):
    p = path.lower()
    for key, label in (('/huggingface/', 'Hugging Face cache'), ('/.ollama/', 'Ollama'), ('/.lmstudio/', 'LM Studio'),
                       ('/lm-studio/', 'LM Studio'), ('comfyui', 'ComfyUI'), ('/.cache/llama.cpp', 'llama.cpp cache'),
                       ('stable-diffusion-webui', 'SD WebUI'), ('/invokeai', 'InvokeAI'), ('/.unsloth', 'Unsloth'),
                       ('gpt4all', 'GPT4All'), ('/jan/', 'Jan'), ('koboldcpp', 'KoboldCpp'),
                       ('text-generation-webui', 'text-generation-webui'), ('/.cache/torch', 'PyTorch cache'),
                       ('/.cache/whisper', 'Whisper')):
        if key in p:
            return label
    rel = path[len(HOME) + 1:] if path.startswith(HOME + '/') else path.lstrip('/')
    parts = rel.split('/')
    if parts[0] == '.cache' and len(parts) > 2:
        return f'{parts[1]} cache'
    if parts[:2] == ['.local', 'share'] and len(parts) > 3:
        return parts[2]
    if parts[0] in ('Applications', 'apps', 'Apps', 'Projects', 'projects', 'src', 'code', 'git', 'opt') and len(parts) > 2:
        return parts[1]
    return parts[0] or '/'


def ollama_models(scan):
    roots = {os.path.join(HOME, '.ollama/models'), '/usr/share/ollama/.ollama/models', '/var/lib/ollama/.ollama/models'}
    for m in scan.models:
        i = m[0].find('/.ollama/models/blobs/')
        if i >= 0:
            roots.add(m[0][:i + len('/.ollama/models')])
    out, notes = [], []
    for root in sorted(roots):
        base = root.split('/.ollama')[0]
        if os.path.isdir(base) and not os.access(base, os.R_OK | os.X_OK):
            notes.append(f'Ollama models in {base} can only be read by an admin.')
            continue
        man = os.path.join(root, 'manifests')
        for dp, _, files in os.walk(man):
            for f in files:
                mp = os.path.join(dp, f)
                rel = os.path.relpath(mp, man).split(os.sep)
                if len(rel) != 4:
                    continue
                reg, ns, model, tag = rel
                name = f'{model}:{tag}' if ns == 'library' else f'{ns}/{model}:{tag}'
                if reg != 'registry.ollama.ai':
                    name = f'{reg}/{name}'
                j = load_json(mp, None)
                if not isinstance(j, dict):
                    continue
                layers = list(j.get('layers') or []) + ([j['config']] if j.get('config') else [])
                blobs = [os.path.join(root, 'blobs', l['digest'].replace(':', '-')) for l in layers if l.get('digest')]
                last = 0
                for b in blobs:
                    try:
                        st = os.stat(b)
                        last = max(last, st.st_atime, st.st_mtime)
                    except OSError:
                        pass
                out.append({'kind': 'ollama', 'name': name, 'path': root, 'size': sum(l.get('size', 0) for l in layers),
                            'tool': 'Ollama' if root.startswith(HOME) else 'Ollama (system)', 'role': '',
                            'fmt': 'gguf', 'quant': quant_of(tag), 'last_used': last, 'cmd': f'ollama rm {name}',
                            'files': [l['size'] for l in layers if l.get('size', 0) >= MODEL_MIN]})
    return out, notes


def api_models():
    s = need_scan()
    entries, hf = [], {}
    for path, du, size, atime, mtime in s.models:
        i = path.find('/models--')
        if i >= 0:
            j = path.find('/', i + 1)
            hf.setdefault(path[:j] if j > 0 else path, []).append((du, size, max(atime, mtime)))
        elif '/.ollama/models/blobs/' not in path:
            name = os.path.basename(path)
            entries.append({'kind': 'file', 'name': name, 'path': path, 'size': du, 'tool': model_tool(path),
                            'role': os.path.basename(os.path.dirname(path)), 'fmt': ext_of(name).lstrip('.') or 'bin',
                            'quant': quant_of(name), 'last_used': max(atime, mtime), 'files': [size]})
    for repo, fl in hf.items():
        names = []
        for _, _, fs in os.walk(os.path.join(repo, 'snapshots')):
            names += fs
        fmts = sorted({ext_of(n).lstrip('.') for n in names if EXT_TO_CAT.get(ext_of(n)) == 'model' or ext_of(n) == '.bin'})
        quants = sorted({quant_of(n) for n in names if quant_of(n)})
        entries.append({'kind': 'hf', 'name': '/'.join(os.path.basename(repo).split('--')[1:]), 'path': repo,
                        'size': s.dir_size.get(repo) or sum(f[0] for f in fl), 'tool': model_tool(repo),
                        'role': 'Hugging Face repo', 'fmt': ', '.join(fmts) or 'model', 'quant': ', '.join(quants[:3]),
                        'last_used': max(f[2] for f in fl), 'files': [f[1] for f in fl]})
    olm, notes = ollama_models(s)
    entries += olm
    by_size = {}
    for i, e in enumerate(entries):
        for sz in set(e['files']):
            by_size.setdefault(sz, set()).add(i)
    dupes = 0
    for i, e in enumerate(entries):
        others = set()
        for sz in set(e['files']):
            others |= by_size[sz]
        others.discard(i)
        e['also'] = [f"{entries[o]['tool']}" + (f" ({entries[o]['name']})" if entries[o]['name'] != e['name'] else '')
                     for o in sorted(others)]
        dupes += bool(others)
    for e in entries:
        del e['files']
    entries.sort(key=lambda e: -e['size'])
    tools = {}
    for e in entries:
        t = tools.setdefault(e['tool'], {'tool': e['tool'], 'size': 0, 'count': 0})
        t['size'] += e['size']
        t['count'] += 1
    return {'entries': entries, 'tools': sorted(tools.values(), key=lambda t: -t['size']),
            'total': sum(e['size'] for e in entries), 'with_copies': dupes, 'notes': notes}


# ---------------------------------------------------------------- developer junk

def api_junk():
    s = need_scan()
    rows = []
    for path, kind in s.junk:
        size = s.dir_size.get(path, 0)
        if size < 1 << 20 or not os.path.isdir(path):
            continue
        proj = os.path.dirname(path)
        last = 0
        try:
            with os.scandir(proj) as it:
                for e in it:
                    if e.name not in JUNK:
                        last = max(last, e.stat(follow_symlinks=False).st_mtime)
            last = max(last, os.stat(proj + '/.git/index').st_mtime)
        except OSError:
            pass
        rows.append({'path': path, 'name': os.path.basename(path), 'kind': kind, 'size': size,
                     'project': proj, 'last': last})
    rows.sort(key=lambda r: -r['size'])
    return {'rows': rows, 'total': sum(r['size'] for r in rows)}


# ---------------------------------------------------------------- Timeshift

def api_timeshift():
    s = SCAN if SCAN and SCAN.state == 'done' else None
    conf = load_json('/etc/timeshift/timeshift.json', None) or {}
    try:
        names = sorted((n for n in os.listdir(TS_ROOT) if os.path.isdir(os.path.join(TS_ROOT, n))), reverse=True)
    except OSError:
        return {'available': False}
    readable = bool(IS_ROOT and s and s.contains(TS_ROOT))
    snaps = []
    for n in names:
        info = load_json(f'{TS_ROOT}/{n}/info.json', {})
        try:
            created = int(info.get('created') or 0) or int(time.mktime(time.strptime(n, '%Y-%m-%d_%H-%M-%S')))
        except ValueError:
            created = 0
        snaps.append({'name': n, 'created': created, 'tags': info.get('tags', ''), 'comments': info.get('comments', ''),
                      'unique': s.ts_unique.get(n, 0) if readable else None})
    excludes = [x.rstrip('*').rstrip('/') for x in conf.get('exclude', [])]
    prefixes = []
    if readable:
        for p, sz in sorted(s.ts_prefix.items(), key=lambda kv: -kv[1])[:12]:
            if sz < 50 << 20:
                break
            prefixes.append({'path': p, 'size': sz,
                             'excluded': any(p == x or p.startswith(x + '/') for x in excludes if x),
                             'candidate': any(k in p for k in ('ollama', 'docker', 'cache', '/var/log', '/var/tmp',
                                                                'flatpak', 'snapd', 'containers', 'libvirt', 'steam'))})
    sched = [f"{k.split('_')[1]} (keep {conf.get('count_' + k.split('_')[1], '?')})" for k in
             ('schedule_monthly', 'schedule_weekly', 'schedule_daily', 'schedule_hourly', 'schedule_boot')
             if conf.get(k) == 'true']
    total = s.dir_size.get('/timeshift') if s and readable else None
    return {'available': True, 'readable': readable, 'is_root': IS_ROOT, 'snaps': snaps, 'total': total,
            'schedule': sched, 'excludes': conf.get('exclude', []), 'prefixes': prefixes,
            'stale': bool(s and s.stale_data)}


def ts_delete(name):
    if not IS_ROOT:
        raise ValueError('deleting snapshots needs admin')
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}', name or '') or not os.path.isdir(f'{TS_ROOT}/{name}'):
        raise ValueError('unknown snapshot')
    unique = SCAN.ts_unique.get(name, 0) if SCAN else 0
    r = subprocess.run(['timeshift', '--delete', '--snapshot', name, '--scripted', '--yes'],
                       capture_output=True, text=True, timeout=3600)
    if r.returncode or os.path.isdir(f'{TS_ROOT}/{name}'):
        raise OSError((r.stderr or r.stdout).strip()[-400:] or 'timeshift failed')
    log_activity('ts-delete', f'{TS_ROOT}/{name}', unique)
    if SCAN:
        SCAN.stale_data = True
        SCAN.ts_unique.pop(name, None)
        persist_later()
    return unique


# ---------------------------------------------------------------- activity log & undo

ACTIVITY_FILE = os.path.join(CACHE_DIR, 'activity.json')


def log_activity(action, path, size, **extra):
    with ALOCK:
        data = load_json(ACTIVITY_FILE, [])
        data.append({'time': time.time(), 'action': action, 'path': path, 'size': size, **extra})
        save_json(ACTIVITY_FILE, data[-500:])


def trash_index():
    """original path -> (file in trash, .trashinfo, deletion date) for the user's trash cans."""
    cans = [(os.path.join(HOME, '.local/share/Trash'), '/')]
    for m in list_mounts():
        top = m['mount'].rstrip('/') or ''
        cans += [(f'{top}/.Trash-{USER_UID}', top or '/'), (f'{top}/.Trash/{USER_UID}', top or '/')]
    idx = {}
    for can, top in cans:
        try:
            it = os.scandir(os.path.join(can, 'info'))
        except OSError:
            continue
        with it:
            for e in it:
                if not e.name.endswith('.trashinfo'):
                    continue
                try:
                    with open(e.path) as f:
                        txt = f.read()
                except OSError:
                    continue
                pm = re.search(r'^Path=(.*)$', txt, re.M)
                dm = re.search(r'^DeletionDate=(.*)$', txt, re.M)
                if not pm:
                    continue
                orig = unquote(pm.group(1))
                if not orig.startswith('/'):
                    orig = os.path.join(top, orig)
                date = dm.group(1) if dm else ''
                if orig not in idx or date > idx[orig][2]:
                    idx[orig] = (os.path.join(can, 'files', e.name[:-len('.trashinfo')]), e.path, date)
    return idx


def restore(path):
    ent = trash_index().get(path)
    if not ent or not os.path.lexists(ent[0]):
        raise ValueError('not in the Trash any more (it may have been emptied)')
    if os.path.lexists(path):
        raise ValueError('something else now exists at that path')
    os.makedirs(os.path.dirname(path), exist_ok=True)
    shutil.move(ent[0], path)
    try:
        os.remove(ent[1])
    except OSError:
        pass
    log_activity('restore', path, 0)
    if SCAN:
        SCAN.stale_data = True
        persist_later()


def api_activity():
    data = load_json(ACTIVITY_FILE, [])
    idx = trash_index() if any(a['action'] == 'trash' for a in data) else {}
    out = []
    for a in reversed(data[-300:]):
        a = dict(a)
        a['restorable'] = a['action'] == 'trash' and a['path'] in idx and not os.path.lexists(a['path'])
        try:
            a['splittable'] = a['action'] == 'merge' and os.lstat(a['path']).st_nlink > 1
        except OSError:
            a['splittable'] = False
        out.append(a)
    return {'items': out, 'file': ACTIVITY_FILE}


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
        dict(name='Yarn cache', path=f'{h}/.cache/yarn', how='empty', note='Same as `yarn cache clean`.'),
        dict(name='pnpm store', path=f'{h}/.local/share/pnpm/store', how='cmd', cmd='pnpm store prune',
             note='Removes packages no project uses.'),
        dict(name='Cargo registry cache', path=f'{h}/.cargo/registry/cache', how='empty',
             note='Downloaded crate archives; re-fetched when needed.'),
        dict(name='Go module cache', path=f'{h}/go/pkg/mod', how='cmd', cmd='go clean -modcache',
             note='Downloaded Go modules.'),
        dict(name='Gradle caches', path=f'{h}/.gradle/caches', how='empty',
             note='Android/Java builds re-download these (first build afterwards is slower).'),
        dict(name='Playwright browsers', path=f'{h}/.cache/ms-playwright', how='empty',
             note='Re-install with `npx playwright install` if a project needs them.'),
        dict(name='Thumbnail cache', path=f'{h}/.cache/thumbnails', how='empty', note='Regenerated automatically.'),
        dict(name='Hugging Face models', path=f'{h}/.cache/huggingface/hub', how='browse',
             note='See the AI models tab. Remove whole models--* folders, never single blobs.'),
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
        dict(name='Timeshift snapshots', path='/timeshift', how='tab', tab='backups',
             note='System backups. See the Backups tab.'),
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

def locked(path):
    return path in PROTECTED or is_system(path)


def check_target(path):
    path = os.path.abspath(path)
    if locked(path):
        raise ValueError(f'refusing to touch system path {path}')
    if not os.path.lexists(path):
        raise ValueError(f'{path} no longer exists')
    return path


def measure(path):
    """(bytes, files, is_dir) of a path, using scan data when available."""
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
    log_activity('delete' if permanent else 'trash', path, size)
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
    log_activity('empty', path, freed)
    return freed


def user_empty_dirs():
    """Empty folders under home, skipping hidden/app folders where empty dirs are often intentional."""
    if not SCAN or SCAN.state != 'done':
        return []
    return [d for d in SCAN.empty_dirs
            if d.startswith(HOME + '/') and '/.' not in d[len(HOME):] and os.path.isdir(d)]


# ---------------------------------------------------------------- alerts

def notify(title, body, open_path='/'):
    if not shutil.which('notify-send'):
        print(f'{title}: {body}')
        return
    try:
        r = subprocess.run(['notify-send', '-a', 'DiskScope', '-i', 'diskscope', '-A', 'open=Open DiskScope',
                            title, body], capture_output=True, text=True, timeout=900)
    except subprocess.TimeoutExpired:
        return
    if r.stdout.strip() == 'open':
        subprocess.Popen([sys.executable, SCRIPT, open_path], start_new_session=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def check_alerts():
    cfg = settings()
    state_file = os.path.join(CACHE_DIR, 'alert-state.json')
    state = load_json(state_file, {})
    now = time.time()
    msgs, first = [], None
    for m in list_mounts():
        if m['total'] < GB:
            continue
        key, free = m['mount'], m['free']
        s = state.setdefault(key, {})
        pct = free / m['total'] * 100
        if pct < cfg['alert_pct'] and now - s.get('low_at', 0) > 86400:
            msgs.append(f"{m['label']} ({key}): only {fmt(free)} free ({pct:.0f}%).")
            s['low_at'] = now
            first = first or key
        base = s.get('base')
        if base and now - base['time'] < 26 * 3600 and base['free'] - free > cfg['alert_drop_gb'] * GB \
                and not s.get('drop_at'):
            msgs.append(f"{m['label']} ({key}): {fmt(base['free'] - free)} filled in the last "
                        f"{(now - base['time']) / 3600:.0f} h.")
            s['drop_at'] = now
            first = first or key
        if not base or now - base['time'] > 86400:
            s['base'] = {'time': now, 'free': free}
            s['drop_at'] = 0
    save_json(state_file, state)
    if msgs:
        notify('Disk space is running low' if len(msgs) == 1 and 'only' in msgs[0] else 'Disk space alert',
               '\n'.join(msgs), first or '/')
    return msgs


def alerts_enabled():
    try:
        r = subprocess.run(as_user(['systemctl', '--user', 'is-enabled', 'diskscope-check.timer']),
                           capture_output=True, text=True, timeout=10)
        return r.stdout.strip() == 'enabled'
    except (OSError, subprocess.TimeoutExpired):
        return False


def set_alerts(on):
    svc, tmr = os.path.join(UNIT_DIR, 'diskscope-check.service'), os.path.join(UNIT_DIR, 'diskscope-check.timer')
    run = lambda *a: subprocess.run(as_user(['systemctl', '--user', *a]), capture_output=True, text=True, timeout=30)  # noqa: E731
    if on:
        user_dir(UNIT_DIR)
        with open(svc, 'w') as f:
            f.write(f'[Unit]\nDescription=DiskScope low disk space check\n\n[Service]\nType=oneshot\n'
                    f'ExecStart={sys.executable} {SCRIPT} --check\nKillMode=process\nTimeoutStartSec=20min\n')
        with open(tmr, 'w') as f:
            f.write('[Unit]\nDescription=Check disk space every hour (DiskScope)\n\n[Timer]\nOnBootSec=10min\n'
                    'OnUnitActiveSec=1h\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n')
        chown_user(svc)
        chown_user(tmr)
        run('daemon-reload')
        r = run('enable', '--now', 'diskscope-check.timer')
        if r.returncode:
            raise OSError(r.stderr.strip() or 'systemctl failed')
    else:
        run('disable', '--now', 'diskscope-check.timer')
        for p in (svc, tmr):
            try:
                os.remove(p)
            except OSError:
                pass
        run('daemon-reload')


# ---------------------------------------------------------------- insights

def insights(s, disk):
    out = []

    def add(size, text, tab, **extra):
        out.append({'size': size, 'text': text, 'tab': tab, **extra})
    hidden = max(0, disk['used'] - s.bytes) if s.root == disk['mount'] else 0
    if not IS_ROOT and hidden > disk['total'] * 0.02:
        add(hidden, f'{fmt(hidden)} is in folders only an admin can read (backups, Docker, logs).', 'elevate')
    for sp in spots():
        if sp['how'] == 'empty' and s.contains(sp['path']):
            sz = s.dir_size.get(sp['path'], 0)
            if sz >= GB:
                add(sz, f"The Trash still holds {fmt(sz)}." if sp['name'] == 'Trash' else
                    f"{sp['name']}: {fmt(sz)}, safe to empty (re-downloaded when needed).", 'cleanup')
    if DUPES.state == 'done':
        w = sum(g['wasted'] for g in DUPES.groups)
        if w >= GB:
            add(w, f'{fmt(w)} is taken by extra copies of identical files. Merge them or remove them.', 'dupes')
    else:
        est = sum(sz * (len(ps) - 1) for sz, ps in s.by_size.items() if len(ps) > 1)
        if est >= GB:
            add(est, f'Up to {fmt(est)} may be duplicate files. Run the duplicate check to find out.', 'dupes')
    junk = sum(s.dir_size.get(p, 0) for p, _ in s.junk)
    if junk >= GB:
        add(junk, f'{fmt(junk)} in developer folders that rebuild themselves (node_modules, venvs, build output).', 'junk')
    stale = sum(t[0] for t in s.stale)
    if stale >= GB:
        add(stale, f'{fmt(stale)} in large files nobody has opened for over a year.', 'largest', cat='stale')
    ts = s.dir_size.get('/timeshift', 0)
    if ts >= 5 * GB:
        add(ts, f'Timeshift backups use {fmt(ts)}.', 'backups')
    models = sum(m[1] for m in s.models)
    if models >= 5 * GB:
        add(models, f'AI models take {fmt(models)}. See which apps hold which models, and any copies.', 'models')
    if disk['fstype'].startswith('ext') and disk['reserved'] > disk['total'] * 0.02 and s.root == disk['mount']:
        gain = int(disk['reserved'] - disk['total'] * 0.01)
        add(gain, f"The filesystem reserves {fmt(disk['reserved'])}. Lowering it to 1% gives back about {fmt(gain)}.",
            'cleanup')
    out.sort(key=lambda x: -x['size'])
    return out


# ---------------------------------------------------------------- API

SCAN = None
DUPES = Dupes()
SIMILAR = Similar()
ELEVATE = {'state': 'idle'}


class Life:
    last_ping = 0.0
    bye_at = 0.0
    keep = False


def start_scan(path, fresh=True):
    """Scan `path`, or with fresh=False open its saved scan when there is one."""
    global SCAN, DUPES, SIMILAR
    path = os.path.abspath(os.path.expanduser(path))
    if not os.path.isdir(path):
        raise ValueError(f'not a folder: {path}')
    if SCAN and SCAN.state in ('scanning', 'loading'):
        raise ValueError('a scan is already running')
    pending = _persist['timer']
    if pending and pending.is_alive():    # flush unsaved changes to the scan we're leaving
        pending.cancel()
        if SCAN and SCAN.state == 'done':
            save_scan(SCAN)
    _persist['timer'] = None
    SCAN = Scan(path)
    DUPES = Dupes()
    SIMILAR = Similar()
    if not fresh and os.path.exists(scan_file(path)):
        SCAN.state = 'loading'
        threading.Thread(target=SCAN.load_saved, daemon=True).start()
    else:
        threading.Thread(target=SCAN.run, daemon=True).start()


def need_scan():
    if not SCAN or SCAN.state != 'done':
        raise LookupError('scan not finished')
    return SCAN


def api_status():
    s = SCAN
    return {
        'scan': s.state if s else 'idle', 'root': s.root if s else None,
        'files': s.files if s else 0, 'dirs': s.dirs if s else 0, 'bytes': s.bytes if s else 0,
        'current': s.current if s else '', 'used': s.disk['used'] if s else 0,
        'elapsed': ((s.finished or time.time()) - s.started) if s else 0, 'last': s.last if s else None,
        'stale': bool(s and s.stale_data), 'cached': bool(s and s.cached),
        'scanned_at': s.finished if s and s.state == 'done' else None,
        'dupes': {'state': DUPES.state, 'done': DUPES.done, 'total': DUPES.total},
        'similar': {'state': SIMILAR.state, 'done': SIMILAR.done, 'total': SIMILAR.total},
        'is_root': IS_ROOT, 'home': HOME, 'user': USER_NAME, 'version': VERSION,
    }


def api_overview():
    s = need_scan()
    disk = mount_info(s.root)
    kids = api_ls(s.root)['entries'][:14]
    cats = sorted(({'cat': c, 'label': CAT_LABEL[c], 'count': v[0], 'bytes': v[1]} for c, v in s.cats.items()),
                  key=lambda x: -x['bytes'])
    return {'root': s.root, 'disk': disk, 'scanned': s.bytes, 'files': s.files, 'dirs': s.dirs,
            'elapsed': s.finished - s.started, 'err_count': s.err_count, 'errors': s.errors[:40],
            'children': kids, 'cats': cats, 'is_root': IS_ROOT, 'last': s.last, 'insights': insights(s, disk),
            'stale': s.stale_data, 'mounts': mounts_with_age(), 'cached': s.cached, 'scanned_at': s.finished,
            'used_at_scan': s.disk['used']}


def mounts_with_age():
    out = list_mounts()
    for m in out:
        info = saved_scan_info(m['mount'])
        m['scanned_at'] = info['time'] if info else None
    return out


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
                                    'unscanned': size is None, 'cat': 'dir', 'locked': locked(e.path)})
                elif stat.S_ISREG(st.st_mode):
                    du = st.st_blocks * 512
                    entries.append({'name': e.name, 'path': e.path, 'dir': False, 'size': du, 'files': 1,
                                    'mtime': st.st_mtime, 'cat': category(e.path, ext_of(e.name), du),
                                    'locked': locked(e.path)})
    except OSError as e:
        raise ValueError(f'cannot read {path}: {e.strerror}')
    entries.sort(key=lambda x: -x['size'])
    return {'path': path, 'size': s.dir_size.get(path, 0), 'files': s.dir_files.get(path, 0), 'entries': entries}


def api_top(cat):
    s = need_scan()
    if cat == 'stale':
        return {'files': [{'path': p, 'size': sz, 'used': used, 'cat': category(p, ext_of(p), sz)}
                          for sz, p, used in sorted(s.stale, reverse=True)][:500]}
    out = []
    for size, path, mtime, atime in sorted(s.top, reverse=True):
        c = category(path, ext_of(os.path.basename(path)), size)
        if cat in ('all', c):
            out.append({'path': path, 'size': size, 'used': max(mtime, atime), 'cat': c, 'locked': locked(path)})
        if len(out) >= 500:
            break
    return {'files': out}


def api_types():
    s = need_scan()
    rows = sorted(({'ext': k, 'count': v[0], 'bytes': v[1], 'cat': EXT_TO_CAT.get(k, 'other')}
                   for k, v in s.types.items()), key=lambda x: -x['bytes'])
    return {'types': rows[:150], 'total': s.bytes}


def api_dupes():
    groups = [{k: v for k, v in g.items() if k != 'meta'} for g in DUPES.groups[:400]]
    return {'state': DUPES.state, 'done': DUPES.done, 'total': DUPES.total, 'groups': groups,
            'wasted': sum(g['wasted'] for g in DUPES.groups), 'count': len(DUPES.groups)}


def api_similar():
    s = SCAN if SCAN and SCAN.state == 'done' else None
    return {'state': SIMILAR.state if FFMPEG else 'unavailable', 'done': SIMILAR.done, 'total': SIMILAR.total,
            'candidates': len(s.media) if s else 0, 'groups': SIMILAR.groups[:300], 'count': len(SIMILAR.groups)}


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


def api_settings():
    return {**settings(), 'alerts': alerts_enabled(), 'notify': bool(shutil.which('notify-send')),
            'systemd': bool(shutil.which('systemctl')), 'cache_dir': CACHE_DIR, 'script': SCRIPT,
            'version': VERSION, 'is_root': IS_ROOT, 'user': USER_NAME, 'ffmpeg': bool(FFMPEG),
            'python': sys.version.split()[0]}


def elevate(root):
    if IS_ROOT:
        raise ValueError('already running as admin')
    if not shutil.which('pkexec'):
        raise ValueError('pkexec is not installed; run "sudo diskscope" in a terminal instead')
    if ELEVATE.get('state') == 'waiting':
        raise ValueError('already waiting for the password dialog')
    handoff = os.path.join(user_dir(CACHE_DIR), f'handoff-{secrets.token_hex(6)}')
    env = [f'{k}={os.environ[k]}' for k in ('DISPLAY', 'WAYLAND_DISPLAY', 'XAUTHORITY', 'XDG_RUNTIME_DIR',
                                            'DBUS_SESSION_BUS_ADDRESS') if os.environ.get(k)]
    p = subprocess.Popen(['pkexec', 'env', *env, sys.executable, SCRIPT, root or '/', '--no-browser',
                          '--handoff', handoff], start_new_session=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ELEVATE.update(state='waiting', proc=p, file=handoff)


def elevate_status():
    st = ELEVATE.get('state')
    if st != 'waiting':
        return {'state': st}
    f = ELEVATE['file']
    if os.path.exists(f):
        with open(f) as fh:
            url = fh.read().strip()
        if url:
            os.remove(f)
            ELEVATE.update(state='ready', url=url)
            return {'state': 'ready', 'url': url}
    rc = ELEVATE['proc'].poll()
    if rc is not None:
        ELEVATE['state'] = 'idle'
        return {'state': 'cancelled' if rc in (126, 127) else 'failed', 'code': rc}
    return {'state': 'waiting'}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype='application/json', cache='no-store'):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Cache-Control', cache)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _host_ok(self):
        port = self.server.server_address[1]
        if self.headers.get('Host') in (f'127.0.0.1:{port}', f'localhost:{port}'):
            return True
        self._send(403, {'error': 'bad host'})
        return False

    def _guard(self, q=None):
        if self.headers.get('X-Token') == TOKEN or (q is not None and q.get('t') == TOKEN):
            return True
        self._send(403, {'error': 'bad token'})
        return False

    def _run(self, fn):
        try:
            self._send(200, fn())
        except LookupError as e:
            self._send(409, {'error': str(e)})
        except (ValueError, OSError, subprocess.SubprocessError) as e:
            self._send(400, {'error': str(e)})

    def do_GET(self):
        if not self._host_ok():
            return
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if u.path == '/':
            page = PAGE.replace('__TOKEN__', TOKEN).replace('__VERSION__', VERSION).replace('__SCRIPT__', SCRIPT)
            return self._send(200, page.encode(), 'text/html; charset=utf-8')
        if u.path == '/api/thumb':
            if not self._guard(q):
                return
            try:
                return self._send(200, thumbnail(q.get('path', '')), 'image/jpeg', 'private, max-age=3600')
            except (ValueError, OSError, subprocess.SubprocessError):
                return self._send(404, b'', 'image/jpeg')
        if not u.path.startswith('/api/'):
            return self._send(404, {'error': 'not found'})
        if not self._guard():
            return
        routes = {
            '/api/status': api_status,
            '/api/overview': api_overview,
            '/api/ls': lambda: api_ls(q.get('path') or need_scan().root),
            '/api/top': lambda: api_top(q.get('cat', 'all')),
            '/api/types': api_types,
            '/api/dupes': api_dupes,
            '/api/similar': api_similar,
            '/api/models': api_models,
            '/api/junk': api_junk,
            '/api/cleanup': api_cleanup,
            '/api/timeshift': api_timeshift,
            '/api/changes': lambda: api_changes(q.get('vs')),
            '/api/activity': api_activity,
            '/api/settings': api_settings,
            '/api/mounts': lambda: {'mounts': mounts_with_age()},
            '/api/elevate': elevate_status,
        }
        fn = routes.get(u.path)
        return self._run(fn) if fn else self._send(404, {'error': 'not found'})

    def do_POST(self):
        if not self._host_ok():
            return
        u = urlparse(self.path)
        if u.path == '/api/bye':      # sent by navigator.sendBeacon when the window closes
            if self._guard({k: v[0] for k, v in parse_qs(u.query).items()}):
                Life.bye_at = time.time()
                self._send(200, {'ok': True})
            return
        if not self._guard():
            return
        n = int(self.headers.get('Content-Length') or 0)
        try:
            body = json.loads(self.rfile.read(n) or b'{}')
        except ValueError:
            return self._send(400, {'error': 'bad json'})
        p = u.path

        def scan():
            start_scan(body.get('path') or '/', fresh=body.get('fresh', True))
            return {'ok': True}

        def job(obj):
            def start():
                s = need_scan()
                if obj.state == 'running':
                    raise ValueError('already running')
                if obj is SIMILAR and not FFMPEG:
                    raise ValueError('install ffmpeg to compare photos and videos')
                obj.state = 'running'
                threading.Thread(target=obj.run, args=(s,), daemon=True).start()
                return {'ok': True}
            return start

        def batch(fn):
            ok, failed, freed = [], [], 0
            for path in body.get('paths', []):
                try:
                    freed += fn(path) or 0
                    ok.append(path)
                except (ValueError, OSError, subprocess.SubprocessError) as e:
                    failed.append({'path': path, 'error': str(e)})
            return {'ok': ok, 'failed': failed, 'freed': freed}

        def do_merge():
            ok, failed, freed = 0, [], 0
            for item in body.get('items', []):
                try:
                    freed += merge(item['keep'], item['others'])
                    ok += 1
                except (ValueError, OSError, KeyError) as e:
                    failed.append({'path': item.get('keep'), 'error': str(e)})
            return {'ok': ok, 'failed': failed, 'freed': freed}

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
            if n:
                log_activity('rmempty', HOME, 0, count=n)
            return {'removed': n}

        def open_():
            path = os.path.abspath(body.get('path', ''))
            target = path if os.path.isdir(path) else os.path.dirname(path)
            subprocess.Popen(as_user(['xdg-open', target]), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return {'ok': True}

        def save_settings():
            cur = load_json(os.path.join(CONFIG_DIR, 'settings.json'), {})
            for k in ('alert_pct', 'alert_drop_gb'):
                if k in body:
                    cur[k] = max(1, min(90 if k == 'alert_pct' else 10000, int(body[k])))
            save_json(os.path.join(CONFIG_DIR, 'settings.json'), cur)
            if 'alerts' in body and bool(body['alerts']) != alerts_enabled():
                set_alerts(bool(body['alerts']))
            return api_settings()

        def test_alert():
            threading.Thread(target=notify, args=('DiskScope alerts are working',
                                                  'You will get a notice like this when a drive runs low.'),
                             daemon=True).start()
            return {'ok': True}

        def quit_():
            threading.Timer(0.3, self.server.shutdown).start()
            return {'ok': True}

        def ping():
            Life.last_ping = time.time()
            return {'ok': True}

        routes = {
            '/api/scan': scan, '/api/dupes': job(DUPES), '/api/similar': job(SIMILAR),
            '/api/trash': lambda: batch(lambda x: remove(x, bool(body.get('permanent')))),
            '/api/merge': do_merge, '/api/split': lambda: batch(split), '/api/restore': lambda: batch(restore),
            '/api/empty': lambda: {'freed': empty_spot(body.get('path', ''))}, '/api/rmempty': rmempty,
            '/api/ts_delete': lambda: {'freed': ts_delete(body.get('name', ''))},
            '/api/open': open_, '/api/settings': save_settings, '/api/alert_test': test_alert,
            '/api/elevate': lambda: elevate(SCAN.root if SCAN else '/') or {'ok': True},
            '/api/quit': quit_, '/api/ping': ping,
        }
        fn = routes.get(p)
        return self._run(fn) if fn else self._send(404, {'error': 'not found'})


def watchdog(srv):
    """Quit when the window is closed (beacon) or nothing has pinged for ~5 minutes."""
    while True:
        time.sleep(2)
        if Life.keep or not Life.last_ping:
            continue
        now = time.time()
        if Life.bye_at > Life.last_ping and now - Life.bye_at > 8:
            break
        if now - Life.last_ping > 330:
            break
    srv.shutdown()


def open_ui(url, tab=False):
    exe = None if tab else next((shutil.which(c) for c in CHROMES if shutil.which(c)), None)
    if exe:
        cmd = [exe, f'--app={url}', '--no-first-run', '--no-default-browser-check', '--window-size=1320,900',
               '--class=DiskScope']
        if not os.path.realpath(exe).startswith('/snap/'):   # snap browsers can't use hidden profile dirs
            cmd.append(f'--user-data-dir={user_dir(os.path.join(CACHE_DIR, "window"))}')
    elif IS_ROOT:
        cmd = ['xdg-open', url]
    else:
        webbrowser.open(url)
        return
    subprocess.Popen(as_user(cmd), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)


PAGE = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DiskScope</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect x='4' y='4' width='56' height='56' rx='12' fill='%231b2128'/%3E%3Crect x='10' y='10' width='26' height='44' rx='3' fill='%234b84d6'/%3E%3Crect x='38' y='10' width='16' height='20' rx='3' fill='%237c5cd6'/%3E%3Crect x='38' y='32' width='16' height='11' rx='3' fill='%23d9622b'/%3E%3Crect x='38' y='45' width='16' height='9' rx='2' fill='%2322998b'/%3E%3C/svg%3E">
<style>
:root{--bg:#f4f6f8;--panel:#fff;--text:#1a1f26;--muted:#5d6876;--line:#e1e6eb;--accent:#2f6fde;--accent-ink:#fff;
--danger:#c63b35;--warn-bg:#fff4dc;--warn-ink:#7a5200;--ok-bg:#e3f4e8;--ok-ink:#1d6b39;--grow:#d1542a;--shrink:#1f8f6a;
--c-dir:#4b84d6;--c-model:#7c5cd6;--c-video:#d9622b;--c-image:#22998b;--c-audio:#c29a17;--c-archive:#8c6b3c;
--c-diskimg:#cf4777;--c-other:#7f8c99;--c-free:#bfe3c8;--c-reserved:#f0cf8f;--c-unread:#e7aaa6;--c-scanned:#4b84d6;
--hl:color-mix(in srgb,var(--accent) 12%,transparent)}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#12161b;--panel:#1b2128;--text:#e6ebf0;--muted:#97a3b0;
--line:#2c343d;--accent:#5b93ef;--accent-ink:#0d1117;--danger:#ef6b65;--warn-bg:#3a2e14;--warn-ink:#f3cf83;--ok-bg:#163223;--ok-ink:#8fdcab;
--grow:#f08a5d;--shrink:#4cc79a;--c-dir:#4f86d6;--c-model:#8f73e6;--c-video:#e07443;--c-image:#33ab9c;--c-audio:#cfa830;--c-archive:#a07f4e;
--c-diskimg:#de5d8b;--c-other:#6f7c89;--c-free:#2f6b44;--c-reserved:#8a6d2e;--c-unread:#8c3f3b;--c-scanned:#4f86d6}}
:root[data-theme="dark"]{--bg:#12161b;--panel:#1b2128;--text:#e6ebf0;--muted:#97a3b0;--line:#2c343d;--accent:#5b93ef;--accent-ink:#0d1117;
--danger:#ef6b65;--warn-bg:#3a2e14;--warn-ink:#f3cf83;--ok-bg:#163223;--ok-ink:#8fdcab;--grow:#f08a5d;--shrink:#4cc79a;--c-free:#2f6b44;
--c-reserved:#8a6d2e;--c-unread:#8c3f3b}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 system-ui,-apple-system,"Segoe UI",Ubuntu,sans-serif}
header{display:flex;gap:12px;align-items:center;flex-wrap:wrap;padding:12px 20px;background:var(--panel);border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:8px;font-weight:700;font-size:17px}
.brand svg{width:24px;height:24px}
#scanform{display:flex;gap:8px;flex:1;min-width:240px;max-width:560px}
input[type=text],input[type=number],select{padding:7px 10px;border:1px solid var(--line);border-radius:7px;background:var(--bg);color:var(--text);font:inherit}
input[type=text]{flex:1;min-width:0}
input[type=number]{width:80px}
button{font:inherit;padding:7px 13px;border-radius:7px;border:1px solid var(--line);background:var(--panel);color:var(--text);cursor:pointer}
button:hover{border-color:var(--accent)}
button:focus-visible,a:focus-visible,input:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
button.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-ink)}
button.danger{color:var(--danger);border-color:color-mix(in srgb,var(--danger) 40%,var(--line))}
button.small{padding:3px 8px;font-size:12.5px}
button:disabled{opacity:.5;cursor:default}
.hdr-right{margin-left:auto;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.who{color:var(--muted);font-size:12.5px}
nav{display:flex;gap:2px;padding:0 20px;background:var(--panel);border-bottom:1px solid var(--line);overflow-x:auto;scrollbar-width:thin}
nav button{border:0;border-bottom:2px solid transparent;border-radius:0;background:none;padding:10px 12px;color:var(--muted);white-space:nowrap}
nav button.on{color:var(--text);border-bottom-color:var(--accent);font-weight:600}
main{max-width:1240px;margin:0 auto;padding:20px}
section{display:none}section.on{display:block}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:16px}
h2{font-size:15px;margin:0 0 12px}
.muted{color:var(--muted)}.small{font-size:12px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:16px}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.tile .k{color:var(--muted);font-size:12px}.tile .v{font-size:20px;font-weight:650;margin-top:2px;font-variant-numeric:tabular-nums}
.stack{display:flex;height:26px;border-radius:6px;overflow:hidden;background:var(--line);gap:2px}
.stack i{display:block;height:100%}
.legend{display:flex;flex-wrap:wrap;gap:6px 18px;margin-top:10px;font-size:13px}
.legend span::before{content:"";display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px;background:var(--sw)}
.note{background:var(--warn-bg);color:var(--warn-ink);border-radius:8px;padding:10px 12px;margin-top:12px;font-size:13px}
.note.ok{background:var(--ok-bg);color:var(--ok-ink)}
.note:first-child{margin-top:0}
a{color:var(--accent)}.note a{color:inherit;font-weight:600}
code{font-family:ui-monospace,"JetBrains Mono",Menlo,monospace;font-size:12.5px;background:var(--bg);padding:1px 5px;border-radius:4px;word-break:break-all}
.scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:middle}
th{font-size:12px;color:var(--muted);font-weight:600}
td.num,th.num{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums}
td.path,.path{word-break:break-all}
th.ck,td.ck{width:28px}
tr.clickable{cursor:pointer}tr.clickable:hover td,tr.cur td{background:var(--hl)}
.bar{height:8px;border-radius:4px;background:var(--line);min-width:60px}
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
.group .hd{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:6px;font-weight:600}
.group label.row{display:flex;gap:8px;align-items:center;padding:3px 0;font-size:13px}
.group label.row .path{flex:1}
.tag{display:inline-block;font-size:11px;font-weight:500;padding:1px 7px;border-radius:9px;background:var(--warn-bg);color:var(--warn-ink);margin-left:6px;white-space:nowrap}
.tag.ok{background:var(--ok-bg);color:var(--ok-ink)}
.tag.info{background:var(--hl);color:var(--accent)}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(270px,1fr));gap:12px}
.card{border:1px solid var(--line);border-radius:10px;padding:12px 14px;display:flex;flex-direction:column;gap:6px}
.card .sz{font-size:19px;font-weight:650;white-space:nowrap}
.card .p{font-size:12px;color:var(--muted);word-break:break-all}
.card .n{font-size:13px;flex:1}
.mounts{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px}
.mount{display:flex;flex-direction:column;align-items:stretch;gap:3px;text-align:left;min-width:190px;flex:1;max-width:300px;padding:10px 12px;border-radius:10px}
.mount.on{border-color:var(--accent);box-shadow:inset 0 0 0 1px var(--accent)}
.mount .bar{margin-top:4px}
.ins{display:flex;gap:12px;align-items:center;padding:8px 0;border-bottom:1px solid var(--line)}
.ins:last-child{border-bottom:0}
.ins .sz{min-width:78px;font-weight:650;text-align:right;font-variant-numeric:tabular-nums}
.ins .t{flex:1}
.delta.up{color:var(--grow)}.delta.down{color:var(--shrink)}
.thumbs{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:10px}
.th{display:flex;flex-direction:column;gap:4px;border:1px solid var(--line);border-radius:8px;overflow:hidden;font-size:12px;cursor:pointer}
.th img{width:100%;height:130px;object-fit:cover;background:var(--line);display:block}
.th .cap{padding:4px 8px 8px;word-break:break-all}
.th:has(input:checked){border-color:var(--danger);box-shadow:inset 0 0 0 1px var(--danger)}
.progress{padding:10px 20px;background:var(--panel);border-bottom:1px solid var(--line);font-size:13px}
.progress .pbar{height:6px;background:var(--line);border-radius:3px;margin-top:6px;overflow:hidden}
.progress .pbar i{display:block;height:100%;background:var(--accent);width:0;transition:width .4s}
.hidden{display:none!important}
#toast{position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:var(--text);color:var(--bg);padding:9px 16px;border-radius:8px;font-size:13px;opacity:0;transition:opacity .25s;pointer-events:none;max-width:90vw;z-index:20}
#toast.on{opacity:1}
.empty{padding:30px;text-align:center;color:var(--muted)}
#help{position:fixed;inset:0;background:rgba(0,0,0,.45);display:flex;align-items:center;justify-content:center;z-index:10;padding:16px}
#help .panel{max-width:520px;width:100%;margin:0}
kbd{font-family:ui-monospace,monospace;font-size:12px;border:1px solid var(--line);border-bottom-width:2px;border-radius:4px;padding:0 5px;background:var(--bg)}
.kv{display:grid;grid-template-columns:max-content 1fr;gap:6px 16px;font-size:13px}
.switch{display:flex;gap:8px;align-items:center;cursor:pointer}
details summary{cursor:pointer}
@media (max-width:640px){main{padding:12px 16px}header{padding:10px 16px}nav{padding:0 8px}#treemap{height:300px}.hide-sm{display:none}.mount{max-width:none}}
</style></head><body>
<header>
  <div class="brand"><svg viewBox="0 0 64 64" aria-hidden="true"><rect x="4" y="4" width="56" height="56" rx="12" fill="#1b2128"/><rect x="10" y="10" width="26" height="44" rx="3" fill="#4b84d6"/><rect x="38" y="10" width="16" height="20" rx="3" fill="#7c5cd6"/><rect x="38" y="32" width="16" height="11" rx="3" fill="#d9622b"/><rect x="38" y="45" width="7" height="9" rx="2" fill="#22998b"/><rect x="47" y="45" width="7" height="9" rx="2" fill="#c29a17"/></svg>DiskScope</div>
  <form id="scanform"><input type="text" id="scanpath" spellcheck="false" aria-label="Folder to scan"><button class="primary" id="scanbtn">Scan</button></form>
  <span class="who" id="age"></span>
  <div class="hdr-right"><span class="who" id="who"></span><button class="small hidden" id="elev">Run as admin</button>
  <button class="small" id="helpbtn" title="Keyboard shortcuts (?)">?</button><button class="small" id="quit" title="Stop DiskScope">Quit</button></div>
</header>
<div class="progress hidden" id="progress"><div id="ptext"></div><div class="pbar"><i id="pfill"></i></div></div>
<nav id="tabs"></nav>
<main id="main"></main>
<div id="help" class="hidden"><div class="panel"><h2>Keyboard shortcuts</h2><div class="kv">
<span><kbd>1</kbd>–<kbd>9</kbd></span><span>Switch tabs</span>
<span><kbd>↑</kbd><kbd>↓</kbd> or <kbd>j</kbd><kbd>k</kbd></span><span>Move through the list (Browse)</span>
<span><kbd>Enter</kbd> / <kbd>→</kbd></span><span>Open the folder</span>
<span><kbd>Backspace</kbd> / <kbd>←</kbd></span><span>Go up one folder</span>
<span><kbd>Del</kbd> / <kbd>Shift</kbd>+<kbd>Del</kbd></span><span>Move to Trash / delete permanently</span>
<span><kbd>o</kbd></span><span>Open in the file manager</span>
<span><kbd>/</kbd></span><span>Filter the current folder</span>
<span><kbd>?</kbd> / <kbd>Esc</kbd></span><span>Show / hide this help</span></div>
<p class="muted small" style="margin-bottom:0">DiskScope __VERSION__ · <a href="https://github.com/0Beemik/DiskScope" target="_blank" rel="noopener">github.com/0Beemik/DiskScope</a></p></div></div>
<div id="toast" role="status"></div>
<script>
const TOKEN='__TOKEN__';
const $=(s,r=document)=>r.querySelector(s), $$=(s,r=document)=>[...r.querySelectorAll(s)];
const TABS=[['overview','Overview'],['changes','Changes'],['browse','Browse'],['largest','Largest files'],['models','AI models'],
 ['dupes','Duplicates'],['similar','Similar media'],['junk','Dev junk'],['cleanup','Cleanup'],['backups','Backups'],
 ['types','File types'],['activity','Activity'],['settings','Settings']];
const CATS={dir:'Folder',model:'AI models',video:'Video',image:'Images',audio:'Audio',archive:'Archives & packages',diskimg:'Disk images & VMs',other:'Everything else'};
const st={tab:'overview',cwd:null,root:null,cat:'all',loaded:false,status:null,cur:0,filter:'',view:[],vs:null,junkOld:false};

$('#tabs').innerHTML=TABS.map(([k,v])=>`<button data-tab="${k}">${v}</button>`).join('');
$('#main').innerHTML=TABS.map(([k])=>`<section id="${k}"></section>`).join('');

async function api(path,body){
  const r=await fetch(path,{method:body?'POST':'GET',headers:{'X-Token':TOKEN,'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});
  const j=await r.json().catch(()=>({error:r.statusText}));
  if(!r.ok) throw new Error(j.error||r.statusText);
  return j;
}
function fmt(b){if(b==null)return '…';const neg=b<0;b=Math.abs(b);const u=['B','KB','MB','GB','TB'];let i=0;while(b>=1024&&i<4){b/=1024;i++}return (neg?'−':'')+(i?b.toFixed(b<10?2:b<100?1:0):b)+' '+u[i]}
const signed=b=>(b>0?'+':'')+fmt(b);
const num=n=>Number(n).toLocaleString();
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const date=t=>t?new Date(t*1000).toLocaleDateString():'—';
function ago(t){if(!t)return '—';const s=Date.now()/1000-t;if(s<90)return 'just now';const m=s/60,h=m/60,d=h/24;
  if(h<1)return Math.round(m)+' min ago';if(d<1)return Math.round(h)+' h ago';if(d<45)return Math.round(d)+' days ago';
  if(d<540)return Math.round(d/30)+' months ago';return (d/365).toFixed(1)+' years ago'}
const col=c=>`var(--c-${c})`;
const base=p=>p.split('/').filter(Boolean).pop()||'/';
function toast(msg){const t=$('#toast');t.textContent=msg;t.classList.add('on');clearTimeout(t._h);t._h=setTimeout(()=>t.classList.remove('on'),4000)}
function rel(p){const h=st.status&&st.status.home;return h&&p.startsWith(h+'/')?'~'+p.slice(h.length):p}
function go(tab,opts){Object.assign(st,opts||{});selectTab(tab)}
function selectTab(tab){
  st.tab=tab;$$('#tabs button').forEach(x=>x.classList.toggle('on',x.dataset.tab===tab));
  $$('section').forEach(x=>x.classList.toggle('on',x.id===tab));
  if(location.hash!=='#'+tab)history.replaceState(null,'','#'+tab);
  load();
}
$('#tabs').onclick=e=>{const b=e.target.closest('button');if(b)selectTab(b.dataset.tab)};

// ---------- lifecycle: heartbeat so DiskScope quits when its window closes
api('/api/ping',{}).catch(()=>{});
setInterval(()=>api('/api/ping',{}).catch(()=>{}),20000);
addEventListener('pagehide',()=>navigator.sendBeacon('/api/bye?t='+TOKEN));

// ---------- status / background jobs
async function poll(){
  let s;try{s=await api('/api/status')}catch(e){$('#ptext').textContent='DiskScope stopped.';$('#progress').classList.remove('hidden');return}
  st.status=s;
  showAge();
  $('#who').textContent=s.is_root?'Admin mode: sees everything':'';
  $('#elev').classList.toggle('hidden',s.is_root);
  const prog=$('#progress');
  const show=(html,pct)=>{prog.classList.remove('hidden');$('#ptext').innerHTML=html;$('#pfill').style.width=Math.max(0,Math.min(100,pct))+'%'};
  if(s.scan==='loading'){show(`Opening the saved scan of <b>${esc(s.root)}</b>…`,100);setTimeout(poll,300);return}
  if(s.scan==='scanning'){
    const last=s.last?` <span class="muted">· last scan ${ago(s.last.time)}: ${fmt(s.last.scanned)}</span>`:'';
    show(`Scanning <b>${esc(s.root)}</b>: ${num(s.files)} files, ${fmt(s.bytes)}${last}<div class="muted small path">${esc(s.current)}</div>`,s.bytes/Math.max(1,s.used)*100);
    setTimeout(poll,600);return;
  }
  if(s.dupes.state==='running'){show(`Checking for duplicates: ${fmt(s.dupes.done)} of up to ${fmt(s.dupes.total)} read`,s.dupes.total?s.dupes.done/s.dupes.total*100:0);st.jobRunning=true;setTimeout(poll,700);return}
  if(s.similar.state==='running'){show(`Comparing photos and videos: ${num(s.similar.done)} of ${num(s.similar.total)}`,s.similar.total?s.similar.done/s.similar.total*100:0);st.jobRunning=true;setTimeout(poll,700);return}
  prog.classList.add('hidden');
  if(st.jobRunning){st.jobRunning=false;if(['dupes','similar','overview'].includes(st.tab))load()}
  if(s.scan==='done'&&!st.loaded){st.loaded=true;st.root=s.root;st.cwd=s.root;st.vs=null;$('#scanpath').value=s.root;showAge();load()}
  if(s.scan==='error'){$('#overview').innerHTML='<div class="panel">Scan failed. Try another folder.</div>'}
}
function showAge(){
  const s=st.status,el=$('#age');if(!s)return;
  el.textContent=s.scan==='done'&&s.scanned_at?'Scanned '+ago(s.scanned_at):'';
  el.title=s.scanned_at?new Date(s.scanned_at*1000).toLocaleString():'';
  $('#scanbtn').textContent=s.root&&$('#scanpath').value.trim()===s.root&&s.scan==='done'?'Rescan':'Scan';
}
setInterval(showAge,60000);
$('#scanpath').oninput=showAge;
async function startScan(path,fresh=true){
  if(!fresh&&st.status&&st.status.root===path&&st.status.scan==='done'){selectTab('overview');return}
  try{await api('/api/scan',{path,fresh});st.loaded=false;$$('section').forEach(s=>s.innerHTML='<div class="empty">Scanning…</div>');
    if(st.tab!=='overview')selectTab('overview');poll()}catch(err){toast(err.message)}
}
$('#scanform').onsubmit=e=>{e.preventDefault();startScan($('#scanpath').value.trim()||'/')};
$('#quit').onclick=async()=>{if(!confirm('Stop DiskScope?'))return;await api('/api/quit',{}).catch(()=>{});document.body.innerHTML='<div class="empty">DiskScope has stopped. You can close this window.</div>'};
$('#helpbtn').onclick=()=>$('#help').classList.toggle('hidden');
$('#help').onclick=e=>{if(e.target.id==='help')$('#help').classList.add('hidden')};
$('#elev').onclick=elevate;
async function elevate(){
  try{await api('/api/elevate',{})}catch(e){toast(e.message);return}
  toast('Enter your password in the system dialog…');
  const t0=Date.now();
  while(Date.now()-t0<180000){
    await new Promise(r=>setTimeout(r,1000));
    let r;try{r=await api('/api/elevate')}catch(e){return}
    if(r.state==='ready'){location.href=r.url+'#'+st.tab;return}
    if(r.state==='cancelled'){toast('Cancelled: still running as you.');return}
    if(r.state==='failed'){toast('Could not start admin mode (code '+r.code+'). Try "sudo diskscope" in a terminal.');return}
  }
}

async function load(){
  if(!st.loaded)return;
  const el=$('#'+st.tab);
  const fn={overview:loadOverview,changes:loadChanges,browse:loadBrowse,largest:loadLargest,types:loadTypes,models:loadModels,
    dupes:loadDupes,similar:loadSimilar,junk:loadJunk,cleanup:loadCleanup,backups:loadBackups,activity:loadActivity,settings:loadSettings}[st.tab];
  try{await fn(el)}catch(e){el.innerHTML=`<div class="panel">${esc(e.message)}</div>`}
}

// ---------- shared actions
async function removePaths(paths,permanent,label){
  if(!paths.length)return;
  const what=paths.length===1?paths[0]:paths.length+' items';
  const msg=permanent?`PERMANENTLY delete ${what}${label?' ('+label+')':''}?\n\nThis cannot be undone.`
    :`Move ${what}${label?' ('+label+')':''} to the Trash?\n\nSpace is freed when the Trash is emptied (Cleanup tab). You can restore it from the Activity tab.`;
  if(!confirm(msg))return;
  try{const r=await api('/api/trash',{paths,permanent});
    toast(`${permanent?'Deleted':'Trashed'} ${r.ok.length} item(s), ${fmt(r.freed)}`+(r.failed.length?`. ${r.failed.length} failed: ${r.failed[0].error}`:''));
    load()}catch(e){toast(e.message)}
}
function copy(text){navigator.clipboard.writeText(text).then(()=>toast('Copied. Paste it in a terminal.'),()=>prompt('Copy this command:',text))}
document.addEventListener('click',e=>{
  const b=e.target.closest('[data-act],[data-copy],[data-goto],[data-scan],[data-open],[data-elevate]');if(!b)return;
  if(b.dataset.open){startScan(b.dataset.open,false);return}
  if(b.dataset.copy!=null){copy(b.dataset.copy);return}
  if(b.dataset.goto){go(b.dataset.goto,b.dataset.cat?{cat:b.dataset.cat}:{});return}
  if(b.dataset.scan){startScan(b.dataset.scan);return}
  if(b.dataset.elevate!=null){elevate();return}
  e.stopPropagation();
  const p=b.dataset.path;
  if(b.dataset.act==='open')api('/api/open',{path:p}).catch(err=>toast(err.message));
  if(b.dataset.act==='trash')removePaths([p],false,b.dataset.size);
  if(b.dataset.act==='browse'){st.cwd=p;go('browse')}
});
const openBtn=p=>`<button class="small" data-act="open" data-path="${esc(p)}" title="Show in file manager">Open</button>`;

// selectable table with bulk Trash / Delete
function selTable(box,{rows,cols,key='path',sizeKey='size',can=()=>true,empty='Nothing here.'}){
  if(!rows.length){box.innerHTML=`<div class="empty">${empty}</div>`;return}
  box.innerHTML=`<div class="toolbar"><span class="muted si">Select items to remove them.</span>
   <button class="small bt" disabled>Move to Trash</button><button class="small danger bd" disabled>Delete permanently</button></div>
   <div class="scroll"><table><thead><tr><th class="ck"><input type="checkbox" class="sa" aria-label="Select all"></th>${cols.map(c=>`<th class="${c.cls||''}">${c.h}</th>`).join('')}</tr></thead>
   <tbody>${rows.map(r=>`<tr><td class="ck">${can(r)?`<input type="checkbox" data-p="${esc(r[key])}" data-s="${r[sizeKey]||0}" aria-label="Select">`:''}</td>${cols.map(c=>`<td class="${c.cls||''}">${c.f(r)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
  wireSel(box);
}
function wireSel(box){
  const boxes=()=>$$('input[data-p]',box);
  const picked=()=>boxes().filter(c=>c.checked);
  const upd=()=>{const s=picked();$('.si',box).textContent=s.length?`${s.length} selected · ${fmt(s.reduce((a,c)=>a+ +c.dataset.s,0))}`:'Select items to remove them.';
    $('.bt',box).disabled=$('.bd',box).disabled=!s.length};
  boxes().forEach(c=>c.onchange=upd);
  const sa=$('.sa',box);if(sa)sa.onchange=()=>{boxes().forEach(c=>c.checked=sa.checked);upd()};
  $('.bt',box).onclick=()=>removePaths(picked().map(c=>c.dataset.p),false);
  $('.bd',box).onclick=()=>removePaths(picked().map(c=>c.dataset.p),true);
  box._upd=upd;
}

// ---------- overview
function mountsHtml(ms,root){
  return `<div class="mounts">${ms.map(m=>`<button class="mount ${m.mount===root?'on':''}" data-open="${esc(m.mount)}" title="${m.scanned_at?'Open the saved scan of':'Scan'} ${esc(m.mount)}">
    <b>${esc(m.label)}</b><span class="muted small path">${esc(m.mount)}</span><span class="small">${fmt(m.free)} free of ${fmt(m.total)}</span>
    <span class="muted small">${m.scanned_at?'Scanned '+ago(m.scanned_at):'Not scanned yet'}</span>
    <span class="bar"><i style="width:${m.used/m.total*100}%;background:${m.free/m.total<0.1?'var(--danger)':'var(--c-dir)'}"></i></span></button>`).join('')}</div>`;
}
async function loadOverview(el){
  const o=await api('/api/overview');const d=o.disk;
  const isMount=o.root===d.mount;
  const hidden=Math.max(0,d.used-o.scanned);
  const hiddenLabel=isMount?(o.is_root?'Not seen by scan':'Needs admin to read'):`Rest of drive (outside ${o.root})`;
  const segs=[['Scanned',o.scanned,'scanned'],[hiddenLabel,hidden,'unread'],['Reserved for root',d.reserved,'reserved'],['Free',d.free,'free']];
  const maxKid=Math.max(1,...o.children.map(c=>c.size)), maxCat=Math.max(1,...o.cats.map(c=>c.bytes));
  let notes='';
  if(d.reserved>0)notes+=`<div class="note"><b>${fmt(d.reserved)}</b> is reserved by the filesystem so the system keeps working if the disk fills up. It counts as neither used nor free.${d.fstype.startsWith('ext')?` On a desktop drive you can safely shrink it from 5% to 1%: <code>sudo tune2fs -m 1 ${esc(d.device)}</code>`:''}</div>`;
  if(o.err_count)notes+=`<details style="margin-top:10px"><summary class="muted">${num(o.err_count)} folders/files couldn't be read</summary><pre style="white-space:pre-wrap;font-size:12px">${esc(o.errors.join('\n'))}</pre></details>`;
  const since=o.cached?`<div class="note" style="margin:0 0 16px;display:flex;gap:10px;align-items:center;flex-wrap:wrap"><span style="flex:1">Showing the saved scan from <b>${new Date(o.scanned_at*1000).toLocaleString()}</b> (${ago(o.scanned_at)}). Since then the drive's used space changed by <b>${signed(o.disk.used-o.used_at_scan)}</b>.</span><button class="small primary" data-scan="${esc(o.root)}">Rescan now</button></div>`
    :o.last?`<div class="note ${o.disk.used-o.last.used>0?'':'ok'}" style="margin:0 0 16px">Since the last scan (${ago(o.last.time)}), the drive's used space changed by <b>${signed(o.disk.used-o.last.used)}</b>. <a href="#changes" data-goto="changes">See what changed →</a></div>`:'';
  const stale=o.stale?`<div class="note" style="margin:0 0 16px">Files were restored or snapshots deleted since this scan. <button class="small" data-scan="${esc(o.root)}">Rescan</button> for exact numbers.</div>`:'';
  el.innerHTML=`${mountsHtml(o.mounts,o.root)}${stale}${since}
  <div class="tiles">
    <div class="tile"><div class="k">Drive size</div><div class="v">${fmt(d.total)}</div></div>
    <div class="tile"><div class="k">Used</div><div class="v">${fmt(d.used)}</div></div>
    <div class="tile"><div class="k">Free</div><div class="v">${fmt(d.free)}</div></div>
    <div class="tile"><div class="k">Files scanned</div><div class="v">${num(o.files)}</div></div>
    <div class="tile"><div class="k">Scan took</div><div class="v">${o.elapsed.toFixed(1)} s</div></div>
  </div>
  <div class="panel"><h2>Where the drive's space goes <span class="muted" style="font-weight:400">· ${esc(d.mount)} (${esc(d.device)})</span></h2>
    <div class="stack" role="img" aria-label="Drive usage">${segs.filter(s=>s[1]>0).map(s=>`<i style="width:${s[1]/d.total*100}%;background:${col(s[2])}" title="${esc(s[0])}: ${fmt(s[1])}"></i>`).join('')}</div>
    <div class="legend">${segs.map(s=>`<span style="--sw:${col(s[2])}">${esc(s[0])} <b>${fmt(s[1])}</b></span>`).join('')}</div>${notes}
  </div>
  ${o.insights.length?`<div class="panel"><h2>Ways to free space</h2>${o.insights.map(i=>`<div class="ins"><span class="sz">${fmt(i.size)}</span><span class="t">${esc(i.text)}</span>
    ${i.tab==='elevate'?'<button class="small" data-elevate>Run as admin</button>':`<button class="small" data-goto="${i.tab}" ${i.cat?`data-cat="${i.cat}"`:''}>Show</button>`}</div>`).join('')}</div>`:''}
  <div class="panel"><h2>Biggest folders in ${esc(o.root)}</h2><table>
    ${o.children.map(c=>`<tr class="clickable" data-go="${esc(c.path)}" data-dir="${c.dir?1:0}"><td class="path"><span class="dot" style="background:${col(c.dir?'dir':c.cat)}"></span>${esc(c.name)}${c.unscanned?' <span class="tag">other drive / not scanned</span>':''}</td>
    <td style="width:40%" class="hide-sm"><div class="bar"><i style="width:${c.size/maxKid*100}%"></i></div></td><td class="num">${fmt(c.size)}</td></tr>`).join('')}
  </table></div>
  <div class="panel"><h2>By kind of file</h2><table>
    ${o.cats.map(c=>`<tr class="clickable" data-cat="${c.cat}"><td><span class="dot" style="background:${col(c.cat)}"></span>${esc(c.label)}</td><td class="num hide-sm">${num(c.count)} files</td>
    <td style="width:40%" class="hide-sm"><div class="bar"><i style="width:${c.bytes/maxCat*100}%;background:${col(c.cat)}"></i></div></td><td class="num">${fmt(c.bytes)}</td></tr>`).join('')}
  </table></div>`;
  $$('[data-go]',el).forEach(r=>r.onclick=()=>{if(r.dataset.dir==='1'){st.cwd=r.dataset.go;go('browse')}});
  $$('tr[data-cat]',el).forEach(r=>r.onclick=()=>go('largest',{cat:r.dataset.cat}));
}

// ---------- changes since a previous scan
async function loadChanges(el){
  const r=await api('/api/changes'+(st.vs?'?vs='+st.vs:''));
  if(r.first){el.innerHTML=`<div class="panel empty">This is the first saved scan of <b>${esc(st.root)}</b>.<br>Scan again another day and this tab will show exactly what grew and what shrank.</div>`;return}
  const sm=r.summary, mx=Math.max(1,...r.dirs.map(d=>Math.abs(d.delta)));
  const fileRows=(rows,cls)=>rows.length?`<table>${rows.map(f=>`<tr><td class="path">${esc(rel(f.path))}</td><td class="num delta ${cls}">${fmt(f.size)}</td><td class="acts">${cls==='up'?openBtn(f.path):''}</td></tr>`).join('')}</table>`:'<div class="muted">None.</div>';
  el.innerHTML=`<div class="panel"><div class="toolbar"><b>Compare with the scan from</b><select id="vs" aria-label="Previous scan">${r.history.map(h=>`<option value="${h.time}" ${h.time===r.vs?'selected':''}>${new Date(h.time*1000).toLocaleString()} (${ago(h.time)})</option>`).join('')}</select></div>
   <div class="tiles" style="margin:0">
    <div class="tile"><div class="k">Used space on the drive</div><div class="v delta ${sm.used_delta>0?'up':'down'}">${signed(sm.used_delta)}</div></div>
    <div class="tile"><div class="k">In the scanned folder</div><div class="v delta ${sm.scanned_delta>0?'up':'down'}">${signed(sm.scanned_delta)}</div></div>
    <div class="tile"><div class="k">Free now</div><div class="v">${fmt(sm.free)}</div></div>
    <div class="tile"><div class="k">Time between scans</div><div class="v">${ago(sm.time).replace(' ago','')}</div></div></div></div>
  <div class="panel"><h2>Folders that changed</h2>${r.dirs.length?`<div class="scroll"><table><thead><tr><th>Folder</th><th class="hide-sm" style="width:26%"></th><th class="num">Change</th><th class="num hide-sm">Before</th><th class="num hide-sm">Now</th><th></th></tr></thead><tbody>
    ${r.dirs.map(d=>`<tr><td class="path">${esc(rel(d.path))}${d.state==='new'?' <span class="tag info">new</span>':d.state==='gone'?' <span class="tag ok">gone</span>':''}</td>
    <td class="hide-sm"><div class="bar"><i style="width:${Math.abs(d.delta)/mx*100}%;background:var(--${d.delta>0?'grow':'shrink'})"></i></div></td>
    <td class="num delta ${d.delta>0?'up':'down'}">${signed(d.delta)}</td><td class="num hide-sm">${fmt(d.before)}</td><td class="num hide-sm">${fmt(d.now)}</td>
    <td class="acts">${d.state!=='gone'?`<button class="small" data-act="browse" data-path="${esc(d.path)}">Browse</button>`:''}</td></tr>`).join('')}</tbody></table></div>`:'<div class="muted">No folder changed by more than 50 MB.</div>'}</div>
  <div class="panel"><h2>New large files</h2>${fileRows(r.new_files,'up')}</div>
  <div class="panel"><h2>Large files that are gone</h2>${fileRows(r.gone_files,'down')}</div>`;
  $('#vs').onchange=e=>{st.vs=e.target.value;loadChanges(el)};
}

// ---------- browse (treemap + list + keyboard)
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
function cd(path,from){st.cwd=path;st.filter='';st.from=from||null;loadBrowse($('#browse'))}
function up(){if(st.cwd===st.root||st.cwd==='/')return;cd(st.cwd.replace(/\/[^/]+$/,'')||'/',st.cwd)}
async function loadBrowse(el){
  const r=await api('/api/ls?path='+encodeURIComponent(st.cwd));
  st.cwd=r.path;st.ls=r;
  const parts=[];let p=r.path;
  while(true){parts.unshift(p);if(p===st.root||p==='/')break;p=p.replace(/\/[^/]+$/,'')||'/'}
  const crumbs=parts.map((q,i)=>`<a data-cd="${esc(q)}" tabindex="0">${esc(i===0?q:base(q))}</a>`).join(' <span class="muted">/</span> ');
  el.innerHTML=`<div class="panel">
    <div class="crumbs">${crumbs} <span class="muted" style="margin-left:8px">${fmt(r.size)} · ${num(r.files)} files</span>
      <span style="margin-left:auto;display:flex;gap:6px"><button class="small" id="upbtn" ${st.cwd===st.root?'disabled':''}>Up</button>${openBtn(r.path)}</span></div>
    <div id="treemap" aria-label="Treemap of this folder"></div>
    <div class="legend" style="margin:-4px 0 12px">${Object.entries(CATS).map(([k,v])=>`<span style="--sw:${col(k)}">${v}</span>`).join('')}</div>
    <div class="toolbar"><input type="text" id="bfilter" placeholder="Filter by name ( / )" value="${esc(st.filter)}" aria-label="Filter" style="max-width:320px"><span class="muted small">↑↓ to move · Enter to open · Backspace to go up · Del to trash · ? for help</span></div>
    <div id="blist"></div></div>`;
  $$('[data-cd]',el).forEach(a=>a.onclick=()=>cd(a.dataset.cd));
  $('#upbtn').onclick=up;
  $('#bfilter').oninput=e=>{st.filter=e.target.value;st.cur=0;renderList()};
  renderList();
  if(st.from){const i=st.view.findIndex(e=>e.path===st.from);if(i>=0){st.cur=i;markCur()}}
  const tm=$('#treemap'),W=tm.clientWidth,H=tm.clientHeight;
  const ents=r.entries.filter(e=>e.size>0);
  let items=ents.slice(0,150).map(e=>({...e,v:e.size}));
  const rest=ents.slice(150).reduce((s,e)=>s+e.size,0);
  if(rest>0)items.push({name:`${ents.length-150} smaller items`,v:rest,cat:'other',size:rest});
  if(!items.length){tm.innerHTML='<div class="empty">Nothing to show</div>';return}
  const out=[];squarify(items,0,0,W,H,out);
  tm.innerHTML=out.filter(t=>t.w>=1&&t.h>=1).map(t=>`<div class="tm ${t.dir?'dir':''}" ${t.dir?`data-cd="${esc(t.path)}"`:''}
    style="left:${t.x}px;top:${t.y}px;width:${t.w}px;height:${t.h}px;background:${col(t.dir?'dir':t.cat)}"
    title="${esc(t.name)}: ${fmt(t.size)}">${t.w>60&&t.h>30?`<b>${esc(t.name)}</b>${fmt(t.size)}`:''}</div>`).join('');
  $$('[data-cd]',tm).forEach(a=>a.onclick=()=>cd(a.dataset.cd));
}
function renderList(){
  const r=st.ls,f=st.filter.toLowerCase();
  st.view=r.entries.filter(e=>!f||e.name.toLowerCase().includes(f)).slice(0,500);
  st.cur=Math.min(st.cur,Math.max(0,st.view.length-1));
  $('#blist').innerHTML=st.view.length?`<div class="scroll"><table><thead><tr><th>Name</th><th class="hide-sm" style="width:22%"></th><th class="num">Size</th><th class="num hide-sm">Files</th><th class="num hide-sm">Modified</th><th></th></tr></thead><tbody>
    ${st.view.map((e,i)=>`<tr class="${e.dir?'clickable':''}" data-i="${i}">
      <td class="path"><span class="dot" style="background:${col(e.dir?'dir':e.cat)}"></span>${esc(e.name)}${e.dir?'/':''}${e.unscanned?' <span class="tag">not scanned</span>':''}</td>
      <td class="hide-sm"><div class="bar"><i style="width:${r.size?e.size/r.size*100:0}%;background:${col(e.dir?'dir':e.cat)}"></i></div></td>
      <td class="num">${fmt(e.size)}</td><td class="num hide-sm">${e.dir?num(e.files):''}</td><td class="num hide-sm">${date(e.mtime)}</td>
      <td class="acts">${openBtn(e.path)} ${e.locked?'':`<button class="small danger" data-act="trash" data-path="${esc(e.path)}" data-size="${fmt(e.size)}">Trash</button>`}</td></tr>`).join('')}</tbody></table></div>`
    :`<div class="empty">${f?'No matches.':'Empty folder.'}</div>`;
  $$('#blist tr[data-i]').forEach(tr=>tr.onclick=()=>{const e=st.view[+tr.dataset.i];st.cur=+tr.dataset.i;markCur();if(e.dir)cd(e.path)});
  markCur(true);
}
function markCur(noScroll){
  $$('#blist tr.cur').forEach(t=>t.classList.remove('cur'));
  const tr=$(`#blist tr[data-i="${st.cur}"]`);if(tr){tr.classList.add('cur');if(!noScroll)tr.scrollIntoView({block:'nearest'})}
}
function browseKey(e){
  const k=e.key,row=st.view[st.cur];
  if(k==='ArrowDown'||k==='j'){st.cur=Math.min(st.view.length-1,st.cur+1);markCur()}
  else if(k==='ArrowUp'||k==='k'){st.cur=Math.max(0,st.cur-1);markCur()}
  else if(k==='Enter'||k==='ArrowRight'||k==='l'){if(row&&row.dir)cd(row.path)}
  else if(k==='Backspace'||k==='ArrowLeft'||k==='h'){up()}
  else if(k==='Delete'){if(row&&!row.locked)removePaths([row.path],e.shiftKey,fmt(row.size))}
  else if(k==='o'){if(row)api('/api/open',{path:row.path}).catch(err=>toast(err.message))}
  else if(k==='/'){$('#bfilter').focus()}
  else return;
  e.preventDefault();
}
addEventListener('resize',()=>{clearTimeout(st._rs);st._rs=setTimeout(()=>{if(st.tab==='browse')load()},250)});
document.addEventListener('keydown',e=>{
  const typing=/INPUT|SELECT|TEXTAREA/.test(document.activeElement.tagName);
  if(e.key==='Escape'){$('#help').classList.add('hidden');if(typing)document.activeElement.blur();return}
  if(typing){if(e.key==='Enter'&&document.activeElement.id==='bfilter'){document.activeElement.blur()}return}
  if(e.ctrlKey||e.metaKey||e.altKey)return;
  if(e.key==='?'){$('#help').classList.toggle('hidden');return}
  if(/^[1-9]$/.test(e.key)&&TABS[+e.key-1]){selectTab(TABS[+e.key-1][0]);return}
  if(st.tab==='browse'&&st.loaded)browseKey(e);
});

// ---------- largest files
async function loadLargest(el){
  const r=await api('/api/top?cat='+st.cat);
  const chips=['all','stale','model','video','image','audio','archive','diskimg','other'];
  el.innerHTML=`<div class="panel"><div class="chips">${chips.map(c=>`<button class="${st.cat===c?'on':''}" data-c="${c}">${c==='all'?'All':c==='stale'?'Unused for 1 year+':CATS[c]}</button>`).join('')}</div><div id="ltable"></div></div>`;
  $$('[data-c]',el).forEach(b=>b.onclick=()=>{st.cat=b.dataset.c;loadLargest(el)});
  selTable($('#ltable'),{rows:r.files,can:f=>!f.locked,empty:st.cat==='stale'?'No large files have gone unused for a year.':'No large files of this kind.',cols:[
    {h:'File',cls:'path',f:f=>`<span class="dot" style="background:${col(f.cat)}"></span>${esc(rel(f.path))}`},
    {h:'Size',cls:'num',f:f=>fmt(f.size)},
    {h:'Last used',cls:'num hide-sm',f:f=>ago(f.used)},
    {h:'',cls:'acts',f:f=>openBtn(f.path)}]});
}

// ---------- types
async function loadTypes(el){
  const r=await api('/api/types');const mx=Math.max(1,...r.types.map(t=>t.bytes));
  el.innerHTML=`<div class="panel"><h2>Space by file extension</h2><div class="scroll"><table><thead><tr><th>Extension</th><th class="num">Files</th><th class="hide-sm" style="width:40%"></th><th class="num">Size</th><th class="num">Share</th></tr></thead><tbody>
  ${r.types.map(t=>`<tr><td><span class="dot" style="background:${col(t.cat)}"></span>${esc(t.ext)}</td><td class="num">${num(t.count)}</td>
  <td class="hide-sm"><div class="bar"><i style="width:${t.bytes/mx*100}%;background:${col(t.cat)}"></i></div></td>
  <td class="num">${fmt(t.bytes)}</td><td class="num">${(t.bytes/Math.max(1,r.total)*100).toFixed(1)}%</td></tr>`).join('')}</tbody></table></div></div>`;
}

// ---------- AI models
async function loadModels(el){
  const r=await api('/api/models');
  if(!r.entries.length){el.innerHTML=`<div class="panel empty">No AI model files found in ${esc(st.root)}.${r.notes.map(n=>`<div class="note">${esc(n)}</div>`).join('')}</div>`;return}
  const mx=Math.max(1,...r.tools.map(t=>t.size));
  el.innerHTML=`<div class="tiles">
    <div class="tile"><div class="k">Space used by models</div><div class="v">${fmt(r.total)}</div></div>
    <div class="tile"><div class="k">Models</div><div class="v">${num(r.entries.length)}</div></div>
    <div class="tile"><div class="k">Apps holding models</div><div class="v">${num(r.tools.length)}</div></div>
    <div class="tile"><div class="k">Stored in more than one place</div><div class="v">${num(r.with_copies)}</div></div></div>
  ${r.notes.map(n=>`<div class="note" style="margin:0 0 16px">${esc(n)} <button class="small" data-elevate>Run as admin</button></div>`).join('')}
  <div class="panel"><h2>By app</h2><table>${r.tools.map(t=>`<tr><td>${esc(t.tool)}</td><td class="num hide-sm">${num(t.count)} model${t.count>1?'s':''}</td>
    <td style="width:45%" class="hide-sm"><div class="bar"><i style="width:${t.size/mx*100}%;background:var(--c-model)"></i></div></td><td class="num">${fmt(t.size)}</td></tr>`).join('')}</table>
    ${r.with_copies?`<div class="note">Models tagged <b>also in…</b> have a file of exactly the same size in another app, so it's almost certainly the same model stored twice. The <a href="#dupes" data-goto="dupes">Duplicates</a> tab can confirm it and <b>merge</b> the copies, so both apps keep working and the space is used once.</div>`:''}</div>
  <div class="panel"><h2>All models</h2><div id="mtable"></div></div>`;
  selTable($('#mtable'),{rows:r.entries,can:m=>!m.cmd,cols:[
    {h:'Model',f:m=>`<b>${esc(m.name)}</b>${m.also.map(a=>`<span class="tag">also in ${esc(a)}</span>`).join('')}<div class="muted small path">${esc(rel(m.path))}</div>`},
    {h:'App',f:m=>esc(m.tool)+(m.role?`<div class="muted small">${esc(m.role)}</div>`:'')},
    {h:'Format',cls:'hide-sm',f:m=>esc(m.fmt)+(m.quant?`<div class="muted small">${esc(m.quant)}</div>`:'')},
    {h:'Size',cls:'num',f:m=>fmt(m.size)},
    {h:'Last used',cls:'num hide-sm',f:m=>ago(m.last_used)},
    {h:'',cls:'acts',f:m=>m.cmd?`<button class="small" data-copy="${esc(m.cmd)}">Copy remove command</button>`:openBtn(m.path)}]});
}

// ---------- duplicates
async function loadDupes(el){
  const r=await api('/api/dupes');
  const start=async()=>{try{await api('/api/dupes',{});el.innerHTML='<div class="empty">Checking… (progress at the top)</div>';poll()}catch(e){toast(e.message)}};
  if(r.state==='idle'){el.innerHTML=`<div class="panel"><h2>Duplicate files</h2><p class="muted">Finds files over 1 MB with identical contents. It compares sizes first, then a quick fingerprint, then a full checksum. Reading big model files can take a few minutes.</p>
    <button class="primary" id="dstart">Find duplicates</button></div>`;$('#dstart').onclick=start;return}
  if(r.state==='running'){el.innerHTML='<div class="empty">Checking for duplicates… (progress at the top)</div>';return}
  const blob=p=>/\/blobs\/(sha256-)?[0-9a-f]{20,}/.test(p);
  const merge=async(items)=>{
    const total=items.reduce((a,i)=>a+i.size*i.others.length,0);
    if(!confirm(`Merge ${items.length} set(s) and free about ${fmt(total)}?\n\nEach extra copy is replaced by a hard link to the first one: the same file, stored once. Every path keeps working, and you can undo it from the Activity tab.\n\nOnly do this for files that don't get edited (models, installers, photos, videos). Editing one copy would change all of them.`))return;
    try{const x=await api('/api/merge',{items:items.map(({keep,others})=>({keep,others}))});
      toast(`Merged ${x.ok} set(s), freed ${fmt(x.freed)}`+(x.failed.length?`. ${x.failed.length} failed: ${x.failed[0].error}`:''));loadDupes(el)}catch(e){toast(e.message)}
  };
  const mergeable=r.groups.filter(g=>g.samefs).map(g=>({keep:g.paths[0],others:g.paths.slice(1),size:g.size}));
  el.innerHTML=`<div class="panel"><h2>${num(r.count)} sets of duplicates · ${fmt(r.wasted)} could be freed</h2>
    <p class="muted" style="margin-top:-6px"><b>Merge</b> keeps every path working but stores the file once (a hard link). <b>Trash/Delete</b> removes the copies you select.</p>
    <div class="toolbar">${mergeable.length?`<button class="small primary" id="d-mergeall">Merge all ${num(mergeable.length)} sets</button>`:''}
      <button class="small" id="d-pick">Select extra copies</button><span class="muted si"></span>
      <button class="small bt" disabled>Move to Trash</button><button class="small danger bd" disabled>Delete permanently</button>
      <button class="small" id="d-re" style="margin-left:auto">Check again</button></div>
    ${r.groups.some(g=>g.paths.some(blob))?`<div class="note" style="margin-bottom:12px">Paths tagged <b>model cache</b> are inside a Hugging Face or Ollama style cache. Don't trash those one by one, because that breaks the model. <b>Merging is safe</b>: both copies keep working.</div>`:''}
    ${r.groups.map((g,i)=>`<div class="group"><div class="hd"><span>${g.paths.length} copies × ${fmt(g.size)}</span><span style="display:flex;gap:8px;align-items:center"><span class="muted">${fmt(g.wasted)} extra</span>
      ${g.samefs?`<button class="small" data-merge="${i}">Merge</button>`:'<span class="tag">on different drives</span>'}</span></div>
      ${g.paths.map((p,j)=>`<label class="row"><input type="checkbox" data-p="${esc(p)}" data-s="${g.size}"><span class="path">${esc(rel(p))}${j===0&&g.samefs?'<span class="tag ok">kept when merging</span>':''}${blob(p)?'<span class="tag">model cache</span>':''}</span>${openBtn(p)}</label>`).join('')}</div>`).join('')||'<div class="empty">No duplicates found.</div>'}
    ${r.count>r.groups.length?`<div class="muted">Showing the ${r.groups.length} biggest sets.</div>`:''}</div>`;
  wireSel(el);
  $('#d-pick').onclick=()=>{$$('.group',el).forEach(g=>$$('input[data-p]',g).forEach((c,i)=>c.checked=i>0));el._upd()};
  $('#d-re').onclick=start;
  const ma=$('#d-mergeall');if(ma)ma.onclick=()=>merge(mergeable);
  $$('[data-merge]',el).forEach(b=>b.onclick=()=>{const g=r.groups[+b.dataset.merge];merge([{keep:g.paths[0],others:g.paths.slice(1),size:g.size}])});
}

// ---------- similar photos & videos
async function loadSimilar(el){
  const r=await api('/api/similar');
  const start=async()=>{try{await api('/api/similar',{});el.innerHTML='<div class="empty">Comparing… (progress at the top)</div>';poll()}catch(e){toast(e.message)}};
  if(r.state==='unavailable'){el.innerHTML=`<div class="panel"><h2>Similar photos and videos</h2><p>This needs <b>ffmpeg</b> to look inside images and videos.</p><code>sudo apt install ffmpeg</code> <button class="small" data-copy="sudo apt install ffmpeg">Copy</button></div>`;return}
  if(r.state==='idle'){el.innerHTML=`<div class="panel"><h2>Similar photos and videos</h2><p class="muted">Finds near-duplicates: the same shot saved twice, resized or re-compressed copies, burst photos, or the same video exported twice. It looks at ${num(r.candidates)} photos and videos in your own folders and skips app and system folders. Results are cached, so later runs are fast.</p>
    <button class="primary" id="sstart" ${r.candidates?'':'disabled'}>Find similar media</button></div>`;$('#sstart').onclick=start;return}
  if(r.state==='running'){el.innerHTML='<div class="empty">Comparing photos and videos… (progress at the top)</div>';return}
  el.innerHTML=`<div class="panel"><h2>${num(r.count)} sets of similar photos and videos</h2>
    <div class="toolbar"><button class="small" id="s-pick">Select all but the largest in each set</button><span class="muted si"></span>
      <button class="small bt" disabled>Move to Trash</button><button class="small danger bd" disabled>Delete permanently</button><button class="small" id="s-re" style="margin-left:auto">Check again</button></div>
    ${r.groups.map(g=>`<div class="group"><div class="hd"><span>${g.items.length} similar ${g.kind==='video'?'videos':'photos'}</span><span class="muted">${fmt(g.total)}</span></div>
      <div class="thumbs">${g.items.map((it,j)=>`<label class="th"><img loading="lazy" alt="" src="/api/thumb?t=${TOKEN}&path=${encodeURIComponent(it.path)}">
      <span class="cap"><input type="checkbox" data-p="${esc(it.path)}" data-s="${it.size}"> ${esc(base(it.path))}${j===0?' <span class="tag ok">largest</span>':''}<br><span class="muted">${fmt(it.size)} · ${date(it.mtime)}</span><br><span class="muted small">${esc(rel(it.path.replace(/\/[^/]+$/,'')))}</span></span></label>`).join('')}</div></div>`).join('')||'<div class="empty">No similar photos or videos found.</div>'}</div>`;
  wireSel(el);
  $('#s-pick').onclick=()=>{$$('.group',el).forEach(g=>$$('input[data-p]',g).forEach((c,i)=>c.checked=i>0));el._upd()};
  $('#s-re').onclick=start;
}

// ---------- developer junk
async function loadJunk(el){
  const r=await api('/api/junk');
  const cut=Date.now()/1000-90*86400;
  const rows=st.junkOld?r.rows.filter(x=>x.last&&x.last<cut):r.rows;
  el.innerHTML=`<div class="tiles"><div class="tile"><div class="k">Rebuildable developer folders</div><div class="v">${fmt(r.total)}</div></div>
    <div class="tile"><div class="k">In projects untouched for 3+ months</div><div class="v">${fmt(r.rows.filter(x=>x.last&&x.last<cut).reduce((a,x)=>a+x.size,0))}</div></div></div>
  <div class="panel"><p class="muted" style="margin-top:0">These folders are recreated by <code>npm install</code>, <code>uv sync</code>/<code>pip install</code>, <code>cargo build</code>, <code>gradle build</code> and so on. Projects you haven't touched in months are the safest to clear. Note that a <code>.venv</code> inside an <i>app</i> (rather than a project you work on) is that app's runtime. Remove it only if you'll reinstall the app.</p>
  <div class="chips"><button class="${st.junkOld?'':'on'}" data-j="0">All</button><button class="${st.junkOld?'on':''}" data-j="1">Untouched for 3 months+</button></div><div id="jtable"></div></div>`;
  $$('[data-j]',el).forEach(b=>b.onclick=()=>{st.junkOld=b.dataset.j==='1';loadJunk(el)});
  selTable($('#jtable'),{rows,empty:'No developer junk found.',cols:[
    {h:'Folder',f:x=>`<b>${esc(base(x.project))}</b>/${esc(x.name)} <span class="muted small">${esc(x.kind)}</span><div class="muted small path">${esc(rel(x.project))}</div>`},
    {h:'Size',cls:'num',f:x=>fmt(x.size)},
    {h:'Project last touched',cls:'num hide-sm',f:x=>ago(x.last)},
    {h:'',cls:'acts',f:x=>openBtn(x.project)}]});
}

// ---------- cleanup
async function loadCleanup(el){
  const r=await api('/api/cleanup');const d=r.disk;
  const pending=r.spots.some(s=>s.status==='pending');
  el.innerHTML=`<div class="panel"><h2>Caches, model stores &amp; system leftovers</h2>
    <p class="muted" style="margin-top:-6px">Known places that grow quietly. <b>Empty</b> is only offered for caches that are safe to re-download.</p>
    <div class="cards">${r.spots.map(s=>`<div class="card">
      <div style="display:flex;justify-content:space-between;gap:8px"><b>${esc(s.name)}</b><span class="sz">${s.status==='pending'?'<span class="muted" style="font-size:13px;font-weight:400">measuring…</span>':fmt(s.size)+(s.partial?'<span class="tag" title="Part of it needs admin to read">at least</span>':'')}</span></div>
      <div class="p">${esc(s.path)}</div><div class="n">${esc(s.note)}</div>
      ${s.how==='cmd'?`<div><code>${esc(s.cmd)}</code></div>`:''}
      <div style="display:flex;gap:6px;flex-wrap:wrap">
        ${s.how==='empty'?`<button class="small danger" data-empty="${esc(s.path)}" data-name="${esc(s.name)}" ${s.size?'':'disabled'}>Empty</button>`:''}
        ${s.how==='cmd'?`<button class="small" data-copy="${esc(s.cmd)}">Copy command</button>`:''}
        ${s.how==='tab'?`<button class="small" data-goto="${s.tab}">Open ${esc(s.tab)} tab</button>`:''}
        ${s.browsable?`<button class="small" data-act="browse" data-path="${esc(s.path)}">Browse</button>`:''}
        ${openBtn(s.path)}
      </div></div>`).join('')}</div></div>
  ${d.reserved>0&&d.fstype.startsWith('ext')?`<div class="panel"><h2>Reserved space · ${fmt(d.reserved)}</h2>
    <p>The ext4 filesystem keeps ${(d.reserved/d.total*100).toFixed(0)}% of the drive for the system. Lowering that to 1% is safe on a desktop drive and gives back about <b>${fmt(d.reserved-d.total*0.01)}</b>.</p>
    <code>sudo tune2fs -m 1 ${esc(d.device)}</code> <button class="small" data-copy="sudo tune2fs -m 1 ${esc(d.device)}">Copy</button></div>`:''}
  <div class="panel"><h2>Empty folders in your home · ${num(r.empty_count)}</h2>
    <p class="muted" style="margin-top:-6px">Hidden and app folders are skipped. These use almost no space, so this is just tidying.</p>
    ${r.empty_count?`<button class="small danger" id="rmempty">Remove all ${num(r.empty_count)} empty folders</button>
    <details style="margin-top:8px"><summary class="muted">Show list</summary><pre style="white-space:pre-wrap;font-size:12px">${esc(r.empty_dirs.join('\n'))}</pre></details>`:'<div class="muted">None found.</div>'}
  </div>`;
  $$('[data-empty]',el).forEach(b=>b.onclick=async()=>{
    if(!confirm(`Empty "${b.dataset.name}"?\n\n${b.dataset.empty}\n\nThis permanently deletes its contents.`))return;
    try{const x=await api('/api/empty',{path:b.dataset.empty});toast(`Freed ${fmt(x.freed)}`);loadCleanup(el)}catch(e){toast(e.message)}});
  const rm=$('#rmempty');if(rm)rm.onclick=async()=>{if(!confirm('Remove all listed empty folders?'))return;
    const x=await api('/api/rmempty',{});toast(`Removed ${x.removed} folders`);loadCleanup(el)};
  if(pending)setTimeout(()=>{if(st.tab==='cleanup')loadCleanup(el)},2000);
}

// ---------- Timeshift backups
async function loadBackups(el){
  const r=await api('/api/timeshift');
  if(!r.available){el.innerHTML='<div class="panel empty">No Timeshift snapshots found in /timeshift.</div>';return}
  el.innerHTML=`<div class="panel"><h2>Timeshift snapshots${r.total!=null?' · '+fmt(r.total):''}</h2>
    <div class="kv" style="margin-bottom:12px"><span class="muted">Schedule</span><span>${esc(r.schedule.join(', ')||'none (manual only)')}</span>
    <span class="muted">Excluded</span><span>${r.excludes.length?r.excludes.map(x=>`<code>${esc(x)}</code>`).join(' '):'nothing'}</span></div>
    ${r.readable?'':`<div class="note" style="margin-bottom:12px">Snapshot contents are only readable by an admin, so sizes are hidden. <button class="small" data-elevate>Run as admin</button></div>`}
    ${r.stale?'<div class="note" style="margin-bottom:12px">Snapshots changed since this scan. Rescan for exact sizes.</div>':''}
    <div class="scroll"><table><thead><tr><th>Snapshot</th><th>Type</th><th class="hide-sm">Comment</th><th class="num" title="Space only this snapshot holds, which is roughly what deleting it frees">Frees if deleted</th><th></th></tr></thead><tbody>
    ${r.snaps.map(s=>`<tr><td>${s.created?new Date(s.created*1000).toLocaleString():esc(s.name)}<div class="muted small">${ago(s.created)}</div></td><td>${esc(s.tags)}</td><td class="hide-sm">${esc(s.comments)}</td>
    <td class="num">${s.unique==null?'<span class="muted">admin only</span>':'≈ '+fmt(s.unique)}</td>
    <td class="acts">${r.is_root?`<button class="small danger" data-ts="${esc(s.name)}">Delete</button>`:`<button class="small" data-copy="sudo timeshift --delete --snapshot '${esc(s.name)}'">Copy delete command</button>`}</td></tr>`).join('')}</tbody></table></div>
    <p class="muted small">Snapshots share unchanged files, so deleting one only frees what no other snapshot also holds. The oldest snapshot usually holds the most. You can also lower how many snapshots Timeshift keeps in its Settings → Schedule.</p></div>
  ${r.prefixes.length?`<div class="panel"><h2>What takes the most space in your backups</h2><p class="muted" style="margin-top:-6px">Folders whose changes are stored again in each snapshot. App data such as models, containers and caches is usually not worth backing up. Exclude it in Timeshift → Settings → Filters → <b>Add folder</b>. Keep <code>/etc</code>, <code>/usr</code> and <code>/boot</code> included.</p>
    <table>${r.prefixes.map(p=>`<tr><td><code>${esc(p.path)}</code> ${p.excluded?'<span class="tag ok">already excluded</span>':p.candidate?'<span class="tag">good to exclude</span>':''}</td><td class="num">${fmt(p.size)}</td>
    <td class="acts">${!p.excluded?`<button class="small" data-copy="${esc(p.path)}/**">Copy filter</button>`:''}</td></tr>`).join('')}</table></div>`:''}`;
  $$('[data-ts]',el).forEach(b=>b.onclick=async()=>{
    if(!confirm(`Delete the Timeshift snapshot ${b.dataset.ts}?\n\nThis cannot be undone.`))return;
    b.disabled=true;b.textContent='Deleting…';
    try{const x=await api('/api/ts_delete',{name:b.dataset.ts});toast(`Snapshot deleted, about ${fmt(x.freed)} freed`);loadBackups(el)}catch(e){toast(e.message);b.disabled=false;b.textContent='Delete'}});
}

// ---------- activity / undo
async function loadActivity(el){
  const r=await api('/api/activity');
  const label={trash:'Moved to Trash',delete:'Deleted',empty:'Emptied cache',merge:'Merged duplicate',split:'Undid merge',restore:'Restored','ts-delete':'Deleted snapshot',rmempty:'Removed empty folders'};
  el.innerHTML=`<div class="panel"><h2>Activity</h2><p class="muted" style="margin-top:-6px">Everything DiskScope removed or changed, newest first. Trashed items can be restored while they're still in the Trash, and merges can be undone.</p>
  ${r.items.length?`<div class="scroll"><table><thead><tr><th>When</th><th>What</th><th>Path</th><th class="num">Size</th><th></th></tr></thead><tbody>
  ${r.items.map(a=>`<tr><td class="muted" title="${new Date(a.time*1000).toLocaleString()}">${ago(a.time)}</td><td>${esc(label[a.action]||a.action)}${a.count?` (${num(a.count)})`:''}</td>
   <td class="path">${esc(rel(a.path))}${a.keep?`<div class="muted small">now linked to ${esc(rel(a.keep))}</div>`:''}</td><td class="num">${a.size?fmt(a.size):''}</td>
   <td class="acts">${a.restorable?`<button class="small" data-restore="${esc(a.path)}">Restore</button>`:''}${a.splittable?`<button class="small" data-split="${esc(a.path)}">Undo merge</button>`:''}</td></tr>`).join('')}</tbody></table></div>`:'<div class="empty">Nothing yet.</div>'}</div>`;
  const act=async(url,path,msg)=>{try{const x=await api(url,{paths:[path]});if(x.failed.length)toast(x.failed[0].error);else toast(msg);loadActivity(el)}catch(e){toast(e.message)}};
  $$('[data-restore]',el).forEach(b=>b.onclick=()=>act('/api/restore',b.dataset.restore,'Restored'));
  $$('[data-split]',el).forEach(b=>b.onclick=()=>{if(confirm('Give this file its own copy again? This uses the space again.'))act('/api/split',b.dataset.split,'Merge undone')});
}

// ---------- settings
async function loadSettings(el){
  const r=await api('/api/settings');
  el.innerHTML=`<div class="panel"><h2>Low disk space alerts</h2>
    <p class="muted" style="margin-top:-6px">A light check runs once an hour in the background (a systemd user timer; it takes a split second and doesn't scan). It sends a desktop notification when a drive gets low or fills up quickly.</p>
    ${r.systemd?'':'<div class="note">systemd isn\'t available, so background alerts can\'t be scheduled.</div>'}
    ${r.notify?'':'<div class="note">notify-send is missing (<code>sudo apt install libnotify-bin</code>).</div>'}
    <label class="switch"><input type="checkbox" id="al-on" ${r.alerts?'checked':''} ${r.systemd?'':'disabled'}> Enable alerts</label>
    <div class="toolbar" style="margin-top:10px">Warn when free space drops below <input type="number" id="al-pct" min="1" max="90" value="${r.alert_pct}">%
      or when more than <input type="number" id="al-drop" min="1" value="${r.alert_drop_gb}"> GB fills up within a day.</div>
    <div class="toolbar"><button class="primary small" id="al-save">Save</button><button class="small" id="al-test">Send a test notification</button></div></div>
  <div class="panel"><h2>About</h2><div class="kv">
    <span class="muted">Version</span><span>DiskScope ${esc(r.version)} · Python ${esc(r.python)}</span>
    <span class="muted">Running as</span><span>${r.is_root?'admin (root), for '+esc(r.user):esc(r.user)}</span>
    <span class="muted">Program</span><span><code>${esc(r.script)}</code></span>
    <span class="muted">Saved data</span><span><code>${esc(r.cache_dir)}</code> <span class="muted small">(scan history, activity log, photo fingerprints)</span></span>
    <span class="muted">Photo/video compare</span><span>${r.ffmpeg?'available (ffmpeg found)':'needs ffmpeg'}</span>
    <span class="muted">Shortcuts</span><span>Press <kbd>?</kbd> anywhere.</span>
    <span class="muted">Project</span><span><a href="https://github.com/0Beemik/DiskScope" target="_blank" rel="noopener">github.com/0Beemik/DiskScope</a></span></div></div>`;
  $('#al-save').onclick=async()=>{try{await api('/api/settings',{alerts:$('#al-on').checked,alert_pct:+$('#al-pct').value,alert_drop_gb:+$('#al-drop').value});toast('Saved');loadSettings(el)}catch(e){toast(e.message)}};
  $('#al-test').onclick=()=>api('/api/alert_test',{}).then(()=>toast('Sent. Check your notifications.')).catch(e=>toast(e.message));
}

const initial=location.hash.slice(1);
selectTab(TABS.some(t=>t[0]===initial)?initial:'overview');
poll();
</script></body></html>'''


def main():
    ap = argparse.ArgumentParser(prog='diskscope', description='See what is using your disk and clean it up: folders, '
                                 'big files, AI models, duplicates, caches, backups. Opens a local window.')
    ap.add_argument('path', nargs='?', default='/', help='folder or drive to scan (default: / , the whole drive)')
    ap.add_argument('--rescan', action='store_true', help='scan now instead of opening the saved scan')
    ap.add_argument('--port', type=int, default=0, help='port to listen on (default: random)')
    ap.add_argument('--no-browser', action='store_true', help="don't open a window, just print the URL")
    ap.add_argument('--tab', action='store_true', help='open in a normal browser tab instead of an app window')
    ap.add_argument('--keep-running', action='store_true', help="don't quit when the window is closed")
    ap.add_argument('--check', action='store_true', help='check free space and notify if low, then exit')
    ap.add_argument('--enable-alerts', action='store_true', help='turn on hourly low-space notifications')
    ap.add_argument('--disable-alerts', action='store_true', help='turn off low-space notifications')
    ap.add_argument('--handoff', help=argparse.SUPPRESS)
    ap.add_argument('--version', action='version', version=f'DiskScope {VERSION}')
    args = ap.parse_args()
    if args.check:
        for m in check_alerts():
            print(m)
        return
    if args.enable_alerts or args.disable_alerts:
        set_alerts(args.enable_alerts)
        print('Low-space alerts', 'enabled (checks hourly).' if args.enable_alerts else 'disabled.')
        return
    try:
        start_scan(args.path, fresh=args.rescan)
    except ValueError as e:
        ap.error(str(e))
    srv = ThreadingHTTPServer(('127.0.0.1', args.port), Handler)
    url = f'http://127.0.0.1:{srv.server_address[1]}/'
    print(f'DiskScope {VERSION} running at {url}  (close the window, press Ctrl+C, or use Quit to stop)', flush=True)
    Life.keep = args.keep_running
    if args.handoff:
        with open(args.handoff, 'w') as f:
            f.write(url)
        chown_user(args.handoff)
    elif not args.no_browser and os.environ.get('DISKSCOPE_NO_BROWSER') != '1':
        open_ui(url, args.tab)
    else:
        Life.keep = True
    threading.Thread(target=watchdog, args=(srv,), daemon=True).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
