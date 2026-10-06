"""Tests for DiskScope. Run with:  python3 -m unittest discover -s tests -v"""
import http.client
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
_tmp_state = tempfile.mkdtemp(prefix='diskscope-state-')
os.environ['DISKSCOPE_CACHE'] = os.path.join(_tmp_state, 'cache')
os.environ['DISKSCOPE_CONFIG'] = os.path.join(_tmp_state, 'config')

spec = importlib.util.spec_from_file_location('diskscope', os.path.join(HERE, '..', 'diskscope.py'))
ds = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ds)

MB = 1 << 20


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as f:
        f.write(data)
    return path


def run_scan(root):
    ds.start_scan(root)
    for _ in range(600):
        if ds.SCAN.state != 'scanning':
            break
        time.sleep(0.05)
    assert ds.SCAN.state == 'done', ds.SCAN.errors[:3]
    return ds.SCAN


class Base(unittest.TestCase):
    def setUp(self):
        self.root = os.path.realpath(tempfile.mkdtemp(prefix='dstest'))
        self._saved = (ds.MODEL_MIN, ds.STALE_MIN, ds.CHANGE_MIN, ds.HIST_DIR_MIN, ds.HIST_FILE_MIN, ds.HOME)
        ds.MODEL_MIN = ds.STALE_MIN = 1 * MB
        ds.CHANGE_MIN = ds.HIST_DIR_MIN = ds.HIST_FILE_MIN = 1 * MB
        self.blob = os.urandom(2 * MB)

    def tearDown(self):
        (ds.MODEL_MIN, ds.STALE_MIN, ds.CHANGE_MIN, ds.HIST_DIR_MIN, ds.HIST_FILE_MIN, ds.HOME) = self._saved
        shutil.rmtree(self.root, ignore_errors=True)


class ScanTests(Base):
    def test_sizes_hardlinks_and_categories(self):
        a = write(f'{self.root}/a/big.bin', self.blob)
        write(f'{self.root}/a/b/copy.bin', self.blob)
        os.link(a, f'{self.root}/c-hardlink.bin')                 # must be counted once
        write(f'{self.root}/m/model.gguf', os.urandom(MB + 1))
        os.makedirs(f'{self.root}/empty')
        s = run_scan(self.root)
        du = lambda p: os.lstat(p).st_blocks * 512  # noqa: E731
        expected = du(a) + du(f'{self.root}/a/b/copy.bin') + du(f'{self.root}/m/model.gguf')
        self.assertEqual(s.dir_size[self.root], expected)
        self.assertEqual(s.files, 3)
        self.assertIn(f'{self.root}/empty', s.empty_dirs)
        self.assertIn('model', s.cats)
        self.assertEqual([m[0] for m in s.models], [f'{self.root}/m/model.gguf'])

    def test_category_rules(self):
        self.assertEqual(ds.category('/x/a.safetensors', '.safetensors', 1), 'model')
        self.assertEqual(ds.category('/h/.cache/huggingface/hub/models--a--b/blobs/abc', '', 1), 'model')
        self.assertEqual(ds.category('/x/firmware.bin', '.bin', 10), 'other')
        self.assertEqual(ds.category('/h/.cache/nvidia/GLCache/x.bin', '.bin', 300 * MB), 'other')
        self.assertEqual(ds.category('/h/models/pytorch_model.bin', '.bin', 300 * MB), 'model')
        self.assertEqual(ds.category('/x/clip.MP4'.lower(), '.mp4', 1), 'video')
        self.assertEqual(ds.ext_of('archive.tar.gz'), '.gz')
        self.assertEqual(ds.ext_of('.bashrc'), '')
        self.assertEqual(ds.ext_of('libLLVM.so.21.1'), '.so')
        self.assertEqual(ds.ext_of('backup.7z.001'), '.7z')
        self.assertEqual(ds.ext_of('/a.b/README'), '')
        self.assertEqual(ds.ext_of('.config.json'), '.json')
        self.assertEqual(ds.ext_of('report.2024'), '')
        self.assertEqual(ds.quant_of('qwen3-27b-Q4_K_M.gguf'), 'Q4_K_M')
        self.assertEqual(ds.quant_of('ltx-2.3-22b-distilled-fp8.safetensors'), 'FP8')

    def test_dev_junk_detection(self):
        write(f'{self.root}/proj/package.json', b'{}')
        write(f'{self.root}/proj/node_modules/x/index.js', self.blob)
        write(f'{self.root}/proj/node_modules/y/node_modules/z.js', b'z')   # nested: not listed again
        write(f'{self.root}/rs/Cargo.toml', b'')
        write(f'{self.root}/rs/target/debug/app', self.blob)
        write(f'{self.root}/notrust/target/file', self.blob)                # no Cargo.toml: not junk
        write(f'{self.root}/py/.venv/pyvenv.cfg', b'')
        run_scan(self.root)
        kinds = {os.path.relpath(r['path'], self.root): r['kind'] for r in ds.api_junk()['rows']}
        self.assertEqual(set(kinds), {'proj/node_modules', 'rs/target'})   # .venv is < 1 MB
        self.assertEqual(kinds['rs/target'], 'Rust build output')

    def test_protected_paths(self):
        for p in ('/', '/usr/bin/ls', ds.HOME, '/etc/passwd', '/timeshift/x', '/run/user/1000/x'):
            with self.assertRaises(ValueError, msg=p):
                ds.check_target(p)
        self.assertFalse(ds.is_system('/run/media/me/disk/file'))


class DuplicateTests(Base):
    def test_find_merge_and_split(self):
        a = write(f'{self.root}/one/data.bin', self.blob)
        b = write(f'{self.root}/two/data.bin', self.blob)
        write(f'{self.root}/two/other.bin', os.urandom(2 * MB))           # same size, different content
        s = run_scan(self.root)
        ds.DUPES.run(s)
        self.assertEqual(len(ds.DUPES.groups), 1)
        g = ds.DUPES.groups[0]
        self.assertEqual(sorted(g['paths']), sorted([a, b]))
        self.assertTrue(g['samefs'])
        before = s.dir_size[self.root]
        freed = ds.merge(g['paths'][0], g['paths'][1:])
        self.assertGreater(freed, 0)
        self.assertEqual(os.stat(a).st_ino, os.stat(b).st_ino)
        self.assertEqual(ds.DUPES.groups, [])
        self.assertEqual(s.dir_size[self.root], before - freed)
        with open(b, 'rb') as f:
            self.assertEqual(f.read(), self.blob)
        ds.split(b)
        self.assertNotEqual(os.stat(a).st_ino, os.stat(b).st_ino)
        with open(b, 'rb') as f:
            self.assertEqual(f.read(), self.blob)

    def test_checks_do_not_change_last_used_time(self):
        a = write(f'{self.root}/one/data.bin', self.blob)
        b = write(f'{self.root}/two/data.bin', self.blob)
        old = time.time() - 400 * 86400
        for p in (a, b):
            os.utime(p, (old, old))
        s = run_scan(self.root)
        ds.DUPES.run(s)
        self.assertEqual(len(ds.DUPES.groups), 1)
        for p in (a, b):
            self.assertAlmostEqual(os.stat(p).st_atime, old, delta=1)

    def test_merge_refuses_changed_file(self):
        a = write(f'{self.root}/one/data.bin', self.blob)
        b = write(f'{self.root}/two/data.bin', self.blob)
        s = run_scan(self.root)
        ds.DUPES.run(s)
        time.sleep(0.01)
        write(b, self.blob)                                                 # same bytes, new mtime
        self.assertEqual(len(ds.DUPES.groups), 1)
        with self.assertRaisesRegex(ValueError, 'changed since'):
            ds.merge(a, [b])
        self.assertNotEqual(os.stat(a).st_ino, os.stat(b).st_ino)


def wait_persist():
    timer = ds._persist['timer']
    if timer:
        timer.join(10)


class SavedScanTests(Base):
    def test_reopen_uses_saved_scan_until_rescan(self):
        write(f'{self.root}/a/one.bin', self.blob)
        s1 = run_scan(self.root)
        self.assertFalse(s1.cached)
        self.assertTrue(os.path.exists(ds.scan_file(self.root)))
        self.assertEqual(ds.saved_scan_info(self.root)['files'], 1)
        write(f'{self.root}/b/new.bin', self.blob)            # appears after the scan
        ds.start_scan(self.root, fresh=False)
        for _ in range(200):
            if ds.SCAN.state == 'done':
                break
            time.sleep(0.02)
        s2 = ds.SCAN
        self.assertTrue(s2.cached)
        self.assertEqual(s2.files, 1)                           # saved data, not a new scan
        self.assertEqual(s2.dir_size, s1.dir_size)
        self.assertEqual(sorted(s2.top), sorted(s1.top))
        self.assertEqual(s2.finished, s1.finished)
        s3 = run_scan(self.root)                                # Scan button = fresh scan
        self.assertFalse(s3.cached)
        self.assertEqual(s3.files, 2)

    def reopen(self):
        ds.start_scan(self.root, fresh=False)
        for _ in range(200):
            if ds.SCAN.state == 'done':
                break
            time.sleep(0.02)
        self.assertTrue(ds.SCAN.cached)
        return ds.SCAN

    def test_results_and_removals_are_kept(self):
        a = write(f'{self.root}/one/data.bin', self.blob)
        b = write(f'{self.root}/two/data.bin', self.blob)
        gone = write(f'{self.root}/three/old.bin', os.urandom(MB))
        s = run_scan(self.root)
        ds.DUPES.run(s)
        wait_persist()
        ds.remove(gone, permanent=True)
        wait_persist()
        s2 = self.reopen()
        self.assertEqual(s2.dir_size[f'{self.root}/three'], 0)
        self.assertEqual(s2.dir_size[self.root], os.lstat(a).st_blocks * 512 * 2)
        self.assertEqual(s2.files, 2)
        self.assertEqual(ds.DUPES.state, 'done')
        self.assertEqual(len(ds.DUPES.groups), 1)
        ds.merge(ds.DUPES.groups[0]['paths'][0], ds.DUPES.groups[0]['paths'][1:])   # still works after reload
        self.assertEqual(os.stat(a).st_ino, os.stat(b).st_ino)
        wait_persist()
        self.reopen()
        self.assertEqual(ds.DUPES.groups, [])

    def test_corrupt_saved_scan_falls_back_to_scanning(self):
        write(f'{self.root}/a/one.bin', self.blob)
        run_scan(self.root)
        with open(ds.scan_file(self.root), 'wb') as f:
            f.write(b'not gzip')
        ds.start_scan(self.root, fresh=False)
        for _ in range(300):
            if ds.SCAN.state == 'done':
                break
            time.sleep(0.02)
        self.assertEqual(ds.SCAN.state, 'done')
        self.assertFalse(ds.SCAN.cached)
        self.assertEqual(ds.SCAN.files, 1)


class HistoryTests(Base):
    def test_changes_between_scans(self):
        write(f'{self.root}/keep/a.bin', self.blob)
        write(f'{self.root}/shrinks/a.bin', self.blob)
        s = run_scan(self.root)
        first = int(s.finished)
        time.sleep(1.1)                                                     # history is keyed by second
        write(f'{self.root}/grows/new.bin', os.urandom(3 * MB))
        os.remove(f'{self.root}/shrinks/a.bin')
        s = run_scan(self.root)
        self.assertEqual(s.last['time'], first)
        r = ds.api_changes()
        self.assertFalse(r['first'])
        by = {os.path.relpath(d['path'], self.root): d for d in r['dirs']}
        self.assertIn('grows', by)
        self.assertEqual(by['grows']['state'], 'new')
        self.assertLess(by['shrinks']['delta'], 0)
        self.assertNotIn('keep', by)
        self.assertNotIn('.', by)        # explained by its children
        self.assertIn(f'{self.root}/grows/new.bin', [f['path'] for f in r['new_files']])


class ModelTests(Base):
    def test_hf_ollama_and_cross_app_copies(self):
        ds.HOME = self.root
        hf = f'{self.root}/.cache/huggingface/hub/models--org--tiny-GGUF'
        write(f'{hf}/blobs/0123456789abcdef0123', self.blob)
        os.makedirs(f'{hf}/snapshots/rev')
        os.symlink('../../blobs/0123456789abcdef0123', f'{hf}/snapshots/rev/tiny-Q4_K_M.gguf')
        write(f'{self.root}/Applications/llamaapp/tiny-Q4_K_M.gguf', self.blob)   # same model elsewhere
        om = f'{self.root}/.ollama/models'
        write(f'{om}/blobs/sha256-aaaa', os.urandom(MB + 5))
        write(f'{om}/manifests/registry.ollama.ai/library/llama3/8b', json.dumps(
            {'config': {'digest': 'sha256:cfg', 'size': 10},
             'layers': [{'digest': 'sha256:aaaa', 'size': MB + 5}]}).encode())
        run_scan(self.root)
        r = ds.api_models()
        names = {e['name']: e for e in r['entries'] if e['path'].startswith(self.root)}   # ignore real models
        self.assertEqual(set(names), {'org/tiny-GGUF', 'tiny-Q4_K_M.gguf', 'llama3:8b'})
        self.assertEqual(names['org/tiny-GGUF']['tool'], 'Hugging Face cache')
        self.assertEqual(names['org/tiny-GGUF']['quant'], 'Q4_K_M')
        self.assertEqual(names['tiny-Q4_K_M.gguf']['tool'], 'llamaapp')
        self.assertEqual(names['llama3:8b']['size'], MB + 15)
        self.assertEqual(names['llama3:8b']['cmd'], 'ollama rm llama3:8b')
        self.assertTrue(names['tiny-Q4_K_M.gguf']['also'])
        self.assertEqual(sum(bool(e['also']) for e in names.values()), 2)


class TrashTests(Base):
    def test_restore_from_trash(self):
        ds.HOME = self.root
        orig = f'{self.root}/docs/report.txt'
        can = f'{self.root}/.local/share/Trash'
        write(f'{can}/files/report.txt', b'hello')
        write(f'{can}/info/report.txt.trashinfo',
              f'[Trash Info]\nPath={orig.replace(" ", "%20")}\nDeletionDate=2026-01-01T10:00:00\n'.encode())
        ds.restore(orig)
        with open(orig) as f:
            self.assertEqual(f.read(), 'hello')
        self.assertFalse(os.path.exists(f'{can}/info/report.txt.trashinfo'))
        with self.assertRaises(ValueError):
            ds.restore(orig)


@unittest.skipUnless(ds.FFMPEG, 'ffmpeg not installed')
class SimilarTests(Base):
    def test_resized_copies_are_grouped(self):
        def img(path, size, src='testsrc2'):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            subprocess.run([ds.FFMPEG, '-v', 'error', '-y', '-f', 'lavfi', '-i', f'{src}=size={size}:duration=1',
                            '-frames:v', '1', path], check=True)
        img(f'{self.root}/pics/a.png', '640x480')
        img(f'{self.root}/pics/a-small.jpg', '320x240')
        img(f'{self.root}/pics/other.png', '640x480', 'smptebars')
        s = run_scan(self.root)
        s.media = [(p, os.path.getsize(p), os.path.getmtime(p), 'image')
                   for p in (f'{self.root}/pics/a.png', f'{self.root}/pics/a-small.jpg', f'{self.root}/pics/other.png')]
        ds.SIMILAR.run(s)
        self.assertEqual(len(ds.SIMILAR.groups), 1)
        self.assertEqual({os.path.basename(i['path']) for i in ds.SIMILAR.groups[0]['items']}, {'a.png', 'a-small.jpg'})
        self.assertTrue(ds.thumbnail(f'{self.root}/pics/a.png').startswith(b'\xff\xd8'))


class SimilarGroupingTests(Base):
    def test_no_chaining(self):
        a = 0x0F0F0F0F0F0F0F0F
        b = a ^ 0b1111                     # 4 bits from a
        c = b ^ (0b1111 << 40)             # 4 bits from b, 8 from a
        fake = {'a': a, 'b': b, 'c': c}
        paths = {k: write(f'{self.root}/{k}.jpg', os.urandom((3 - i) * 50000)) for i, k in enumerate('abc')}
        s = run_scan(self.root)
        s.media = [(p, os.path.getsize(p), 0, 'image') for p in paths.values()]
        saved = ds.dhash
        ds.dhash = lambda path, kind: fake[os.path.basename(path)[0]]
        try:
            ds.SIMILAR.run(s)
        finally:
            ds.dhash = saved
        self.assertEqual([[os.path.basename(i['path']) for i in g['items']] for g in ds.SIMILAR.groups],
                         [['a.jpg', 'b.jpg']])


class AlertTests(Base):
    def test_low_space_and_fast_fill(self):
        sent, free = [], [50 * 2**30]
        saved = ds.notify, ds.list_mounts
        ds.notify = lambda title, body, path='/': sent.append(body)
        ds.list_mounts = lambda: [{'mount': '/data', 'label': 'Data', 'total': 1000 * 2**30, 'free': free[0]}]
        try:
            ds.check_alerts()                      # 5% free: low-space alert, sets the baseline
            self.assertEqual(len(sent), 1)
            self.assertIn('only 50.0 GB free', sent[0])
            ds.check_alerts()                      # no repeat within a day
            self.assertEqual(len(sent), 1)
            free[0] = 20 * 2**30                   # 30 GB gone since the baseline
            ds.check_alerts()
            self.assertEqual(len(sent), 2)
            self.assertIn('30.0 GB filled', sent[1])
        finally:
            ds.notify, ds.list_mounts = saved


class ServerTests(Base):
    @classmethod
    def setUpClass(cls):
        cls.srv = ds.ThreadingHTTPServer(('127.0.0.1', 0), ds.Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def req(self, method, path, headers=None, body=None):
        c = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        return r.status, r.read()

    def test_security_and_api(self):
        write(f'{self.root}/x/file.bin', self.blob)
        run_scan(self.root)
        status, page = self.req('GET', '/')
        self.assertEqual(status, 200)
        self.assertIn(ds.TOKEN.encode(), page)
        self.assertEqual(self.req('GET', '/', {'Host': f'evil.example:{self.port}'})[0], 403)   # DNS rebinding
        self.assertEqual(self.req('GET', '/api/status')[0], 403)                                # no token
        hdr = {'X-Token': ds.TOKEN}
        status, body = self.req('GET', '/api/overview', hdr)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)['root'], self.root)
        for ep in ('/api/top?cat=all', '/api/types', '/api/models', '/api/junk', '/api/changes', '/api/activity',
                   '/api/mounts', '/api/timeshift', '/api/similar', '/api/dupes', f'/api/ls?path={self.root}/x'):
            self.assertEqual(self.req('GET', ep, hdr)[0], 200, ep)
        status, body = self.req('POST', '/api/trash', {**hdr, 'Content-Type': 'application/json'},
                                json.dumps({'paths': ['/usr/bin/ls'], 'permanent': True}))
        self.assertEqual(json.loads(body)['ok'], [])
        self.assertTrue(os.path.exists('/usr/bin/ls'))
        status, body = self.req('POST', '/api/trash', {**hdr, 'Content-Type': 'application/json'},
                                json.dumps({'paths': [f'{self.root}/x/file.bin'], 'permanent': True}))
        self.assertEqual(json.loads(body)['ok'], [f'{self.root}/x/file.bin'])
        self.assertEqual(ds.SCAN.dir_size[self.root], 0)


class PageTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'node not installed')
    def test_javascript_parses(self):
        js = ds.PAGE[ds.PAGE.index('<script>') + 8:ds.PAGE.index('</script>')]
        with tempfile.NamedTemporaryFile('w', suffix='.js', delete=False) as f:
            f.write(js)
        try:
            r = subprocess.run(['node', '--check', f.name], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
        finally:
            os.remove(f.name)

    def test_cli(self):
        script = os.path.join(HERE, '..', 'diskscope.py')
        r = subprocess.run([sys.executable, script, '--version'], capture_output=True, text=True)
        self.assertEqual(r.stdout.strip(), f'DiskScope {ds.VERSION}')
        r = subprocess.run([sys.executable, script, '/definitely/not/here'], capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)


if __name__ == '__main__':
    unittest.main()
