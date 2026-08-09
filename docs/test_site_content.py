"""
Standalone functional test for /api/site-content/* — verifies admin-only
auth gating and path/folder allowlisting for the secure GCS proxy routes.
Run: python3 docs/test_site_content.py
"""
import os, sys, io, unittest.mock as mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
exec(open(os.path.join(os.path.dirname(__file__), '_fakes.py')).read())

with mock.patch('google.cloud.firestore.Client', FakeClient), \
     mock.patch('google.cloud.storage.Client', mock.MagicMock):
    import main as backend

backend.db = FakeClient()

# Fake GCS bucket/blob so we can verify upload_from_string/upload_from_file
# were called with the right arguments, without touching real GCS.
class FakeBlob:
    def __init__(self, name):
        self.name = name
        self.uploaded = None
        self.content_type = None
        self.size = 12345
    def upload_from_string(self, data, content_type=None):
        self.uploaded = data
        self.content_type = content_type
    def upload_from_file(self, stream, content_type=None):
        self.uploaded = stream.read()
        self.content_type = content_type

class FakeBucket:
    def __init__(self):
        self.blobs = {}
    def blob(self, path):
        b = self.blobs.setdefault(path, FakeBlob(path))
        return b

fake_bucket = FakeBucket()
fake_gcs_client = mock.MagicMock()
fake_gcs_client.bucket.return_value = fake_bucket
backend._gcs_client = fake_gcs_client

client = backend.app.test_client()
failures = 0

def assert_(cond, msg):
    global failures
    if not cond:
        failures += 1
        print('FAIL:', msg)
    else:
        print('ok  :', msg)

# ── Seed an admin so we can get a real admin token ──
client.post('/api/node/shdl/admins', json={'value': [
    {'id': 'A1', 'username': 'boss', 'password': 'pass123', 'name': 'Boss'}
]})
admin_token = client.post('/api/auth/login', json={'role': 'admin', 'username': 'boss', 'password': 'pass123'}).get_json()['token']
admin_hdr = {'Authorization': 'Bearer ' + admin_token}

# ── 1. Unauthenticated JSON upload is rejected ──
r1 = client.post('/api/site-content/upload-json', json={'path': 'site-data/ticker.json', 'data': {'text': 'hi'}})
assert_(r1.status_code == 401, 'upload-json without a token is rejected (401)')

# ── 2. Authenticated admin upload to an allowed path succeeds ──
r2 = client.post('/api/site-content/upload-json', json={'path': 'site-data/ticker.json', 'data': {'text': 'hi', 'enabled': True}}, headers=admin_hdr)
assert_(r2.status_code == 200, 'admin can upload JSON to an allowed site-data path')
assert_('site-data/ticker.json' in fake_bucket.blobs and fake_bucket.blobs['site-data/ticker.json'].uploaded is not None,
        'the JSON was actually written to the (fake) GCS blob')

# ── 3. Path NOT in the allowlist is rejected even for an authenticated admin ──
r3 = client.post('/api/site-content/upload-json', json={'path': 'shdl/admins', 'data': {'evil': True}}, headers=admin_hdr)
assert_(r3.status_code == 400, 'writing to a non-allowlisted path is rejected even with a valid admin token')

# ── 4. File upload requires an allowed folder ──
data = {'file': (io.BytesIO(b'fake image bytes'), 'logo.png'), 'folder': 'not-a-real-folder'}
r4 = client.post('/api/site-content/upload-file', data=data, content_type='multipart/form-data', headers=admin_hdr)
assert_(r4.status_code == 400, 'file upload to a disallowed folder is rejected')

# ── 5. File upload to an allowed folder succeeds and returns a URL ──
data2 = {'file': (io.BytesIO(b'fake image bytes'), 'logo.png'), 'folder': 'homepage'}
r5 = client.post('/api/site-content/upload-file', data=data2, content_type='multipart/form-data', headers=admin_hdr)
assert_(r5.status_code == 200 and 'url' in r5.get_json(), 'file upload to an allowed folder succeeds and returns a URL')

# ── 6. A non-admin (e.g. agent) token is rejected on both routes ──
client.post('/api/node/shdl/agent_logins', json={'value': [{'user': 'ag1', 'pass': 'x', 'name': 'A', 'role': 'Agent'}]})
agent_token = client.post('/api/auth/login', json={'role': 'agent', 'username': 'ag1', 'password': 'x'}).get_json()['token']
r6 = client.post('/api/site-content/upload-json', json={'path': 'site-data/ticker.json', 'data': {}}, headers={'Authorization': 'Bearer ' + agent_token})
assert_(r6.status_code == 401, 'an agent token is rejected on the admin-only site-content routes')

print('\n' + ('ALL SITE-CONTENT TESTS PASSED' if failures == 0 else f'{failures} TEST(S) FAILED'))
sys.exit(0 if failures == 0 else 1)
