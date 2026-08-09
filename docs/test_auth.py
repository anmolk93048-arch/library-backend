"""
Standalone functional test for /api/auth/login — password hashing, lazy
migration from plaintext, lockout after repeated failures, role-based
route protection, and per-role verification (admin / agent-staff /
hrms_employee / student). Run: python3 docs/test_auth.py
"""
import os, sys, time, unittest.mock as mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Reuse the same fakes as test_payments.py
exec(open(os.path.join(os.path.dirname(__file__), '_fakes.py')).read())

with mock.patch('google.cloud.firestore.Client', FakeClient), \
     mock.patch('google.cloud.storage.Client', mock.MagicMock):
    import main as backend

backend.firestore.transactional = fake_transactional
backend.firestore.SERVER_TIMESTAMP = 'SERVER_TIMESTAMP'
backend.db = FakeClient()
# Shrink the lockout window so the test doesn't need to sleep 15 minutes.
backend.LOCKOUT_WINDOW_SECONDS = 2
backend.MAX_ATTEMPTS = 3

client = backend.app.test_client()
failures = 0

def assert_(cond, msg):
    global failures
    if not cond:
        failures += 1
        print('FAIL:', msg)
    else:
        print('ok  :', msg)


# ── Seed data: one admin with a PLAINTEXT password (simulating data that
#    existed before this security update — i.e. pre-migration state) ──
client.post('/api/node/shdl/admins', json={'value': [
    {'id': 'A1', 'username': 'boss', 'password': 'oldplaintext123', 'name': 'Boss'}
]})
client.post('/api/node/shdl/agent_logins', json={'value': [
    {'user': 'agent1', 'pass': 'agentpass', 'name': 'Agent One', 'role': 'Agent'}
]})
client.post('/api/node/shdl/employees', json={'value': [
    {'empId': 'EMP1', 'name': 'Ram', 'phone': '9876543210', 'status': 'active'}
]})
client.post('/api/node/shdl/students', json={'value': [
    {'studentId': 'STU1', 'name': 'Sita', 'mobile': '9123456780'}
]})

# ── 1. Wrong admin password is rejected ──
bad = client.post('/api/auth/login', json={'role': 'admin', 'username': 'boss', 'password': 'wrong'})
assert_(bad.status_code == 401, 'wrong admin password -> 401')

# ── 2. Correct plaintext-era password still works (lazy-migration path) ──
ok = client.post('/api/auth/login', json={'role': 'admin', 'username': 'boss', 'password': 'oldplaintext123'})
assert_(ok.status_code == 200 and 'token' in ok.get_json(), 'correct plaintext password logs in successfully')
assert_('password' not in ok.get_json().get('profile', {}), 'login response profile never includes the password field')

# ── 3. After a successful login, the stored password is now HASHED, not plaintext ──
admins_after = client.get('/api/node/shdl/admins').get_json()['value']
stored_pw = admins_after[0]['password']
assert_(stored_pw != 'oldplaintext123', 'plaintext password was replaced after successful login')
assert_(stored_pw.startswith('pbkdf2:') or stored_pw.startswith('scrypt:'), 'stored password is now a real password hash, not plaintext')

# ── 4. Logging in again with the same password still works against the NEW hash ──
ok2 = client.post('/api/auth/login', json={'role': 'admin', 'username': 'boss', 'password': 'oldplaintext123'})
assert_(ok2.status_code == 200, 'login still succeeds after password was migrated to a hash')

# ── 5. Lockout after MAX_ATTEMPTS failures ──
for i in range(backend.MAX_ATTEMPTS):
    client.post('/api/auth/login', json={'role': 'admin', 'username': 'lockout-test', 'password': 'nope'})
locked = client.post('/api/auth/login', json={'role': 'admin', 'username': 'lockout-test', 'password': 'nope'})
assert_(locked.status_code == 429, f'locked out after {backend.MAX_ATTEMPTS} failed attempts (429)')

# ── 6. Lockout expires after the window passes ──
time.sleep(backend.LOCKOUT_WINDOW_SECONDS + 0.5)
unlocked = client.post('/api/auth/login', json={'role': 'admin', 'username': 'lockout-test', 'password': 'nope'})
assert_(unlocked.status_code == 401, 'lockout window expires — back to normal 401 for a wrong password, not 429')

# ── 7. Agent/staff login (agent_logins, case-insensitive username) ──
agent_ok = client.post('/api/auth/login', json={'role': 'agent', 'username': 'AGENT1', 'password': 'agentpass'})
assert_(agent_ok.status_code == 200, 'agent login is case-insensitive on username and succeeds')

# ── 8. HRMS employee login (empId + mobile, no password) ──
emp_ok = client.post('/api/auth/login', json={'role': 'hrms_employee', 'username': 'EMP1', 'mobile': '9876543210'})
assert_(emp_ok.status_code == 200, 'hrms_employee login succeeds with correct empId+mobile')
emp_bad = client.post('/api/auth/login', json={'role': 'hrms_employee', 'username': 'EMP1', 'mobile': '0000000000'})
assert_(emp_bad.status_code == 401, 'hrms_employee login fails with wrong mobile')

# ── 9. Student login (studentId + mobile, no password) ──
stu_ok = client.post('/api/auth/login', json={'role': 'student', 'username': 'stu1', 'mobile': '9123456780'})
assert_(stu_ok.status_code == 200, 'student login is case-insensitive on studentId and succeeds')

# ── 10. An agent token cannot verify a payment (role-restricted route) ──
agent_token = agent_ok.get_json()['token']
verify_as_agent = client.post('/api/payments/transactions/whatever/verify', json={},
                               headers={'Authorization': 'Bearer ' + agent_token})
assert_(verify_as_agent.status_code == 401, 'an agent token is refused on the verify-transaction route (admin/hrms_employee only)')

# ── 11. An hrms_employee token CAN reach the verify route (even though the
#       txn itself won't exist here, so it should 404, not 401) ──
emp_token = emp_ok.get_json()['token']
verify_as_emp = client.post('/api/payments/transactions/whatever/verify', json={},
                             headers={'Authorization': 'Bearer ' + emp_token})
assert_(verify_as_emp.status_code == 404, 'an hrms_employee token IS allowed through to the route logic (404 = txn not found, not 401 = unauthorized)')

# ── 12. Expired token is rejected ──
expired_token = 'expired-test-token'
backend.db.collection(backend.SESSIONS).document(expired_token).set({
    'role': 'admin', 'username': 'boss', 'expiresAt': time.time() - 10
})
expired_resp = client.delete('/api/node/shdl', headers={'Authorization': 'Bearer ' + expired_token})
assert_(expired_resp.status_code == 401, 'an expired session token is rejected even though the token document still exists')

# ── 13. Generic 'gate' role (Dashboard login) — matches admin first ──
gate_admin = client.post('/api/auth/login', json={'role': 'gate', 'username': 'boss', 'password': 'oldplaintext123'})
assert_(gate_admin.status_code == 200, 'gate login matches an admin account')
gate_admin_session = backend.db.collection(backend.SESSIONS).document(gate_admin.get_json()['token']).get().to_dict()
assert_(gate_admin_session['role'] == 'admin', 'gate login session is stored under the REAL matched role (admin), not "gate"')

# ── 14. Generic 'gate' role falls through to agent/staff when admin doesn't match ──
gate_agent = client.post('/api/auth/login', json={'role': 'gate', 'username': 'agent1', 'password': 'agentpass'})
assert_(gate_agent.status_code == 200, 'gate login falls through and matches an agent account')
gate_agent_session = backend.db.collection(backend.SESSIONS).document(gate_agent.get_json()['token']).get().to_dict()
assert_(gate_agent_session['role'] == 'agent', 'gate login session for an agent match is stored under role "agent", not "gate"')

# ── 15. A token obtained via 'gate' (matched as admin) works on an admin-only route ──
gate_admin_token = gate_admin.get_json()['token']
reset_resp = client.delete('/api/node/does_not_matter_here', headers={'Authorization': 'Bearer ' + gate_admin_token})
assert_(reset_resp.status_code == 200, 'a gate-issued token that matched admin works on an admin-only protected route')

# ── 16. Wrong credentials on the gate route are rejected ──
gate_bad = client.post('/api/auth/login', json={'role': 'gate', 'username': 'nobody', 'password': 'wrong'})
assert_(gate_bad.status_code == 401, 'gate login with credentials matching nothing is rejected (401)')

print('\n' + ('ALL AUTH TESTS PASSED' if failures == 0 else f'{failures} TEST(S) FAILED'))
sys.exit(0 if failures == 0 else 1)
