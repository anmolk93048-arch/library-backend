"""
Standalone functional test for the payment endpoints in main.py, using a
tiny in-memory fake of the google-cloud-firestore Client/Transaction API
(just enough surface for @firestore.transactional + .get(transaction=)/
.set() to behave like the real thing). Run: python3 docs/test_payments.py
"""
import os, sys, json, unittest.mock as mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

exec(open(os.path.join(os.path.dirname(__file__), '_fakes.py')).read())

with mock.patch('google.cloud.firestore.Client', FakeClient), \
     mock.patch('google.cloud.storage.Client', mock.MagicMock):
    import main as backend

# These patches need to stay in effect for the whole test run, since
# main.py's @firestore.transactional decorator is applied at REQUEST time
# (the inner `_run` function is defined fresh inside each route handler),
# not at import time. Mutating the shared `firestore` module object (which
# main.py already holds a reference to) makes the patch visible everywhere
# that does `from google.cloud import firestore; firestore.transactional`.
backend.firestore.transactional = fake_transactional
backend.firestore.SERVER_TIMESTAMP = 'SERVER_TIMESTAMP'
backend.db = FakeClient()

client = backend.app.test_client()
failures = 0

def assert_(cond, msg):
    global failures
    if not cond:
        failures += 1
        print('FAIL:', msg)
    else:
        print('ok  :', msg)

# ── 0. Unauthenticated verify/reject must be rejected (401) — checked
#      BEFORE patching _auth_role for the rest of these payment-math tests.
unauth_resp = client.post('/api/payments/transactions/nonexistent/verify', json={})
assert_(unauth_resp.status_code == 401, 'verify without a bearer token is rejected (401) before even checking the txn')

# The rest of this file is about payment/wallet MATH correctness, not the
# auth layer itself (see test_auth.py for that) — so stub out the role
# check here to act as an authenticated hrms_employee for the remaining calls.
backend._auth_role = lambda: 'hrms_employee'

# ── 1. Create a student payment transaction ──
resp = client.post('/api/payments/student-transaction', json={
    'studentId': 'STU1', 'studentName': 'Ram', 'agentId': 'AG1',
    'amount': 1000, 'paymentMode': 'UPI', 'gatewayRefId': 'GW123'
})
data = resp.get_json()
assert_(resp.status_code == 200 and 'txnId' in data, 'create student-transaction returns 200 + txnId')
txn_id = data['txnId']

wallet_resp = client.get('/api/node/shdl/agent_wallets')
agent_wallets = wallet_resp.get_json()['value']
assert_(agent_wallets['AG1']['pendingBalance'] == 1000, 'agent pendingBalance credited on transaction creation')

txns_resp = client.get('/api/node/shdl/transactions')
txns = txns_resp.get_json()['value']
assert_(txns[txn_id]['status'] == 'Pending_HRMS', 'transaction stored with Pending_HRMS status')

# ── 2. Verify it (default 10% commission) ──
verify_resp = client.post(f'/api/payments/transactions/{txn_id}/verify', json={})
vdata = verify_resp.get_json()
assert_(verify_resp.status_code == 200 and vdata['status'] == 'Approved', 'verify returns Approved')
assert_(vdata['commission'] == 100.0 and vdata['agentShare'] == 900.0, 'verify computes 10% commission correctly (100 / 900)')

wallets_after = client.get('/api/node/shdl/agent_wallets').get_json()['value']
assert_(wallets_after['AG1']['pendingBalance'] == 0, 'pendingBalance cleared after verify')
assert_(wallets_after['AG1']['approvedBalance'] == 900, 'approvedBalance credited with agent share after verify')
assert_(wallets_after['AG1']['totalEarned'] == 900, 'totalEarned updated after verify')

admin_wallet = client.get('/api/node/shdl/admin_wallet').get_json()['value']
assert_(admin_wallet['totalCommission'] == 100, 'admin_wallet totalCommission credited')

ledger = client.get('/api/node/shdl/commission_ledger').get_json()['value']
assert_(txn_id in ledger and ledger[txn_id]['commission'] == 100, 'commission_ledger has an entry for this txn')

# ── 3. Verifying the SAME transaction again must fail (no double-credit) ──
double_verify = client.post(f'/api/payments/transactions/{txn_id}/verify', json={})
assert_(double_verify.status_code == 409, 'double-verify on an already-approved txn is rejected (409)')
wallets_still = client.get('/api/node/shdl/agent_wallets').get_json()['value']
assert_(wallets_still['AG1']['approvedBalance'] == 900, 'double-verify did NOT double-credit the wallet')

# ── 4. Reject flow (fresh transaction) ──
resp2 = client.post('/api/payments/student-transaction', json={
    'studentId': 'STU2', 'agentId': 'AG1', 'amount': 500, 'paymentMode': 'Cash'
})
txn_id2 = resp2.get_json()['txnId']
wallet_after_2nd = client.get('/api/node/shdl/agent_wallets').get_json()['value']
assert_(wallet_after_2nd['AG1']['pendingBalance'] == 500, 'second transaction adds to pendingBalance independently')

reject_resp = client.post(f'/api/payments/transactions/{txn_id2}/reject', json={'reason': 'Fake screenshot'})
assert_(reject_resp.status_code == 200 and reject_resp.get_json()['status'] == 'Rejected', 'reject returns Rejected')
wallet_after_reject = client.get('/api/node/shdl/agent_wallets').get_json()['value']
assert_(wallet_after_reject['AG1']['pendingBalance'] == 0, 'pendingBalance rolled back to 0 after reject')
assert_(wallet_after_reject['AG1']['approvedBalance'] == 900, 'reject does not touch approvedBalance from the earlier verify')

# ── 5. Missing/invalid input ──
bad_resp = client.post('/api/payments/student-transaction', json={'agentId': 'AG1', 'amount': -5})
assert_(bad_resp.status_code == 400, 'negative amount is rejected with 400')

# ── 6. Custom commission rate ──
client.post('/api/node/shdl/commission_rate', json={'value': 20})
resp3 = client.post('/api/payments/student-transaction', json={'studentId': 'STU3', 'agentId': 'AG2', 'amount': 1000})
txn_id3 = resp3.get_json()['txnId']
verify3 = client.post(f'/api/payments/transactions/{txn_id3}/verify', json={}).get_json()
assert_(verify3['commission'] == 200.0 and verify3['agentShare'] == 800.0, 'custom commission_rate (20%) is honored')

print('\n' + ('ALL PAYMENT TESTS PASSED' if failures == 0 else f'{failures} TEST(S) FAILED'))
sys.exit(0 if failures == 0 else 1)
