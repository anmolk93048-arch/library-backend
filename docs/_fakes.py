"""
Tiny in-memory fake of the google-cloud-firestore Client/Transaction API —
just enough surface (.collection/.document/.get/.set/.delete/.where/.batch/
.transaction) for main.py's routes to run against in tests, without needing
a real GCP project or the Firestore emulator.

Shared by test_payments.py and test_auth.py via:
    exec(open(os.path.join(os.path.dirname(__file__), '_fakes.py')).read())
"""
import unittest.mock as mock


class FakeSnapshot:
    def __init__(self, data):
        self._data = data
        self.exists = data is not None
    def to_dict(self):
        return self._data


class FakeDocRef:
    def __init__(self, store, doc_id):
        self.store = store
        self.doc_id = doc_id
    def get(self, transaction=None):
        return FakeSnapshot(self.store.get(self.doc_id))
    def set(self, data):
        self.store[self.doc_id] = data
    def delete(self):
        self.store.pop(self.doc_id, None)


class FakeCollection:
    def __init__(self, store):
        self.store = store
    def document(self, doc_id):
        return FakeDocRef(self.store, doc_id)
    def where(self, field, op, value):
        class Q:
            def __init__(self, items):
                self.items = items
            def stream(self):
                return iter(self.items)
        matches = [FakeDocRef(self.store, k) for k, v in self.store.items() if v.get(field) == value]
        return Q(matches)


class FakeBatch:
    def __init__(self, store):
        self.store = store
        self.ops = []
    def delete(self, ref):
        self.ops.append(('delete', ref.doc_id))
    def commit(self):
        for op, doc_id in self.ops:
            if op == 'delete':
                self.store.pop(doc_id, None)
        self.ops = []


class FakeTransaction:
    def __init__(self, store):
        self.store = store
    def get(self, ref):
        return FakeSnapshot(self.store.get(ref.doc_id))
    def set(self, ref, data):
        self.store[ref.doc_id] = data


class FakeClient:
    def __init__(self):
        self.store = {}
    def collection(self, name):
        return FakeCollection(self.store)
    def transaction(self):
        return FakeTransaction(self.store)
    def batch(self):
        return FakeBatch(self.store)


def fake_transactional(fn):
    def wrapper(transaction, *a, **kw):
        return fn(transaction, *a, **kw)
    return wrapper
