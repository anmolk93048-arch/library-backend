// Minimal in-memory mock of the Cloud Run backend, to sanity-check the shim's logic.
global.fetch = function(url, opts) {
  opts = opts || {};
  var method = opts.method || 'GET';
  var m;
  if ((m = url.match(/^\/api\/node-cas\/([^\/]+)\/([^\/]+)$/))) {
    var ns=decodeURIComponent(m[1]), key=decodeURIComponent(m[2]);
    var body = JSON.parse(opts.body);
    var docId = ns+'__'+key;
    var current = STORE[docId] === undefined ? null : STORE[docId];
    var match = JSON.stringify(current) === JSON.stringify(body.expected);
    if (match) STORE[docId] = body.value;
    return Promise.resolve({ json: () => Promise.resolve({ committed: match, current: match ? body.value : current }) });
  }
  if ((m = url.match(/^\/api\/node\/([^\/]+)\/([^\/]+)$/))) {
    var ns=decodeURIComponent(m[1]), key=decodeURIComponent(m[2]);
    var docId = ns+'__'+key;
    if (method === 'GET') {
      return Promise.resolve({ json: () => Promise.resolve({ value: STORE[docId] === undefined ? null : STORE[docId] }) });
    }
    if (method === 'POST') {
      var body = JSON.parse(opts.body);
      STORE[docId] = body.value;
      return Promise.resolve({ json: () => Promise.resolve({ ok: true }) });
    }
    if (method === 'DELETE') {
      delete STORE[docId];
      return Promise.resolve({ json: () => Promise.resolve({ ok: true }) });
    }
  }
  if ((m = url.match(/^\/api\/node\/([^\/]+)$/))) {
    var ns=decodeURIComponent(m[1]);
    if (method === 'DELETE') {
      var count=0;
      Object.keys(STORE).forEach(function(k){ if (k.indexOf(ns+'__')===0) { delete STORE[k]; count++; } });
      return Promise.resolve({ json: () => Promise.resolve({ ok: true, deleted: count }) });
    }
  }
  return Promise.reject(new Error('unhandled ' + method + ' ' + url));
};
var STORE = {};

eval(require('fs').readFileSync(__dirname + '/firestore-shim.js', 'utf8'));

var FBDB = createFirestoreShim('');

async function main() {
  var failures = 0;
  function assert(cond, msg) { if (!cond) { failures++; console.error('FAIL:', msg); } else { console.log('ok  :', msg); } }

  // 1. Plain set/get whole node
  await FBDB.ref('shdl/students').set([{id:1,name:'A'}]);
  var snap = await FBDB.ref('shdl/students').once('value');
  assert(JSON.stringify(snap.val()) === JSON.stringify([{id:1,name:'A'}]), 'whole-node set/get roundtrip');

  // 2. Sub-path set (agents/3) then read whole
  await FBDB.ref('shdl/agents').set(['a0','a1','a2','a3']);
  await FBDB.ref('shdl/agents/2').set('CHANGED');
  var agentsSnap = await FBDB.ref('shdl/agents').once('value');
  assert(agentsSnap.val()[2] === 'CHANGED' && agentsSnap.val()[0] === 'a0', 'sub-path index set merges into parent array');

  // 3. .update() at sub-path
  await FBDB.ref('shdl/employees/EMP1').set({name:'Ram', phone:'111'});
  await FBDB.ref('shdl/employees/EMP1').update({phone:'222', dept:'HR'});
  var empSnap = await FBDB.ref('shdl/employees/EMP1').once('value');
  assert(empSnap.val().phone === '222' && empSnap.val().name === 'Ram' && empSnap.val().dept === 'HR', '.update() merges fields without clobbering siblings');

  // 4. .remove() at sub-path
  await FBDB.ref('shdl/employees/EMP1').remove();
  var empGoneSnap = await FBDB.ref('shdl/employees').once('value');
  assert(empGoneSnap.val() === null || empGoneSnap.val().EMP1 === undefined, '.remove() at sub-path deletes just that key');

  // 5. Whole-namespace .update()
  await FBDB.ref('shdl').update({settings:{theme:'dark'}, notices:['n1']});
  var settingsSnap = await FBDB.ref('shdl/settings').once('value');
  var noticesSnap = await FBDB.ref('shdl/notices').once('value');
  assert(settingsSnap.val().theme==='dark' && noticesSnap.val()[0]==='n1', 'namespace-level .update() writes each top-level key');

  // 6. push()
  var txnRef = FBDB.ref('shdl/transactions').push();
  var txnId = txnRef.key;
  await txnRef.set({amount: 500, status: 'Pending_HRMS'});
  var txSnap = await FBDB.ref('shdl/transactions').once('value');
  assert(txSnap.val()[txnId].amount === 500, '.push() then .set() inserts keyed child with generated id');

  // 7. orderByChild().equalTo()
  await FBDB.ref('shdl/transactions/txn2').set({amount:200, status:'Approved'});
  var pendingSnap = await FBDB.ref('shdl/transactions').orderByChild('status').equalTo('Pending_HRMS').once('value');
  var pendingKeys = Object.keys(pendingSnap.val());
  assert(pendingKeys.length === 1 && pendingKeys[0] === txnId, 'orderByChild().equalTo() filters correctly');

  // 8. transaction() — simple increment, single attempt succeeds
  await FBDB.ref('shdl/agent_wallets/AG1').remove();
  await FBDB.ref('shdl/agent_wallets/AG1').transaction(function(current) {
    current = current || {pendingBalance:0};
    current.pendingBalance = (current.pendingBalance||0) + 100;
    return current;
  });
  var walletSnap = await FBDB.ref('shdl/agent_wallets/AG1').once('value');
  assert(walletSnap.val().pendingBalance === 100, 'transaction() creates+increments correctly from null');

  // 9. transaction() — abort (return undefined)
  var beforeAbort = await FBDB.ref('shdl/agent_wallets/AG1').once('value');
  var result = await FBDB.ref('shdl/agent_wallets/AG1').transaction(function(current) {
    if (current.pendingBalance === 999999) return current; // never true, so abort
    return undefined;
  });
  assert(result.committed === false, 'transaction() abort (return undefined) reports committed:false');
  var afterAbort = await FBDB.ref('shdl/agent_wallets/AG1').once('value');
  assert(JSON.stringify(beforeAbort.val()) === JSON.stringify(afterAbort.val()), 'transaction() abort leaves data unchanged');

  // 10. transaction() — concurrent conflict + retry (simulate by mutating STORE mid-flight)
  await FBDB.ref('shdl/counter').set({n: 1});
  var origFetch = global.fetch;
  var callCount = 0;
  global.fetch = function(url, opts) {
    if (url.indexOf('/api/node-cas/') === 0 && callCount === 0) {
      callCount++;
      // Simulate another client sneaking in a write between our GET and our CAS attempt.
      STORE['shdl__counter'] = {n: 2};
    }
    return origFetch(url, opts);
  };
  await FBDB.ref('shdl/counter').transaction(function(current) {
    return {n: (current.n||0) + 10};
  });
  var counterSnap = await FBDB.ref('shdl/counter').once('value');
  assert(counterSnap.val().n === 12, 'transaction() retries after a concurrent write and applies on top of the fresh value (2+10=12)');
  global.fetch = origFetch;

  // 11. orderByKey().limitToLast()
  await FBDB.ref('shdl/selfies/STU1').set({d1:'a', d2:'b', d3:'c'});
  var lastSnap = await FBDB.ref('shdl/selfies/STU1').orderByKey().limitToLast(1).once('value');
  assert(Object.keys(lastSnap.val()).length===1 && lastSnap.val().d3==='c', 'orderByKey().limitToLast(1) returns only the last key');

  // 12. .off() stops polling
  var pollCount = 0;
  var handler = FBDB.ref('shdl/students').on('value', function(){ pollCount++; });
  await new Promise(function(r){ setTimeout(r, 50); });
  FBDB.ref('shdl/students').off('value', handler);
  var countAtOff = pollCount;
  await new Promise(function(r){ setTimeout(r, 50); });
  assert(pollCount === countAtOff, '.off() actually stops further polling');

  console.log(failures === 0 ? '\nALL TESTS PASSED' : '\n' + failures + ' TEST(S) FAILED');
  process.exit(failures === 0 ? 0 : 1);
}
main();
