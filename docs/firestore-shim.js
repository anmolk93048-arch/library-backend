// ══════════════════════════════════════════════════════════════════
// FIRESTORE-BACKED SHIM — replaces `firebase.database()`
// ──────────────────────────────────────────────────────────────────
// This mimics the small subset of the old Firebase Realtime Database JS
// SDK that admin.html / agent.html / hrms.html / student.html actually
// use: .ref(path), .child(), .once('value'), .on('value')/.off(),
// .set(), .update(), .remove(), .push(), .transaction(),
// .orderByChild().equalTo(), .orderByKey().limitToLast().
//
// Real storage is Google Cloud Firestore, reached through the Cloud Run
// backend at API_BASE (see backend/main.py). None of the ~165 existing
// `FBDB.ref(...)` call sites in the four portal files needed to change —
// only the three lines that created the old `FBDB`/`FBAUTH`/`FBFUNC`
// objects from the Firebase SDK were replaced with a call to
// createFirestoreShim() below.
//
// Path shape: "<namespace>/<key>/<...subPath>", e.g.
//   "shdl/students"                 -> namespace=shdl, key=students
//   "shdl/agents/3"                 -> namespace=shdl, key=agents,   subPath=[3]
//   "hrms/pending_registrations/E1" -> namespace=hrms, key=pending_registrations, subPath=[E1]
//   "shdl"                          -> namespace=shdl, key=null (whole-namespace ops only)
//
// Each (namespace, key) pair is ONE Firestore document holding the whole
// JSON value, matching how this app already used Firebase (read/write a
// whole array or object at a time). Deeper sub-paths are resolved here,
// client-side, by reading the parent document, editing the JSON in
// memory, and writing it back — the exact same "list is loaded, edited,
// saved back whole" pattern this codebase already used everywhere except
// its two or three real .transaction() call sites, which route through
// the atomic compare-and-set endpoint instead (see below).
// ══════════════════════════════════════════════════════════════════
function createFirestoreShim(apiBase) {

  function apiGet(url) {
    return fetch(apiBase + url).then(function (r) { return r.json(); });
  }
  function apiPost(url, body) {
    return fetch(apiBase + url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {})
    }).then(function (r) { return r.json(); });
  }
  function apiDelete(url) {
    return fetch(apiBase + url, { method: 'DELETE' }).then(function (r) { return r.json(); });
  }

  function getTop(namespace, key) {
    if (!key) return Promise.resolve(null);
    return apiGet('/api/node/' + encodeURIComponent(namespace) + '/' + encodeURIComponent(key))
      .then(function (res) { return res.value === undefined ? null : res.value; });
  }
  function setTop(namespace, key, value) {
    return apiPost('/api/node/' + encodeURIComponent(namespace) + '/' + encodeURIComponent(key), { value: value });
  }
  function deleteTop(namespace, key) {
    if (key) return apiDelete('/api/node/' + encodeURIComponent(namespace) + '/' + encodeURIComponent(key));
    return apiDelete('/api/node/' + encodeURIComponent(namespace));
  }
  function casTop(namespace, key, expected, value) {
    return apiPost('/api/node-cas/' + encodeURIComponent(namespace) + '/' + encodeURIComponent(key), {
      expected: expected === undefined ? null : expected,
      value: value
    });
  }

  function clone(v) { return v === undefined ? undefined : JSON.parse(JSON.stringify(v)); }

  function getAt(root, subPath) {
    var cur = root;
    for (var i = 0; i < subPath.length; i++) {
      if (cur === null || cur === undefined) return undefined;
      cur = cur[subPath[i]];
    }
    return cur;
  }
  function setAt(root, subPath, val) {
    if (subPath.length === 0) return clone(val);
    var newRoot = (root === null || root === undefined || typeof root !== 'object') ? {} : clone(root);
    var cur = newRoot;
    for (var i = 0; i < subPath.length - 1; i++) {
      var seg = subPath[i];
      if (cur[seg] === null || cur[seg] === undefined || typeof cur[seg] !== 'object') cur[seg] = {};
      cur = cur[seg];
    }
    cur[subPath[subPath.length - 1]] = clone(val);
    return newRoot;
  }
  function deleteAt(root, subPath) {
    if (subPath.length === 0) return null;
    if (root === null || root === undefined) return root;
    var newRoot = clone(root);
    var cur = newRoot;
    for (var i = 0; i < subPath.length - 1; i++) {
      var seg = subPath[i];
      if (cur[seg] === null || cur[seg] === undefined) return newRoot;
      cur = cur[seg];
    }
    var last = subPath[subPath.length - 1];
    if (Array.isArray(cur)) cur.splice(Number(last), 1);
    else delete cur[last];
    return newRoot;
  }

  function genId() {
    return 't' + Date.now().toString(36) + Math.random().toString(36).slice(2, 10);
  }

  function makeSnapshot(val, key) {
    val = val === undefined ? null : val;
    return {
      val: function () { return val; },
      key: key || null,
      exists: function () { return val !== null && val !== undefined; },
      forEach: function (cb) {
        var v = val || {};
        Object.keys(v).forEach(function (k) { cb(makeSnapshot(v[k], k)); });
      }
    };
  }

  function parsePath(path) {
    var segs = String(path).split('/').filter(function (s) { return s.length > 0; });
    return {
      namespace: segs[0] || '',
      key: segs.length > 1 ? segs[1] : null,
      subPath: segs.slice(2)
    };
  }

  function Ref(namespace, topKey, subPath) {
    this.namespace = namespace;
    this._topKey = topKey === undefined ? null : topKey; // the real (namespace,key) document this ref lives under — never changes via .child()
    this.subPath = subPath || [];
    // Firebase compat: `.key` on a ref is the LAST path segment (used
    // after .push() to read the generated id) — falls back to the
    // top-level key when there's no deeper sub-path.
    this.key = this.subPath.length > 0 ? this.subPath[this.subPath.length - 1] : this._topKey;
    this._listeners = []; // {event, cb, intervalId}
  }

  Ref.prototype.child = function (rel) {
    var segs = String(rel).split('/').filter(function (s) { return s.length > 0; });
    return new Ref(this.namespace, this._topKey, this.subPath.concat(segs));
  };

  Ref.prototype._realTopKey = function () {
    return this._topKey;
  };

  Ref.prototype._fetchWhole = function () {
    return getTop(this.namespace, this._realTopKey());
  };

  Ref.prototype.once = function (eventType, successCb, errorCb) {
    var self = this;
    var p = self._fetchWhole().then(function (whole) {
      var val = getAt(whole, self.subPath);
      var snap = makeSnapshot(val, self.subPath.length ? self.subPath[self.subPath.length - 1] : self._realTopKey());
      if (successCb) successCb(snap);
      return snap;
    }).catch(function (err) {
      if (errorCb) errorCb(err);
      throw err;
    });
    return p;
  };

  Ref.prototype.on = function (eventType, cb) {
    var self = this;
    function tick() {
      self._fetchWhole().then(function (whole) {
        var val = getAt(whole, self.subPath);
        cb(makeSnapshot(val, self.subPath.length ? self.subPath[self.subPath.length - 1] : self._realTopKey()));
      }).catch(function (err) { console.warn('Firestore shim .on() poll error:', err); });
    }
    tick();
    var intervalId = setInterval(tick, 6000); // polling replaces RTDB's realtime push
    self._listeners.push({ event: eventType, cb: cb, intervalId: intervalId });
    return cb;
  };

  Ref.prototype.off = function (eventType, cbRef) {
    this._listeners = this._listeners.filter(function (l) {
      if (l.event !== eventType) return true;
      if (cbRef && l.cb !== cbRef) return true;
      clearInterval(l.intervalId);
      return false;
    });
  };

  Ref.prototype.set = function (val, cb) {
    var self = this;
    var p;
    if (self.subPath.length === 0) {
      p = setTop(self.namespace, self._realTopKey(), clone(val));
    } else {
      p = self._fetchWhole().then(function (whole) {
        var newWhole = setAt(whole, self.subPath, val);
        return setTop(self.namespace, self._realTopKey(), newWhole);
      });
    }
    return p.then(function (r) { if (cb) cb(null); return r; })
      .catch(function (err) { if (cb) cb(err); else throw err; });
  };

  Ref.prototype.update = function (patch, cb) {
    var self = this;
    var p;
    if (self._realTopKey() === null) {
      // Whole-namespace update: each patch key is itself a top-level key
      // (optionally with further '/'-separated sub-path), e.g.
      // FBDB.ref(FB_ROOT).update({students: [...], 'agents/3': {...}}).
      var entries = Object.keys(patch);
      p = entries.reduce(function (chain, entryKey) {
        return chain.then(function () {
          var segs = entryKey.split('/').filter(function (s) { return s.length > 0; });
          var topKey = segs[0];
          var restSub = segs.slice(1);
          if (restSub.length === 0) return setTop(self.namespace, topKey, clone(patch[entryKey]));
          return getTop(self.namespace, topKey).then(function (whole) {
            return setTop(self.namespace, topKey, setAt(whole, restSub, patch[entryKey]));
          });
        });
      }, Promise.resolve());
    } else {
      p = self._fetchWhole().then(function (whole) {
        var newWhole = whole;
        Object.keys(patch).forEach(function (entryKey) {
          var segs = entryKey.split('/').filter(function (s) { return s.length > 0; });
          newWhole = setAt(newWhole, self.subPath.concat(segs), patch[entryKey]);
        });
        return setTop(self.namespace, self._realTopKey(), newWhole);
      });
    }
    return p.then(function (r) { if (cb) cb(null); return r; })
      .catch(function (err) { if (cb) cb(err); else throw err; });
  };

  Ref.prototype.remove = function (cb) {
    var self = this;
    var p;
    if (self._realTopKey() === null) {
      p = deleteTop(self.namespace, null);
    } else if (self.subPath.length === 0) {
      p = deleteTop(self.namespace, self._realTopKey());
    } else {
      p = self._fetchWhole().then(function (whole) {
        return setTop(self.namespace, self._realTopKey(), deleteAt(whole, self.subPath));
      });
    }
    return p.then(function (r) { if (cb) cb(null); return r; })
      .catch(function (err) { if (cb) cb(err); else throw err; });
  };

  Ref.prototype.push = function (val, cb) {
    var id = genId();
    var childRef = new Ref(this.namespace, this._realTopKey(), this.subPath.concat([id]));
    if (val === undefined) return childRef; // Firebase-style: .push() alone just reserves an id
    return childRef.set(val, cb).then(function () { return childRef; });
  };

  // Compare-and-set-based transaction, with client-side retry — mirrors
  // Firebase's own algorithm (run updateFn locally, attempt atomic commit,
  // on conflict refetch the real value and retry).
  Ref.prototype.transaction = function (updateFn, cb) {
    var self = this;
    var MAX_TRIES = 8;

    function attempt(triesLeft) {
      return self._fetchWhole().then(function (whole) {
        var currentSub = getAt(whole, self.subPath);
        var newSub = updateFn(currentSub === undefined ? null : currentSub);
        if (newSub === undefined) {
          // Firebase semantics: returning undefined aborts without writing.
          return { committed: false, snapshot: makeSnapshot(currentSub) };
        }
        var newWhole = setAt(whole, self.subPath, newSub);
        return casTop(self.namespace, self._realTopKey(), whole === undefined ? null : whole, newWhole)
          .then(function (res) {
            if (res.committed) {
              return { committed: true, snapshot: makeSnapshot(newSub) };
            }
            if (triesLeft <= 1) {
              throw new Error('Transaction did not commit after retries (concurrent update).');
            }
            return attempt(triesLeft - 1);
          });
      });
    }

    var p = attempt(MAX_TRIES);
    return p.then(function (result) {
      if (cb) cb(null, result.committed, result.snapshot);
      return result;
    }).catch(function (err) {
      if (cb) cb(err, false, null);
      else throw err;
    });
  };

  // ── Queries: .orderByChild(field).equalTo(val) / .orderByKey().limitToLast(n) ──
  // These fetch the whole node (same as the app already effectively did —
  // Firebase queries here were always over a moderately-sized object of
  // children, never a huge collection) and filter/sort client-side.
  function FilteredQuery(ref, filterFn) {
    this.ref = ref;
    this.filterFn = filterFn;
  }
  FilteredQuery.prototype._apply = function (whole) {
    var val = getAt(whole, this.ref.subPath) || {};
    return this.filterFn(val);
  };
  FilteredQuery.prototype.once = function (eventType, successCb, errorCb) {
    var self = this;
    return self.ref._fetchWhole().then(function (whole) {
      var snap = makeSnapshot(self._apply(whole));
      if (successCb) successCb(snap);
      return snap;
    }).catch(function (err) { if (errorCb) errorCb(err); throw err; });
  };
  FilteredQuery.prototype.on = function (eventType, cb) {
    var self = this;
    function tick() {
      self.ref._fetchWhole().then(function (whole) {
        cb(makeSnapshot(self._apply(whole)));
      }).catch(function (err) { console.warn('Firestore shim query .on() poll error:', err); });
    }
    tick();
    var intervalId = setInterval(tick, 6000);
    self.ref._listeners.push({ event: eventType, cb: cb, intervalId: intervalId });
    return cb;
  };
  FilteredQuery.prototype.off = function (eventType, cbRef) {
    this.ref.off(eventType, cbRef);
  };

  Ref.prototype.orderByChild = function (field) {
    var self = this;
    return {
      equalTo: function (val) {
        return new FilteredQuery(self, function (obj) {
          var out = {};
          Object.keys(obj).forEach(function (k) { if (obj[k] && obj[k][field] === val) out[k] = obj[k]; });
          return out;
        });
      }
    };
  };

  Ref.prototype.orderByKey = function () {
    var self = this;
    return {
      limitToLast: function (n) {
        return new FilteredQuery(self, function (obj) {
          var keys = Object.keys(obj).sort();
          var lastKeys = keys.slice(Math.max(0, keys.length - n));
          var out = {};
          lastKeys.forEach(function (k) { out[k] = obj[k]; });
          return out;
        });
      }
    };
  };

  return {
    ref: function (path) {
      var p = parsePath(path);
      return new Ref(p.namespace, p.key, p.subPath);
    }
  };
}
