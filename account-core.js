/* account-core.js — shared by index.html (silent prefetch) and account.html (UI).
   Holds NO secrets. All authorization happens server-side from the session token. */
(function () {
  'use strict';

  var EXAMS = {
    OCT:  { label: 'October Mock (Beta)',   api: 'https://script.google.com/macros/s/AKfycbyl1OJhZSEfk96nsFrqZ-WjGVhb8ZIWjVggr-wiIamoQ_Bt8WQUSF12zw9NxNL6uJPFmw/exec' },
    SEPT: { label: 'September Mock (Alpha)', api: 'https://script.google.com/macros/s/AKfycbyPRyb0tKH18K5CsPDlpYl1reuEGsEYTHcyeAebugtjTquvCDuKMAjbdRFkBxKtut5Y1g/exec' }
  };

  function ctx() {
    var ex = localStorage.getItem('activeExam');
    if (!EXAMS[ex]) ex = 'OCT';
    return { exam: ex, cfg: EXAMS[ex], token: localStorage.getItem('token') || '', rep: localStorage.getItem('repId') || '' };
  }
  function cKey(c) { return 'bb_acct_' + c.exam + '_' + c.rep; }

  /* ---- encrypted-at-rest cache (AES-GCM, key derived from the live session token).
     A new login = new token = old cached copies become unreadable. ---- */
  var keyMemo = {};
  function deriveKey(c) {
    var id = c.rep + '|' + c.token;
    if (keyMemo[id]) return keyMemo[id];
    var enc = new TextEncoder();
    keyMemo[id] = crypto.subtle.importKey('raw', enc.encode(c.token), 'PBKDF2', false, ['deriveKey']).then(function (b) {
      return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: enc.encode('bbek-acct:' + c.rep), iterations: 60000, hash: 'SHA-256' },
        b, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    });
    return keyMemo[id];
  }
  function b64(u8) { var s = ''; for (var i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]); return btoa(s); }
  function unb64(s) { var b = atob(s), u = new Uint8Array(b.length); for (var i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; }

  async function putCache(c, obj) {
    try {
      if (!window.crypto || !crypto.subtle || !c.token) return;
      var k = await deriveKey(c), iv = crypto.getRandomValues(new Uint8Array(12));
      var ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, k, new TextEncoder().encode(JSON.stringify(obj))));
      localStorage.setItem(cKey(c), b64(iv) + '.' + b64(ct));
    } catch (e) { /* cache is a nicety, never fatal */ }
  }
  async function getCached() {
    try {
      var c = ctx(); if (!c.token || !c.rep || !window.crypto || !crypto.subtle) return null;
      var raw = localStorage.getItem(cKey(c)); if (!raw) return null;
      var p = raw.split('.'), k = await deriveKey(c);
      var pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(p[0]) }, k, unb64(p[1]));
      return JSON.parse(new TextDecoder().decode(pt));
    } catch (e) { return null; }
  }

  /* ---- network ---- */
  var inflight = null, lastOk = 0;
  function refresh(force) {
    if (inflight) return inflight;
    if (!force && Date.now() - lastOk < 15000) return Promise.resolve({ status: 'fresh' });
    var c = ctx();
    if (!c.token || !c.rep) return Promise.resolve({ status: 'unauthorized' });
    var ctl = new AbortController(), t = setTimeout(function () { ctl.abort(); }, 20000);
    inflight = fetch(c.cfg.api, {
      method: 'POST', headers: { 'Content-Type': 'text/plain;charset=utf-8' },
      body: JSON.stringify({ action: 'account', token: c.token }), signal: ctl.signal,
      referrerPolicy: 'no-referrer', credentials: 'omit'
    }).then(function (r) { return r.json(); }).then(function (d) {
      if (d && d.status === 'ok') { lastOk = Date.now(); return putCache(c, d).then(function () { return d; }); }
      return d || { status: 'error' };
    }).catch(function () { return { status: 'offline' }; })
      .then(function (d) { clearTimeout(t); inflight = null; return d; });
    return inflight;
  }

  function clear() {
    try {
      var rm = [];
      for (var i = 0; i < localStorage.length; i++) { var k = localStorage.key(i); if (k && k.indexOf('bb_acct_') === 0) rm.push(k); }
      rm.forEach(function (k) { localStorage.removeItem(k); });
    } catch (e) {}
    keyMemo = {}; lastOk = 0;
  }

  window.AccountCore = {
    ctx: ctx, getCached: getCached, refresh: refresh, clear: clear,
    prefetch: function () { return refresh(true); }
  };
})();