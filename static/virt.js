// Hypervisor and server management: one handler for every action on the
// /virt pages and on a server's /bmc page (data-endpoint="/bmc/act").
//
// A button or a form carries data-act="vm.start" (an action in
// virtops.ACTIONS) and its own parameters as data-p-<name> attributes or form
// fields. The page's context — connection, node, guest type, VM, whether the
// connection is production and the name to type — sits on the element with
// data-virt. Nothing here is an inline handler: the CSP forbids them.
//
// Order of an action: the page's own confirmation (data-ask: a plain confirm;
// data-del: the house "type Delete" dialog), then on a production connection
// the name typed into #vprod, then POST /virt/act, then — when the hypervisor
// answers with a task — /virt/task polled until it finishes, then the page
// reloaded (or data-after followed). The server re-checks every gate; the page
// only saves a round trip.
(function () {
  'use strict';
  var root = document.querySelector('[data-virt]');
  if (!root) return;
  var ctx = root.dataset;
  var bar = document.getElementById('vstatus');
  var busy = false;

  function say(text, tone) {
    if (!bar) return;
    bar.hidden = !text;
    bar.className = 'vstatus' + (tone ? ' ' + tone : '');
    bar.textContent = text || '';
  }

  function snake(k) { return k.replace(/[A-Z]/g, function (c) { return '_' + c.toLowerCase(); }); }

  function params(el) {
    var out = {};
    Object.keys(el.dataset).forEach(function (k) {
      if (k.length > 1 && k[0] === 'p' && k[1] === k[1].toUpperCase()) {
        out[snake(k[1].toLowerCase() + k.slice(2))] = el.dataset[k];
      }
    });
    var form = el.tagName === 'FORM' ? el : null;
    if (form) {
      Array.prototype.forEach.call(form.elements, function (f) {
        if (!f.name || f.disabled) return;
        if (f.type === 'checkbox') out[f.name] = f.checked ? '1' : '0';
        else if (f.type !== 'file' && f.type !== 'submit') out[f.name] = f.value;
      });
    }
    return out;
  }

  function lock(on) {
    busy = on;
    document.querySelectorAll('[data-act]').forEach(function (b) {
      if (b.tagName === 'FORM') {
        Array.prototype.forEach.call(b.querySelectorAll('button'), function (x) {
          if (on) { x.dataset.wasDisabled = x.disabled ? '1' : ''; x.disabled = true; }
          else { x.disabled = x.dataset.wasDisabled === '1'; }
        });
      } else {
        if (on) { b.dataset.wasDisabled = b.disabled ? '1' : ''; b.disabled = true; }
        else { b.disabled = b.dataset.wasDisabled === '1'; }
      }
    });
  }

  // production: the name of what is about to change, typed. Resolves to the
  // typed text, or null when cancelled.
  function typed(name, what) {
    var dlg = document.getElementById('vprod');
    if (!dlg) return Promise.resolve(window.prompt('Type ' + name + ' to confirm') );
    var input = dlg.querySelector('input'), go = dlg.querySelector('[data-vprod-go]');
    dlg.querySelector('[data-vprod-name]').textContent = name;
    dlg.querySelector('[data-vprod-what]').textContent = what || 'make this change';
    input.value = ''; go.disabled = true;
    return new Promise(function (resolve) {
      function done(v) {
        go.removeEventListener('click', ok); dlg.removeEventListener('close', cancel);
        input.removeEventListener('input', check); input.removeEventListener('keydown', key);
        if (dlg.open) dlg.close();
        resolve(v);
      }
      function check() { go.disabled = input.value.trim() !== name; }
      function ok() { done(input.value.trim()); }
      function cancel() { done(null); }
      function key(e) { if (e.key === 'Enter' && !go.disabled) { e.preventDefault(); ok(); } }
      go.addEventListener('click', ok); dlg.addEventListener('close', cancel);
      input.addEventListener('input', check); input.addEventListener('keydown', key);
      dlg.showModal(); setTimeout(function () { input.focus(); }, 30);
    });
  }

  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

  async function poll(task, label) {
    var started = Date.now();
    for (;;) {
      await sleep(900);
      var r;
      try {
        r = await (await fetch('/virt/task?c=' + encodeURIComponent(ctx.c) +
          '&node=' + encodeURIComponent(ctx.node || '') +
          '&task=' + encodeURIComponent(task))).json();
      } catch (e) { r = { ok: false, error: String(e) }; }
      if (!r.ok) throw new Error(r.error || 'the task could not be read');
      if (r.state === 'success') return r;
      if (r.state === 'error') throw new Error(r.error || 'the hypervisor reported a failure');
      var secs = Math.round((Date.now() - started) / 1000);
      say(label + '… ' + (r.progress != null ? r.progress + '%' : secs + 's'), 'busy');
      if (Date.now() - started > 30 * 60 * 1000) throw new Error('still running after 30 minutes — see Tasks');
    }
  }

  function after(el, r, info) {
    var to = el.dataset.after;
    if (to) {
      to = to.replace('{c}', encodeURIComponent(ctx.c))
        .replace('{node}', encodeURIComponent(ctx.node || ''))
        .replace('{new_id}', encodeURIComponent(r.new_id || ''))
        .replace('{result}', encodeURIComponent((info && info.result) || r.new_id || ''));
      window.location.assign(to);
    } else {
      window.location.reload();
    }
  }

  // What an action takes down with it (app/chain.py), asked at the moment of
  // the click rather than when the page was drawn: a VM that became a
  // Kubernetes node five minutes ago must say so now. Never blocks the action:
  // no answer in five seconds is no warning, not no button.
  async function impactOf(el) {
    if (!el.dataset.impact) return '';
    say('Checking what this affects…', 'busy');
    var ctl = window.AbortController ? new AbortController() : null;
    var timer = ctl ? setTimeout(function () { ctl.abort(); }, 5000) : null;
    try {
      var r = await (await fetch(el.dataset.impact, ctl ? { signal: ctl.signal } : {})).json();
      return (r && r.ok && r.text) || '';
    } catch (e) {
      return '';
    } finally {
      if (timer) clearTimeout(timer);
      say('', '');
    }
  }

  async function act(el) {
    if (busy || el.disabled) return;
    var impact = await impactOf(el);
    if (el.dataset.del) { if (!(await window.confirmDelete(el.dataset.del, impact))) return; }
    else if (el.dataset.ask) {
      if (!window.confirm(el.dataset.ask + (impact ? '\n\n' + impact : ''))) return;
    } else if (impact && !window.confirm(impact + '\n\nGo ahead?')) return;
    var confirmText = '';
    var label = el.dataset.label || el.textContent.trim() || 'Working';
    if (ctx.prod === '1') {
      var name = el.dataset.target || ctx.prodname || '';
      confirmText = await typed(name, label.toLowerCase());
      if (confirmText === null) return;
    }
    var body = Object.assign({ c: ctx.c, node: ctx.node || '', kind: ctx.kind || '',
      vm: ctx.vm || '', action: el.dataset.act, confirm: confirmText }, params(el));
    lock(true);
    say(label + '…', 'busy');
    var r;
    try {
      r = await (await fetch(ctx.endpoint || '/virt/act', { method: 'POST',
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })).json();
    } catch (e) { r = { ok: false, error: String(e) }; }
    if (!r.ok) { lock(false); say('✕ ' + (r.error || 'refused'), 'err'); return; }
    var info = null;
    if (r.task) {
      try { info = await poll(r.task, label); }
      catch (e) { lock(false); say('✕ ' + e.message, 'err'); return; }
    }
    // a follow-on action (create, then power on) chained by the form
    if (el.dataset.then && el.dataset.thenIf && body[el.dataset.thenIf] === '1') {
      var vmid = (info && info.result) || r.new_id;
      say(label + ' — done. Powering on…', 'busy');
      var r2;
      try {
        r2 = await (await fetch('/virt/act', { method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ c: ctx.c, node: body.node || ctx.node || '',
            kind: 'qemu', vm: vmid, action: el.dataset.then, confirm: confirmText }) })).json();
        if (r2.ok && r2.task) await poll(r2.task, 'Powering on');
      } catch (e) { /* the VM exists; say so and go to it */ }
    }
    say('✓ ' + label + ' — done', 'ok');
    setTimeout(function () { after(el, r, info); }, 450);
  }

  document.addEventListener('click', function (e) {
    var b = e.target.closest('[data-act]');
    if (!b || b.tagName === 'FORM') return;
    e.preventDefault();
    act(b);
  });
  document.addEventListener('submit', function (e) {
    var f = e.target.closest('form[data-act]');
    if (!f) return;
    e.preventDefault();
    act(f);
  });

  // Links set by hand between the layers (app/chain.py): a form carrying
  // data-link="/bmc/link" or "/virt/link", its fixed side in hidden fields,
  // the other side in a select, and buttons named link whose value says what
  // to do: link, none (not linked, whatever matches) or auto.
  document.addEventListener('click', function (e) {
    var b = e.target.closest('form[data-link] button[name=link]');
    if (!b || busy) return;
    e.preventDefault();
    var f = b.form, body = { action: b.value };
    Array.prototype.forEach.call(f.elements, function (x) {
      if (x.name && x.name !== 'link' && !x.disabled) body[x.name] = x.value;
    });
    if (b.value === 'link' && !(body.server && body.host || body.vm && body.node)) {
      say('✕ choose what to link first', 'err'); return;
    }
    lock(true); say('Saving…', 'busy');
    fetch(f.dataset.link, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body) }).then(function (r) { return r.json(); }).then(function (r) {
      if (!r.ok) { lock(false); say('✕ ' + (r.error || 'refused'), 'err'); return; }
      say('✓ ' + (r.said || 'saved'), 'ok');
      setTimeout(function () { window.location.reload(); }, 450);
    }).catch(function (err) { lock(false); say('✕ ' + err, 'err'); });
  });

  // a console opens in its own window, sized for a screen
  document.addEventListener('click', function (e) {
    var a = e.target.closest('a[data-console]');
    if (!a || a.getAttribute('aria-disabled') === 'true') return;
    e.preventDefault();
    window.open(a.href, 'console-' + (a.dataset.console || ''),
      'popup=yes,width=1100,height=780');
  });

  // uploads: one file at a time, straight to /virt/upload with progress
  var up = document.querySelector('[data-virt-upload]');
  if (up) {
    var file = up.querySelector('input[type=file]');
    var go = up.querySelector('button');
    file.addEventListener('change', function () { go.disabled = !file.files.length; });
    up.addEventListener('submit', async function (e) {
      e.preventDefault();
      if (busy || !file.files.length) return;
      var f = file.files[0];
      var confirmText = '';
      if (ctx.prod === '1') {
        confirmText = await typed(ctx.prodname || '', 'upload ' + f.name);
        if (confirmText === null) return;
      }
      var q = new URLSearchParams({ c: ctx.c, node: ctx.node || '', ds: up.dataset.ds || '',
        path: up.dataset.path || '', name: f.name, confirm: confirmText });
      var xhr = new XMLHttpRequest();
      xhr.open('POST', '/virt/upload?' + q.toString());
      xhr.setRequestHeader('Content-Type', 'application/octet-stream');
      xhr.upload.onprogress = function (ev) {
        if (ev.lengthComputable) say('Uploading ' + f.name + '… ' +
          Math.round(ev.loaded / ev.total * 100) + '%', 'busy');
      };
      xhr.onload = function () {
        var r = {};
        try { r = JSON.parse(xhr.responseText); } catch (err) { r = { ok: false, error: 'HTTP ' + xhr.status }; }
        lock(false);
        if (r.ok) { say('✓ Uploaded ' + f.name, 'ok'); setTimeout(function () { window.location.reload(); }, 450); }
        else say('✕ ' + (r.error || 'the upload failed'), 'err');
      };
      xhr.onerror = function () { lock(false); say('✕ the upload was interrupted', 'err'); };
      lock(true);
      say('Uploading ' + f.name + '…', 'busy');
      xhr.send(f);
    });
  }
})();
