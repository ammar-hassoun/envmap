/* EnvMap Move: the move form (templates/virt_move.html), a move's progress
 * (virt_move_job.html) and the list of moves (virt_moves.html). Text is put on
 * the page with textContent only: the log carries lines from the guest. */
(function () {
  'use strict';

  function $(sel, root) { return (root || document).querySelector(sel); }
  function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }
  async function post(url, body) {
    try {
      var r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body) });
      return await r.json();
    } catch (e) { return { ok: false, error: String(e) }; }
  }
  function when(t) {
    if (!t) return '';
    var d = new Date(t * 1000);
    // the long form, day first: 27 November 2026, 14:05
    return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' }) + ', ' +
      d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
  }
  var LABEL = { starting: 'starting', preparing: 'preparing', copying: 'copying',
    frozen: 'crossing', stuck: 'waiting for you', finishing: 'finishing', done: 'moved',
    undone: 'undone', failed: 'failed' };
  function stateTone(s) {
    return s === 'done' ? 'ok' : (s === 'failed' || s === 'stuck') ? 'bad' : s === 'undone' ? 'warn' : 'run';
  }

  /* ── the list ─────────────────────────────────────────────── */
  $$('td[data-when]').forEach(function (td) { td.textContent = when(+td.dataset.when); td.classList.remove('mono'); });
  $$('.mv-state[data-s]').forEach(function (s) {
    s.dataset.tone = stateTone(s.dataset.s);
    s.textContent = LABEL[s.dataset.s] || s.dataset.s;
  });

  $$('[data-forget-key]').forEach(function (b) {
    b.addEventListener('click', async function () {
      if (!window.confirm('Forget the SSH key of ' + b.dataset.forgetWhat + '? The next contact is trusted as a first one.')) return;
      b.disabled = true;
      var r = await post('/virt/moves/forget-key', { id: b.dataset.forgetKey });
      if (r.ok) location.reload(); else { b.disabled = false; window.alert(r.error || 'refused'); }
    });
  });

  /* ── the form ─────────────────────────────────────────────── */
  var box = $('[data-move]');
  var form = $('[data-move-form]');
  if (box && form) {
    var targets = [];
    try { targets = JSON.parse(box.dataset.targets || '[]'); } catch (e) { targets = []; }
    var to = $('#mv_to'), nodeSel = $('#mv_node'), store = $('#mv_store'), iso = $('#mv_iso');
    var sayEl = $('[data-move-say]');
    var plan = $('[data-move-plan]');
    function say(t, tone) { sayEl.textContent = t || ''; sayEl.dataset.tone = tone || ''; }
    function target() { return targets.filter(function (t) { return t.id === to.value; })[0] || {}; }
    function fill(sel, items, keep, empty) {
      var was = keep || sel.value;
      sel.textContent = '';
      if (empty) sel.appendChild(new Option(empty, ''));
      items.forEach(function (it) {
        var o = new Option(it.label, it.value);
        if (it.value === was) o.selected = true;
        sel.appendChild(o);
      });
      // the page's themed dropdown (base.html) shows what the select holds now
      if (sel._ddRefresh) sel._ddRefresh();
    }
    async function choices() {
      var t = target();
      $$('[data-pve-only]').forEach(function (e) { e.hidden = t.flavor !== 'proxmox'; });
      $('[data-store-label]').textContent = t.flavor === 'proxmox' ? 'Storage for the disks' : 'Datastore';
      if (t.flavor === 'proxmox') {
        fill(nodeSel, (t.nodes || []).map(function (n) { return { label: n, value: n }; }), nodeSel.value || box.dataset.node);
      }
      plan.hidden = true;
      say('reading ' + (t.name || 'the target') + '…');
      var q = '/virt/move/choices?to=' + encodeURIComponent(t.id || '') +
        '&node=' + encodeURIComponent(t.flavor === 'proxmox' ? nodeSel.value : '');
      var r;
      try { r = await (await fetch(q)).json(); } catch (e) { r = { ok: false, error: String(e) }; }
      if (!r.ok) { say('✕ ' + (r.error || 'could not read the target'), 'err'); return; }
      fill(store, (r.storages || []).map(function (s) {
        return { label: s.name + (s.free_gib != null ? ' · ' + s.free_gib + ' GiB free' : ''), value: s.name };
      }));
      if (iso) fill(iso, (r.iso_storages || []).map(function (s) { return { label: s.name, value: s.name }; }));
      var nets = (r.networks || []).map(function (n) { return { label: n, value: n }; });
      $$('select[data-net]').forEach(function (s) {
        var was = s.dataset.was;
        var pick = nets.some(function (n) { return n.value === was; }) ? was :
          (nets.some(function (n) { return n.value === 'vmbr0'; }) ? 'vmbr0' :
            (nets.some(function (n) { return n.value === 'VM Network'; }) ? 'VM Network' : ''));
        fill(s, nets, s.value || pick, '— choose —');
      });
      fill($('[data-tnet]'), nets, '', 'same as its first card');
      say('');
    }
    function body() {
      var b = { c: box.dataset.c, vm: box.dataset.vm, node: box.dataset.node };
      new FormData(form).forEach(function (v, k) { b[k] = v; });
      return b;
    }
    function routed() {
      var on = (form.querySelector('input[name=transfer_mode]:checked') || {}).value === 'routed';
      $$('[data-routed]').forEach(function (e) { e.hidden = !on; });
    }
    function list(ul, items, cls) {
      ul.textContent = '';
      items.forEach(function (t) { ul.appendChild(el('li', cls, t)); });
      ul.hidden = !items.length;
    }
    async function check() {
      var btn = $('[data-move-check]');
      btn.disabled = true;
      var isOff = box.dataset.off === '1';
      say(isOff ? 'checking: reading the VM and looking at the two hosts…'
        : 'checking: reading the VM, asking the guest, looking at the target…');
      var r = await post('/virt/move/check', body());
      btn.disabled = false;
      if (!r.ok) { say('✕ ' + (r.error || 'the check failed'), 'err'); plan.hidden = true; return; }
      var p = r.plan;
      say(p.ok ? '✓ ready to move' : '✕ not possible yet: see below', p.ok ? 'ok' : 'err');
      plan.hidden = false;
      list($('[data-plan-problems]'), p.problems || [], 'bad');
      list($('[data-plan-notes]'), p.notes || [], 'note');
      var f = $('[data-plan-facts]');
      f.textContent = '';
      var rows = [
        p.mode === 'off' ? ['Moved', 'powered off: its disks are copied and read back; it is not started']
          : ['Guest', (p.src.os || '?') + (p.src.kernel ? ' · kernel ' + p.src.kernel : '')],
        ['New VM', p.dst.conn_name + (p.dst.node ? ' · ' + p.dst.node : '') + ' · disks on ' + p.dst.storage],
        ['Disks', (p.src.disks || []).map(function (d) { return d.key + ' ' + d.gib + ' GiB'; }).join(', ') || '—'],
        ['Disk controllers', p.mode === 'off' ? (p.cross ? 'the nearest types the other hypervisor has' : 'the same as now')
          : (p.cross ? 'change type: storage re-pointed on arrival' : 'the same, kept through the move')],
        ['Transfer', p.transfer.src_ip + ' → ' + p.transfer.dst_ip + (p.transfer.mode === 'auto' ? ' (link-local, for the move only)' : '')]
      ];
      rows.forEach(function (row) {
        var d = el('div'); d.appendChild(el('span', '', row[0])); d.appendChild(el('b', '', row[1])); f.appendChild(d);
      });
      var go = $('[data-plan-go]');
      go.hidden = !p.ok;
      var prod = p.src.production || p.dst.production;
      $('[data-plan-prod]').hidden = !prod;
      $('[data-plan-name]').textContent = p.src.name;
    }
    async function start() {
      var btn = $('[data-move-start]');
      btn.disabled = true;
      say('starting…');
      var b = body();
      b.confirm = ($('#mv_confirm') || {}).value || '';
      var r = await post('/virt/move/start', b);
      if (!r.ok) { btn.disabled = false; say('✕ ' + (r.error || 'the move did not start'), 'err'); return; }
      location.href = '/virt/moves/job?id=' + encodeURIComponent(r.id);
    }
    to.addEventListener('change', function () { nodeSel.value = ''; choices(); });
    nodeSel.addEventListener('change', choices);
    form.addEventListener('change', function (e) {
      if (e.target.name === 'transfer_mode') routed();
      else if (e.target !== to && e.target !== nodeSel) { plan.hidden = true; }
    });
    $('[data-move-check]').addEventListener('click', check);
    $('[data-move-start]').addEventListener('click', start);
    routed();
    choices();
  }

  /* ── one move's progress ──────────────────────────────────── */
  var job = $('[data-move-job]');
  if (job) {
    var id = job.dataset.id, seen = 0, t0 = null;
    var isOffJob = job.dataset.mode === 'off';
    var ORDER = isOffJob ? ['preparing', 'copying', 'finishing', 'done']
      : ['preparing', 'copying', 'frozen', 'finishing', 'done'];
    function size(n) {
      n = +n || 0;
      return n >= 1073741824 ? (n / 1073741824).toFixed(1) + ' GiB' : Math.round(n / 1048576) + ' MiB';
    }
    var started = $('[data-job-started]');
    if (started) started.textContent = '· ' + when(+started.dataset.t);
    function stamp(t) {
      if (t0 === null) t0 = t;
      var s = Math.max(0, Math.round(t - t0));
      return (s >= 60 ? Math.floor(s / 60) + 'm ' : '') + (s % 60) + 's';
    }
    function paint(j) {
      var st = $('[data-job-state]');
      st.textContent = LABEL[j.state] || j.state;
      st.dataset.tone = stateTone(j.state);
      var reached = ORDER.indexOf(j.state === 'stuck' ? 'frozen' : j.state);
      $$('.mv-step').forEach(function (s) {
        var i = ORDER.indexOf(s.dataset.step);
        s.dataset.at = (j.state === 'undone' || j.state === 'failed') ? (j.times && j.times[s.dataset.step] ? 'past' : 'no') :
          i < reached ? 'past' : i === reached ? (j.state === 'done' ? 'past' : 'now') : 'later';
      });
      var ban = $('[data-job-banner]');
      var msg = (isOffJob ? {
        done: '✓ Moved: the new VM carries its name and is powered off, as the VM was. Every byte of its disks was read back from the new storage. The old VM is kept, renamed, until you delete it.',
        undone: '↺ Undone: the VM is powered off where it was. What was made for the move was removed.',
        failed: '✕ The move did not complete; nothing changed for the VM. See what is left below.' } : {
        done: '✓ Moved: it runs on the new VM, which now carries its name. The old VM is kept, powered off and renamed, until you delete it.',
        undone: '↺ Undone: the VM carries on where it was. What was built for the move was removed.',
        failed: '✕ The move could not start; nothing changed for the VM.',
        stuck: '⚠ The move needs you: see below.' })[j.state];
      var copy = $('[data-job-copy]');
      if (copy) {
        var g = j.progress || {}, going = ['starting', 'preparing', 'copying'].indexOf(j.state) !== -1;
        copy.hidden = !(going || (j.state === 'finishing' && g.total));
        $('[data-job-stop]').hidden = !going;
        var frac = g.total ? Math.min(1, ((+g.done || 0) + (+g.checked || 0)) / (2 * g.total)) : 0;
        $('[data-job-bar]').style.width = (Math.round(frac * 1000) / 10) + '%';
        $('[data-job-numbers]').textContent = g.total
          ? (g.step ? g.step.charAt(0).toUpperCase() + g.step.slice(1) + ' · ' : '') + size(g.done) + ' of ' + size(g.total) +
            ' read on the old host, ' + size(g.sent) + ' sent (zeros are not sent), ' + size(g.checked) + ' read back on the new host' +
            (g.breaks ? ' · ' + g.breaks + ' connection break' + (g.breaks > 1 ? 's' : '') + ', carried on' : '')
          : 'The two helpers are being made and started.';
      }
      ban.hidden = !msg;
      if (msg) { ban.textContent = msg; ban.className = 'flash' + (j.state === 'done' ? '' : j.state === 'undone' ? ' warn' : ' err'); }
      $('[data-job-decide]').hidden = isOffJob || !(j.state === 'stuck' || j.state === 'frozen');
      var ol = $('[data-job-log]');
      // follow the newest line, unless the person scrolled up to read
      var follow = !seen || ol.scrollHeight - ol.scrollTop - ol.clientHeight < 40;
      (j.log || []).slice(seen).forEach(function (e) {
        var li = el('li', 'k-' + (e.kind || 'step'));
        li.appendChild(el('span', 'tm', stamp(e.t)));
        li.appendChild(el('span', 'tx', e.text));
        ol.appendChild(li);
      });
      seen = (j.log || []).length;
      if (follow) ol.scrollTop = ol.scrollHeight;
    }
    async function tick() {
      var r;
      try { r = await (await fetch('/virt/moves/state?id=' + encodeURIComponent(id))).json(); } catch (e) { r = null; }
      if (r && r.ok) {
        paint(r.job);
        if (['done', 'undone', 'failed'].indexOf(r.job.state) >= 0 && !r.job.running) return;
      }
      setTimeout(tick, document.hidden ? 6000 : 2000);
    }
    $$('[data-decide]').forEach(function (b) {
      b.addEventListener('click', async function () {
        var what = b.dataset.decide;
        var ask = what === 'stop' ? 'Stop the move? It is undone: the helpers and the new VM are removed, and the VM stays as it is.' :
          what === 'back' ? 'Restart the new VM so the VM carries on where it was?' :
          'Power the old copy off and keep the VM on the new one?';
        if (!window.confirm(ask)) return;
        var confirmName = '';
        if (job.dataset.prod === '1' && what !== 'stop') {
          confirmName = window.prompt('A production hypervisor is involved: type the VM name to confirm') || '';
          if (!confirmName) return;
        }
        $$('[data-decide]').forEach(function (x) { x.disabled = true; });
        var r = await post('/virt/moves/decide', { id: id, what: what, confirm: confirmName });
        $$('[data-decide]').forEach(function (x) { x.disabled = false; });
        if (!r.ok) window.alert(r.error || 'refused');
      });
    });
    tick();
  }
})();
