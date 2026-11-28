/* VM migration (templates/virt_migrate.html): two hosts side by side, an arrow
 * between them, and the moves under way.
 *
 * Every name here comes from a hypervisor or from a guest, so text is put on
 * the page with textContent only. The server decides what a move needs
 * (/virt/migrate/go); this script only asks, and shows what came back. */
(function () {
  'use strict';
  var root = document.querySelector('[data-migrate]');
  if (!root) return;

  function $(sel, r) { return (r || document).querySelector(sel); }
  function $$(sel, r) { return Array.prototype.slice.call((r || document).querySelectorAll(sel)); }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = text;
    return e;
  }
  function enc(v) { return encodeURIComponent(v || ''); }
  function cap(t) { return t ? t.charAt(0).toUpperCase() + t.slice(1) : ''; }
  async function getJSON(url) {
    try { return await (await fetch(url, { headers: { Accept: 'application/json' } })).json(); }
    catch (e) { return { ok: false, error: 'the page could not reach EnvMap (' + e + ')' }; }
  }
  async function post(url, body) {
    try {
      var r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body) });
      return await r.json();
    } catch (e) { return { ok: false, error: 'the page could not reach EnvMap (' + e + ')' }; }
  }

  var hosts = [];
  try { hosts = JSON.parse(root.dataset.hosts || '[]'); } catch (e) { hosts = []; }
  var byKey = {};
  hosts.forEach(function (h) { byKey[h.key] = h; });
  var ready = root.dataset.ready === '1';
  var S = { a: { host: null, vms: [], error: '', loading: false, find: '' },
            b: { host: null, vms: [], error: '', loading: false, find: '' } };
  var sel = null;          // the selected VM: { side, id }
  var busy = false;        // a check is on its way
  var pend = null;         // the move being asked about: { from, to, vm, name, fromSide }
  var jobs = {};           // the moves under way, by id
  var gone = {};           // tracks the person closed
  var sig = '';            // what the lists last showed of the moves
  var note = null;         // a line that stays a few seconds: { text, tone, until }
  var timer = null;

  function box(side) { return $('[data-side="' + side + '"]', root); }
  function other(side) { return side === 'a' ? 'b' : 'a'; }
  function sideName(side) { return side === 'a' ? 'left' : 'right'; }
  function vmOf(side, id) {
    return S[side].vms.filter(function (v) { return v.id === id; })[0] || null;
  }

  /* ── the two lists ────────────────────────────────────────── */
  function empty(ul, text, cls) {
    var li = el('li', 'mg-empty' + (cls ? ' ' + cls : ''), text);
    li.setAttribute('role', 'presentation');
    ul.appendChild(li);
  }
  function movingOf(side, v) {
    // the server's word when the list was read, and this page's own moves since
    if (v.moving && (!jobs[v.moving] || !ended(jobs[v.moving]))) return v.moving;
    var h = S[side].host, id = '';
    Object.keys(jobs).forEach(function (k) {
      var j = jobs[k];
      if (!ended(j) && h && j.from.key === h.key && String(j.vm) === String(v.id)) id = k;
    });
    return id;
  }
  function paintList(side) {
    var s = S[side], b = box(side), ul = $('[data-list]', b), sub = $('[data-sub]', b);
    var scroll = ul.scrollTop;
    ul.textContent = '';
    sub.textContent = '';
    sub.dataset.tone = '';
    $('[data-find]', b).disabled = !s.host;
    $('[data-reload]', b).disabled = !s.host || s.loading;
    if (!s.host) { empty(ul, 'Choose a host to see its VMs.'); return; }
    if (s.loading) { empty(ul, 'Reading ' + s.host.name + '…'); return; }
    if (s.error) { empty(ul, s.error, 'err'); return; }
    var running = s.vms.filter(function (v) { return v.live; }).length;
    sub.textContent = s.vms.length + (s.vms.length === 1 ? ' VM' : ' VMs') + ' · ' + running + ' running' +
      (s.host.why ? ' · ' + s.host.why : '');
    if (s.host.why) sub.dataset.tone = 'warn';
    // a VM on its way here is shown arriving, before the host itself lists it;
    // once the host lists the new VM, that row is the one that says so
    var listed = {};
    s.vms.forEach(function (v) { if (v.arriving) listed[v.arriving] = true; });
    Object.keys(jobs).forEach(function (k) {
      var j = jobs[k];
      if (ended(j) || j.to.key !== s.host.key || listed[k]) return;
      var g = el('li', 'mg-vm mg-ghost');
      g.setAttribute('role', 'presentation');
      g.appendChild(el('span', 'mg-dot'));
      var m = el('span', 'mg-main');
      m.appendChild(el('b', 'mg-name', j.name));
      m.appendChild(el('span', 'mg-meta', 'arriving from ' + j.from.name));
      g.appendChild(m);
      g.appendChild(el('span', 'mg-tag run', LABEL[j.state] || j.state));
      ul.appendChild(g);
    });
    var q = s.find.trim().toLowerCase();
    var shown = s.vms.filter(function (v) {
      return !q || (v.name + ' ' + v.ip + ' ' + v.id).toLowerCase().indexOf(q) !== -1;
    });
    if (!s.vms.length) empty(ul, 'This host has no VMs.');
    else if (!shown.length) empty(ul, 'No VM here matches “' + s.find.trim() + '”.');
    shown.forEach(function (v) {
      var moving = movingOf(side, v);
      var coming = v.arriving && jobs[v.arriving] && !ended(jobs[v.arriving]) ? jobs[v.arriving] : null;
      var why = moving ? 'it is being moved' : v.why;
      var li = el('li', 'mg-vm' + (coming ? ' mg-ghost' : ''));
      li.setAttribute('role', 'option');
      li.dataset.id = v.id;
      li.setAttribute('aria-selected', sel && sel.side === side && sel.id === v.id ? 'true' : 'false');
      if (why) { li.setAttribute('aria-disabled', 'true'); li.title = cap(why); } else li.tabIndex = 0;
      li.appendChild(el('span', 'mg-dot' + (v.live ? ' on' : '')));
      var main = el('span', 'mg-main');
      main.appendChild(el('b', 'mg-name', v.name));
      var meta = [];
      if (v.cores) meta.push(v.cores + ' vCPU');
      if (v.mem_gib) meta.push(v.mem_gib + ' GiB');
      if (v.ip) meta.push(v.ip);
      main.appendChild(el('span', 'mg-meta', coming ? 'arriving from ' + coming.from.name : (meta.join(' · ') || 'id ' + v.id)));
      li.appendChild(main);
      if (coming) li.appendChild(el('span', 'mg-tag run', LABEL[coming.state] || coming.state));
      else if (v.arriving) li.appendChild(el('span', 'mg-tag run', 'arriving'));
      else if (moving) li.appendChild(el('span', 'mg-tag run', 'moving'));
      else if (v.off && !v.why) li.appendChild(el('span', 'mg-tag', 'powered off'));
      else if (!v.live) li.appendChild(el('span', 'mg-tag', v.off ? 'cannot move' : 'not running'));
      else if (v.why) li.appendChild(el('span', 'mg-tag', 'cannot move'));
      ul.appendChild(li);
    });
    ul.scrollTop = scroll;
  }
  function markSel() {
    $$('.mg-vm[role=option]', root).forEach(function (li) {
      var side = li.closest('[data-side]').dataset.side;
      li.setAttribute('aria-selected', sel && sel.side === side && sel.id === li.dataset.id ? 'true' : 'false');
    });
  }
  function pick(side, id) {
    sel = (sel && sel.side === side && sel.id === id) ? null : { side: side, id: id };
    markSel();
    paintArrows();
  }
  async function load(side, refresh) {
    var s = S[side];
    if (!s.host) { s.vms = []; s.error = ''; paintList(side); paintArrows(); return; }
    var asked = s.host.key;
    s.loading = true; s.error = '';
    paintList(side); paintArrows();
    var r = await getJSON('/virt/migrate/vms?c=' + enc(s.host.conn) + '&node=' + enc(s.host.node) +
      (refresh ? '&refresh=1' : ''));
    if (!s.host || s.host.key !== asked) return;      // another host was chosen meanwhile
    s.loading = false;
    if (!r.ok) { s.vms = []; s.error = cap(r.error || 'this host could not be read'); }
    else s.vms = r.vms || [];
    if (sel && sel.side === side) {
      var v = vmOf(side, sel.id);
      if (!v || v.why || movingOf(side, v)) sel = null;
    }
    paintList(side); paintArrows();
  }
  function remember() {
    var a = S.a.host ? S.a.host.key : '', b = S.b.host ? S.b.host.key : '';
    try { history.replaceState(null, '', '/virt/migrate' + (a || b ? '?a=' + enc(a) + '&b=' + enc(b) : '')); }
    catch (e) { /* the address stays as it was */ }
    try { localStorage.setItem('vmmigrate.hosts', JSON.stringify([a, b])); } catch (e) { /* not kept */ }
  }
  function choose(side, key, quiet) {
    var s = S[side];
    s.host = byKey[key] && !byKey[key].off ? byKey[key] : null;
    s.find = '';
    $('[data-find]', box(side)).value = '';
    if (sel && sel.side === side) sel = null;
    closePanel();
    if (!quiet) remember();
    load(side);
    drawTracks();
  }

  /* ── the arrows ───────────────────────────────────────────── */
  function why(dir) {
    var from = dir === 'ab' ? 'a' : 'b', to = other(from);
    if (!ready) return root.dataset.engineWhy || 'EnvMap Move is not ready on this installation';
    if (!S[from].host) return 'choose a host on the ' + sideName(from);
    if (!sel || sel.side !== from) return 'select a VM on the ' + sideName(from);
    if (!S[to].host) return 'choose the host on the ' + sideName(to) + ', where the VM goes';
    if (S[from].host.key === S[to].host.key ||
        (S[from].host.flavor === 'esxi' && S[from].host.conn === S[to].host.conn))
      return 'both sides show the same host';
    if (S[from].host.why) return S[from].host.name + ': ' + S[from].host.why;
    if (S[to].host.why) return S[to].host.name + ': ' + S[to].host.why;
    if (busy) return 'a check is running';
    return '';
  }
  function say(text, tone) {
    var p = $('[data-say]', root);
    p.textContent = text || '';
    p.dataset.tone = tone || '';
  }
  function paintArrows() {
    ['ab', 'ba'].forEach(function (dir) {
      var b = $('[data-go="' + dir + '"]', root), w = why(dir);
      b.disabled = !!w;
      b.title = w ? cap(w) : 'Move it to the host on the ' + (dir === 'ab' ? 'right' : 'left');
    });
    var opt = $('[data-options]', root);
    if (busy) { opt.disabled = true; return; }
    if (!sel) {
      opt.disabled = true;
      if (note && Date.now() < note.until) say(note.text, note.tone);
      else say(S.a.host || S.b.host ? 'Select a VM, running or powered off, then click the arrow that points where it should go.'
        : 'Choose a host on each side.');
      return;
    }
    note = null;
    var dir = sel.side === 'a' ? 'ab' : 'ba', w = why(dir);
    var v = vmOf(sel.side, sel.id);
    opt.disabled = !!w;
    if (w) say(cap(w) + '.', 'warn');
    else if (v && v.off) say('Move ' + v.name + ' to ' + S[other(sel.side)].host.name +
      '. It is powered off: its disks are copied, and it is not started.');
    else say('Move ' + (v ? v.name : 'it') + ' to ' + S[other(sel.side)].host.name + '.');
  }

  /* ── asking for the move ──────────────────────────────────── */
  function start(dir, ask) {
    var from = dir === 'ab' ? 'a' : 'b', to = other(from);
    if (why(dir) || !sel) return;
    var v = vmOf(from, sel.id);
    if (!v) return;
    pend = { from: S[from].host, to: S[to].host, vm: v.id, name: v.name, fromSide: from, off: !!v.off };
    send({}, ask);
  }
  async function send(extra, ask) {
    if (!pend || busy) return;
    busy = true;
    paintArrows();
    say('Checking ' + pend.name + ' → ' + pend.to.name + (pend.off ? ': reading the VM and looking at the two hosts…'
      : ': reading the VM, asking the guest, looking at the target…'), 'run');
    panelSay(ask ? 'Reading the two hosts…' : 'Checking…');
    $('[data-panel-go]').disabled = true;
    var body = { c: pend.from.conn, vm: pend.vm, node: pend.from.node, to: pend.to.conn, dst_node: pend.to.node };
    Object.keys(extra || {}).forEach(function (k) { body[k] = extra[k]; });
    if (ask) body.ask = true;
    var r = await post('/virt/migrate/go', body);
    busy = false;
    $('[data-panel-go]').disabled = false;
    if (!r.ok) {
      panelSay('✕ ' + cap(r.error || 'the move did not start'), 'err');
      paintArrows();
      say('✕ ' + cap(r.error || 'the move did not start') + '.', 'err');
      return;
    }
    if (r.started) {
      if (body.save_signin && body.guest_password) pend.from.signin = true;
      closePanel();
      sel = null;
      markSel();
      note = { text: 'Started: ' + pend.name + ' is on its way to ' + pend.to.name + '.', tone: 'ok', until: Date.now() + 12000 };
      paintArrows();
      await tick();
      var t = $('[data-job="' + r.id + '"]');
      if (t && t.scrollIntoView) t.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
      return;
    }
    openPanel(r, extra || {});
    paintArrows();
    say('One thing before ' + pend.name + ' moves: see below.', 'warn');
  }

  /* ── the small box: only what could not be decided ─────────── */
  var panel = $('[data-panel]');
  function panelSay(text, tone) {
    var s = $('[data-panel-say]');
    s.textContent = text || '';
    s.dataset.tone = tone || '';
  }
  function closePanel() {
    if (panel) panel.hidden = true;
  }
  function items(ul, list, cls) {
    ul.textContent = '';
    (list || []).forEach(function (t) { ul.appendChild(el('li', cls, t)); });
    ul.hidden = !(list || []).length;
  }
  function field(form, label, control, note, tone) {
    var d = el('div', 'mg-field');
    var l = el('label', '', label);
    if (control.id) l.htmlFor = control.id;
    d.appendChild(l);
    d.appendChild(control);
    if (note) { var n = el('span', 'hint', note); if (tone) n.dataset.tone = tone; d.appendChild(n); }
    form.appendChild(d);
    return d;
  }
  function select(name, options, value, first) {
    var s = document.createElement('select');
    s.name = name; s.id = 'mgf_' + name;
    if (first) s.appendChild(new Option(first, ''));
    options.forEach(function (o) {
      var op = new Option(o.label, o.value);
      if (o.value === value) op.selected = true;
      s.appendChild(op);
    });
    return s;
  }
  function input(name, type, value, placeholder) {
    var i = document.createElement('input');
    i.name = name; i.id = 'mgf_' + name; i.type = type || 'text';
    i.value = value || ''; i.autocomplete = type === 'password' ? 'new-password' : 'off';
    i.spellcheck = false;
    if (placeholder) i.placeholder = placeholder;
    i.setAttribute('data-nosave', '');
    return i;
  }
  function openPanel(r, prev) {
    var form = $('[data-panel-form]'), needs = r.needs || {};
    form.textContent = '';
    $('[data-panel-title]').textContent = 'Move ' + pend.name + ' from ' + pend.from.name + ' to ' + pend.to.name;
    items($('[data-panel-problems]'), r.problems, 'bad');
    items($('[data-panel-notes]'), r.notes, 'note');
    // where the disks go
    var st = (r.storages || []).map(function (s) {
      return { label: s.name + (s.free_gib !== null && s.free_gib !== undefined ? ' · ' + s.free_gib + ' GiB free' : ''),
        value: s.name };
    });
    field(form, (r.flavors.dst === 'proxmox' ? 'Storage for the disks' : 'Datastore') + ' (' + r.disks_gib + ' GiB of disks)',
      select('storage', st, r.chosen.storage, st.length ? '' : '— none —'),
      needs.storage ? cap(needs.storage) : '', needs.storage ? 'err' : '');
    if (r.flavors.dst === 'proxmox') {
      field(form, r.power === 'stopped' ? 'Helper’s CD on' : 'Receiver CD on', select('iso_storage', (r.iso_storages || []).map(function (n) {
        return { label: n, value: n }; }), r.chosen.iso_storage));
    }
    // each card's network on the other host
    var nets = (r.networks || []).map(function (n) { return { label: n, value: n }; });
    (r.cards || []).forEach(function (c) {
      var asked = (needs.nets || []).indexOf(c.i) !== -1;
      var d = field(form, 'Network for card ' + (c.i + 1) + ' (' + c.mac + ', now on ' + (c.now || 'no network') + ')',
        select('net' + c.i, nets, c.network, '— choose —'),
        asked ? pend.to.name + ' has no network called ' + (c.now || 'that') + ': choose the one that carries the same addresses. It is remembered for these two hosts.'
          : (c.how && c.how !== 'chosen' ? 'Chosen for you: ' + c.how + '.' : ''), asked ? 'warn' : '');
      if (r.flavors.dst === 'proxmox') {
        var v = input('vlan' + c.i, 'number', c.vlan, 'VLAN tag, if any');
        v.min = 1; v.max = 4094;
        d.appendChild(v);
      }
    });
    // the VM's own sign-in, on ESXi. A VM that is powered off is not signed in to: nothing runs in it
    if (r.flavors.src === 'esxi' && r.power !== 'stopped') {
      var refused = needs.signin === 'refused', none = needs.signin === 'none';
      var wrap = el('div', 'mg-signin');
      var saved = r.signin === 'saved' && !refused;
      var fields = el('div', 'mg-signin-f');
      var u = input('guest_user', 'text', prev.guest_user || 'root');
      var pw = input('guest_password', 'password', '');
      var lu = el('label', '', 'User inside the VM'); lu.htmlFor = u.id;
      var lp = el('label', '', 'Password'); lp.htmlFor = pw.id;
      var fu = el('div', 'mg-field'); fu.appendChild(lu); fu.appendChild(u);
      var fp = el('div', 'mg-field'); fp.appendChild(lp); fp.appendChild(pw);
      fields.appendChild(fu); fields.appendChild(fp);
      var keep = el('label', 'chk');
      var cb = document.createElement('input');
      cb.type = 'checkbox'; cb.name = 'save_signin'; cb.checked = !pend.from.signin;
      keep.appendChild(cb);
      keep.appendChild(document.createTextNode(' Save it for the VMs on ' + pend.from.name +
        (pend.from.signin ? ', in place of the one saved now' : ', so it is not asked again')));
      fields.appendChild(keep);
      var head = el('p', 'mg-signin-say');
      if (saved) {
        head.textContent = 'The VM’s own sign-in: the one saved for the VMs on ' + (r.saved_for || pend.from.name) + '. ';
        var alt = el('button', 'mg-link', 'Use another for this VM');
        alt.type = 'button';
        alt.addEventListener('click', function () { fields.hidden = false; alt.hidden = true; pw.focus(); });
        head.appendChild(alt);
        fields.hidden = true;
      } else if (refused) {
        head.textContent = pend.name + ' refused the sign-in' + (r.signin === 'saved' ? ' saved for the VMs on ' +
          (r.saved_for || pend.from.name) : '') + '. Type the one this VM takes.';
        head.dataset.tone = 'err';
      } else if (none) {
        head.textContent = 'The move starts inside the VM, so EnvMap signs in to it: root, or a user who may use sudo ' +
          'without a password. This is the VM’s own sign-in, not the host’s.';
      } else {
        head.textContent = 'The VM’s own sign-in, typed for this move.';
      }
      wrap.appendChild(head);
      wrap.appendChild(fields);
      form.appendChild(wrap);
    }
    // a production hypervisor asks for the name
    if (needs.confirm !== undefined || (prev.confirm !== undefined && prev.confirm !== '')) {
      field(form, 'A production hypervisor is involved: type ' + (needs.confirm || pend.name) + ' to confirm',
        input('confirm', 'text', prev.confirm || ''));
    }
    $$('select', form).forEach(function (s) { if (window.enhanceSelect) window.enhanceSelect(s); });
    $('[data-panel-full]').href = '/virt/move?c=' + enc(pend.from.conn) + '&vm=' + enc(pend.vm) + '&node=' + enc(pend.from.node);
    panelSay('');
    panel.hidden = false;
    if (panel.scrollIntoView) panel.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    // the cursor goes to what is being asked for
    var want = $('#mgf_guest_password', form);
    if (!want || want.closest('[hidden]')) want = needs.confirm !== undefined ? $('#mgf_confirm', form) : null;
    if (want) want.focus({ preventScroll: true });
  }
  function values() {
    var out = {};
    var form = $('[data-panel-form]');
    $$('select, input', form).forEach(function (i) {
      if (!i.name || i.closest('[hidden]')) return;
      if (i.type === 'checkbox') { if (i.checked) out[i.name] = true; }
      else out[i.name] = i.value;
    });
    if (!out.guest_password) { delete out.guest_user; delete out.save_signin; }
    return out;
  }

  /* ── the moves under way ──────────────────────────────────── */
  var LABEL = { starting: 'starting', preparing: 'preparing', copying: 'copying', frozen: 'crossing',
    stuck: 'waiting for you', finishing: 'finishing', done: 'moved', undone: 'undone', failed: 'failed' };
  var STEP = { starting: 4, preparing: 12, frozen: 84, stuck: 84, finishing: 94, done: 100, undone: 0, failed: 0 };
  function ended(j) { return ['done', 'undone', 'failed'].indexOf(j.state) !== -1 && !j.running; }
  function tone(s) { return s === 'done' ? 'ok' : (s === 'failed' || s === 'stuck') ? 'bad' : s === 'undone' ? 'warn' : 'run'; }
  function size(n) {
    n = +n || 0;
    return n >= 1073741824 ? (n / 1073741824).toFixed(1) + ' GiB' : Math.round(n / 1048576) + ' MiB';
  }
  function progress(j) {
    var g = j.progress || {};
    if (j.mode === 'off' && j.state === 'copying' && g.total) {
      // a powered-off move says how far it is: every byte is read once on the old host and once more on the new
      return 14 + 78 * Math.min(1, ((+g.done || 0) + (+g.checked || 0)) / (2 * g.total));
    }
    if (j.state === 'copying') {
      // how far a copy is cannot be known from here: it creeps, and never claims the end
      var t = Math.max(0, Date.now() / 1000 - ((j.times || {}).copying || j.created));
      return 20 + 56 * (1 - Math.exp(-t / 150));
    }
    return STEP[j.state] === undefined ? 4 : STEP[j.state];
  }
  function took(j) {
    var end = ended(j) ? Math.max((j.times || {}).done || 0, (j.times || {}).undone || 0, (j.times || {}).failed || 0) : Date.now() / 1000;
    var s = Math.max(0, Math.round(end - j.created));
    return (s >= 3600 ? Math.floor(s / 3600) + 'h ' : '') + (s >= 60 ? Math.floor(s % 3600 / 60) + 'm ' : '') + (s % 60) + 's';
  }
  function story(j) {
    if (j.mode === 'off') {
      var g = j.progress || {};
      if (j.state === 'done') return '✓ Moved: it is on ' + j.to.name + ', powered off as it was. Every byte was read back from the new storage. The old VM is kept on ' + j.from.name + ', renamed, until you delete it.';
      if (j.state === 'undone') return '↺ Undone: the VM is powered off where it was, on ' + j.from.name + '. What was made for the move was removed.';
      if (j.state === 'failed') return '✕ The move did not complete; nothing changed for the VM. ' + cap(j.last || '');
      if (j.state === 'copying' && g.total) {
        return cap(g.step || 'copying') + ' · ' + size(g.done) + ' of ' + size(g.total) + ' read' +
          (g.sent ? ', ' + size(g.sent) + ' sent (zeros are not sent)' : '') +
          (g.checked ? ', ' + size(g.checked) + ' read back' : '') +
          (g.breaks ? ' · ' + g.breaks + ' connection break' + (g.breaks > 1 ? 's' : '') + ', carried on' : '');
      }
      return j.last || '';
    }
    if (j.state === 'done') return '✓ Moved: it runs on ' + j.to.name + '. The old VM is kept on ' + j.from.name + ', powered off and renamed, until you delete it.';
    if (j.state === 'undone') return '↺ Undone: the VM carries on where it was, on ' + j.from.name + '. What was built for the move was removed.';
    if (j.state === 'failed') return '✕ The move could not start; nothing changed for the VM. ' + cap(j.last || '');
    if (j.state === 'stuck') return '⚠ This move needs you: open Details to bring the VM back or keep it on the new host. ' + cap(j.last || '');
    if (j.state === 'frozen') return 'The VM is paused for a moment while its memory crosses.';
    return j.last || '';
  }
  function drawTracks() {
    var host = $('[data-tracks]');
    if (!host) return;
    var ids = Object.keys(jobs).filter(function (k) { return !gone[k]; })
      .sort(function (x, y) { return jobs[y].created - jobs[x].created; });
    $$('[data-job]', host).forEach(function (t) { if (ids.indexOf(t.dataset.job) === -1) t.remove(); });
    ids.forEach(function (k) {
      var j = jobs[k], t = $('[data-job="' + k + '"]', host);
      if (!t) {
        t = el('div', 'card mg-track');
        t.dataset.job = k;
        var top = el('div', 'mg-track-top');
        top.appendChild(el('b', 'mg-track-name'));
        top.appendChild(el('span', 'mv-state'));
        top.appendChild(el('span', 'hint mg-track-time'));
        var sp = el('span'); sp.style.flex = '1'; top.appendChild(sp);
        var stop = el('button', 'mg-link mg-stop', 'Stop'); stop.type = 'button';
        stop.title = 'Stop this move. It is undone: the VM was not changed.';
        stop.addEventListener('click', async function () {
          if (!window.confirm('Stop moving ' + jobs[k].name + '? The move is undone: the helpers and the new VM are removed, and the VM stays as it is.')) return;
          stop.disabled = true;
          var r = await post('/virt/moves/decide', { id: k, what: 'stop' });
          stop.disabled = false;
          if (!r.ok) window.alert(cap(r.error || 'it could not be stopped'));
          else tick();
        });
        top.appendChild(stop);
        var a = el('a', 'mg-link', 'Details'); a.href = '/virt/moves/job?id=' + enc(k); top.appendChild(a);
        var x = el('button', 'mg-x', '×'); x.type = 'button'; x.title = 'Take this off the page';
        x.setAttribute('aria-label', 'Take this move off the page');
        x.addEventListener('click', function () { gone[k] = true; drawTracks(); });
        top.appendChild(x);
        t.appendChild(top);
        var lane = el('div', 'mg-lane');
        lane.appendChild(el('span', 'mg-end mg-from'));
        var rail = el('div', 'mg-rail');
        rail.appendChild(el('div', 'mg-fill'));
        var chip = el('div', 'mg-chip');
        chip.appendChild(el('span', 'mg-chip-dot'));
        chip.appendChild(el('span', 'mg-chip-name'));
        rail.appendChild(chip);
        lane.appendChild(rail);
        lane.appendChild(el('span', 'mg-end mg-to'));
        t.appendChild(lane);
        t.appendChild(el('p', 'mg-last'));
        host.appendChild(t);
        // from the start of the rail to where it is: the first paint is the journey so far
        t.style.setProperty('--p', '0');
        void t.offsetWidth;
      }
      // a move towards the left box is drawn right to left, so the VM travels the way it goes
      var rev = S.a.host && S.b.host && j.from.key === S.b.host.key && j.to.key === S.a.host.key;
      t.classList.toggle('rev', !!rev);
      t.dataset.state = j.state;
      t.dataset.tone = tone(j.state);
      $('.mg-track-name', t).textContent = j.name;
      var st = $('.mv-state', t);
      st.textContent = j.mode === 'off' && j.state === 'copying' ? 'copying disks' : (LABEL[j.state] || j.state);
      st.dataset.tone = tone(j.state);
      $('.mg-stop', t).hidden = !(j.mode === 'off' && ['starting', 'preparing', 'copying'].indexOf(j.state) !== -1);
      $('.mg-track-time', t).textContent = took(j);
      $('.mg-from', t).textContent = j.from.name;
      $('.mg-to', t).textContent = j.to.name;
      $('.mg-chip-name', t).textContent = j.name;
      $('.mg-x', t).hidden = !ended(j);
      var last = $('.mg-last', t);
      last.textContent = story(j);
      last.dataset.kind = j.state === 'copying' || j.state === 'preparing' ? (j.last_kind || '') : '';
      t.style.setProperty('--p', String(Math.round(progress(j) * 10) / 10));
    });
  }
  async function tick() {
    if (timer) { clearTimeout(timer); timer = null; }
    var r = await getJSON('/virt/migrate/active');
    if (r.ok) {
      var was = jobs, now = {}, finished = [];
      (r.jobs || []).forEach(function (j) {
        now[j.id] = j;
        if (ended(j) && was[j.id] && !ended(was[j.id])) finished.push(j);
      });
      jobs = now;
      drawTracks();
      // the lists show who is moving and who is arriving: drawn again only when that changes
      var s = Object.keys(jobs).map(function (k) { return k + ':' + jobs[k].state + ':' + (jobs[k].running ? 1 : 0); }).join(',');
      // (a powered-off move's own numbers change every few seconds: the track shows them, the lists need not)
      if (s !== sig) {
        sig = s;
        if (!S.a.loading) paintList('a');
        if (!S.b.loading) paintList('b');
        paintArrows();
      }
      // a move that has just ended changed both hosts: read them again
      finished.forEach(function (j) {
        ['a', 'b'].forEach(function (side) {
          var h = S[side].host;
          if (h && (h.key === j.from.key || h.key === j.to.key)) load(side, true);
        });
      });
    }
    var live = Object.keys(jobs).some(function (k) { return !ended(jobs[k]); });
    timer = setTimeout(tick, live ? (document.hidden ? 6000 : 2000) : 15000);
  }

  /* ── wiring ───────────────────────────────────────────────── */
  ['a', 'b'].forEach(function (side) {
    var b = box(side), ul = $('[data-list]', b);
    $('[data-host]', b).addEventListener('change', function (e) { choose(side, e.target.value); });
    $('[data-reload]', b).addEventListener('click', function () { load(side, true); });
    $('[data-find]', b).addEventListener('input', function (e) { S[side].find = e.target.value; paintList(side); });
    ul.addEventListener('click', function (e) {
      var li = e.target.closest('.mg-vm[role=option]');
      if (li && li.getAttribute('aria-disabled') !== 'true') pick(side, li.dataset.id);
    });
    ul.addEventListener('keydown', function (e) {
      var li = e.target.closest('.mg-vm[role=option]');
      if (!li) return;
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); pick(side, li.dataset.id); return; }
      if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
      e.preventDefault();
      var all = $$('.mg-vm[role=option]:not([aria-disabled=true])', ul), i = all.indexOf(li);
      var next = all[i + (e.key === 'ArrowDown' ? 1 : -1)];
      if (next) next.focus();
    });
  });
  $$('[data-go]', root).forEach(function (b) {
    b.addEventListener('click', function () { start(b.dataset.go, false); });
  });
  $('[data-options]', root).addEventListener('click', function () {
    if (sel) start(sel.side === 'a' ? 'ab' : 'ba', true);
  });
  $('[data-panel-close]').addEventListener('click', function () { closePanel(); paintArrows(); });
  $('[data-panel-go]').addEventListener('click', function () { send(values(), false); });
  $('[data-panel-form]').addEventListener('submit', function (e) { e.preventDefault(); send(values(), false); });
  $('[data-panel-form]').addEventListener('keydown', function (e) {
    if (e.key === 'Enter' && e.target.tagName === 'INPUT') { e.preventDefault(); send(values(), false); }
  });

  // the hosts this page was opened with, else the ones chosen last time
  var first = [root.dataset.a || '', root.dataset.b || ''];
  if (!first[0] && !first[1]) {
    try { first = JSON.parse(localStorage.getItem('vmmigrate.hosts') || '["",""]'); } catch (e) { first = ['', '']; }
  }
  ['a', 'b'].forEach(function (side, i) {
    var key = first[i], s = $('[data-host]', box(side));
    if (key && byKey[key] && !byKey[key].off) {
      s.value = key;
      if (s._ddRefresh) s._ddRefresh();
      choose(side, key, true);
    } else {
      paintList(side);
    }
  });
  paintArrows();
  tick();
})();
