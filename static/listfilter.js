// Search, filters and sorting over a long list, as you type, with no reload:
// the Hypervisors page's guests and the Server hardware page's servers.
//
// The server has already filtered the first paint by the same rule
// (app/listfilter.py), so a shared link or a reload is right before this runs.
// `core` is that rule a second time, and tests/test_list_filters.py runs it
// against the rows the server rendered and compares every row and count:
// change the rule in both places or that test fails.
//
// The markup it reads (templates/_filterbar.html): one [data-fbar] form, rows
// marked [data-fr] with their search text in data-hay and one data-f-<key>
// per facet, optional groups [data-fg] (a hypervisor's card) with a
// [data-fgn] for their match count, sortable column titles th[data-fsort]
// with rows carrying data-s-<key>, and [data-fhl] text to highlight.
(function () {
  'use strict';
  var MAX_WORDS = 8;

  function words(q) {
    return String(q || '').toLowerCase().split(/\s+/).filter(Boolean).slice(0, MAX_WORDS);
  }

  function keep(row, ws, want, skip) {
    for (var i = 0; i < ws.length; i++) {
      if (row.hay.indexOf(ws[i]) === -1) return false;
    }
    for (var k in want) {
      if (want[k] && k !== skip && (row.f[k] || '') !== want[k]) return false;
    }
    return true;
  }

  // The same shape as listfilter.apply: which rows show, and for every facet
  // how many rows each option would show with the OTHER filters as they are.
  function core(rows, q, want, keys) {
    var ws = words(q), counts = {}, show = [], shown = 0;
    keys.forEach(function (k) { counts[k] = {}; });
    rows.forEach(function (r) {
      var s = keep(r, ws, want, '');
      show.push(s);
      if (s) shown++;
      keys.forEach(function (k) {
        if (!keep(r, ws, want, k)) return;
        var c = counts[k], v = r.f[k] || '';
        c[''] = (c[''] || 0) + 1;
        c[v] = (c[v] || 0) + 1;
      });
    });
    var active = ws.length > 0 || Object.keys(want).some(function (k) { return !!want[k]; });
    return {show: show, shown: shown, total: rows.length, counts: counts, active: active};
  }

  window.listFilter = {core: core, words: words};

  var bar = document.querySelector('[data-fbar]');
  if (!bar) return;
  var box = bar.querySelector('[data-fq]');
  var each = function (list, fn) { Array.prototype.forEach.call(list, fn); };
  var all = function (sel, root) {
    return Array.prototype.slice.call((root || document).querySelectorAll(sel));
  };

  var segs = {}, picks = {}, keys = [];
  all('.fseg[data-fk]', bar).forEach(function (g) {
    segs[g.getAttribute('data-fk')] = g; keys.push(g.getAttribute('data-fk'));
  });
  all('select[data-fk]', bar).forEach(function (s) {
    picks[s.getAttribute('data-fk')] = s; keys.push(s.getAttribute('data-fk'));
  });
  // the parameters this bar owns; anything else in the address is left
  // alone. `refresh` is dropped once the page has been read, or every one of
  // its own reloads would throw the cache away and start again.
  var MINE = ['q', 'sort', 'dir', 'stopped_only'].concat(keys);
  var OWN = MINE.concat(['refresh']);

  var rows = all('[data-fr]').map(function (el, i) {
    var f = {};
    keys.forEach(function (k) { f[k] = el.getAttribute('data-f-' + k) || ''; });
    return {el: el, hay: el.getAttribute('data-hay') || '', f: f, i: i};
  });
  var groups = all('[data-fg]');
  var heads = all('th[data-fsort]');
  var marks = all('[data-fhl]').map(function (el) { return {el: el, text: el.textContent}; });

  function want() {
    var w = {};
    Object.keys(segs).forEach(function (k) {
      var on = segs[k].querySelector('[aria-pressed="true"]');
      w[k] = on ? on.getAttribute('data-fv') : '';
    });
    Object.keys(picks).forEach(function (k) { w[k] = picks[k].value; });
    return w;
  }

  function setSeg(k, v) {
    each(segs[k].querySelectorAll('[data-fv]'), function (b) {
      var on = b.getAttribute('data-fv') === v;
      b.classList.toggle('on', on);
      b.setAttribute('aria-pressed', on ? 'true' : 'false');
    });
  }

  function setPick(k, v) {
    var s = picks[k];
    s.value = v;
    if (s.value !== v) s.value = '';   // an option the list no longer has
    if (window.ddRefresh) window.ddRefresh(s);
  }

  function counts(got) {
    Object.keys(segs).forEach(function (k) {
      each(segs[k].querySelectorAll('[data-fv]'), function (b) {
        var n = got.counts[k][b.getAttribute('data-fv')] || 0;
        var span = b.querySelector('[data-fn]');
        if (span) span.textContent = String(n);
        b.classList.toggle('zero', !n);
      });
    });
    Object.keys(picks).forEach(function (k) {
      var s = picks[k];
      each(s.options, function (o) {
        o.textContent = (o.getAttribute('data-fl') || '') + ' (' + (got.counts[k][o.value] || 0) + ')';
      });
      if (window.ddRefresh) window.ddRefresh(s);
    });
  }

  // A card with nothing matching steps aside, and one with matches opens —
  // when the filter starts, or when the card first gets a match, not on every
  // key: a card somebody closed while searching stays closed as they type.
  var was = null;
  function fold(active) {
    var on = 0;
    groups.forEach(function (g) {
      var n = 0;
      each(g.querySelectorAll('[data-fr]'), function (r) { if (!r.hidden) n++; });
      if (n) on++;
      g.hidden = active && !n;
      if (active && n && g.tagName === 'DETAILS' && (was !== true || !g._lfn)) g.open = true;
      g._lfn = n;
      var lab = g.querySelector('[data-fgn]');
      if (lab) lab.textContent = active ? ' · ' + n + (n === 1 ? ' match' : ' matches') : '';
    });
    was = active;
    return on;
  }

  // Built from text nodes and <mark> elements, never innerHTML: textContent is
  // already DECODED, and assigning it back as markup would turn a VM called
  // "<img src=x onerror=…>" into an element (CLAUDE.md, the Search bug).
  function highlight(ws) {
    marks.forEach(function (m) {
      var low = m.text.toLowerCase(), hits = [];
      if (ws.length && low.length === m.text.length) {
        ws.forEach(function (w) {
          for (var at = low.indexOf(w); at !== -1; at = low.indexOf(w, at + w.length)) {
            hits.push([at, at + w.length]);
          }
        });
      }
      if (!hits.length) {
        if (m.el._lfm) { m.el.textContent = m.text; m.el._lfm = false; }
        return;
      }
      hits.sort(function (a, b) { return a[0] - b[0]; });
      var merged = [hits[0]];
      hits.slice(1).forEach(function (h) {
        var last = merged[merged.length - 1];
        if (h[0] <= last[1]) last[1] = Math.max(last[1], h[1]); else merged.push(h);
      });
      var parts = [], pos = 0;
      merged.forEach(function (h) {
        if (h[0] > pos) parts.push(document.createTextNode(m.text.slice(pos, h[0])));
        var mk = document.createElement('mark');
        mk.className = 'fhit';
        mk.textContent = m.text.slice(h[0], h[1]);
        parts.push(mk);
        pos = h[1];
      });
      if (pos < m.text.length) parts.push(document.createTextNode(m.text.slice(pos)));
      m.el.replaceChildren.apply(m.el, parts);
      m.el._lfm = true;
    });
  }

  function said(got, gon) {
    var n1 = bar.getAttribute('data-noun'), n2 = bar.getAttribute('data-nouns');
    var t = (got.active ? got.shown + ' of ' : '') + got.total + ' ' + (got.total === 1 ? n1 : n2);
    var g1 = bar.getAttribute('data-gnoun'), g2 = bar.getAttribute('data-gnouns');
    if (g1) {
      t += ' on ' + (got.active ? gon + ' of ' : '') + groups.length + ' '
        + (groups.length === 1 ? g1 : g2);
    }
    each(bar.querySelectorAll('[data-fcount]'), function (el) { el.textContent = t; });
  }

  function empty(got) {
    each(document.querySelectorAll('[data-fempty]'), function (el) {
      el.hidden = !(got.active && !got.shown);
      var q = el.querySelector('[data-fempty-q]');
      if (q) q.textContent = box.value.trim() ? '“' + box.value.trim() + '”' : 'these filters';
    });
    each(document.querySelectorAll('[data-fclear]'), function (a) {
      if (!a.closest('[data-fempty]')) a.hidden = !got.active;
    });
  }

  // ── the address: filters live in it, so a reload, the page's own "still
  // collecting" reloads and a link sent to somebody all keep them
  var sortKey = '', sortDir = '';
  function params(base) {
    var p = new URLSearchParams(base === undefined ? location.search : base);
    OWN.forEach(function (k) { p.delete(k); });
    if (box.value.trim()) p.set('q', box.value.trim());
    var w = want();
    keys.forEach(function (k) { if (w[k]) p.set(k, w[k]); });
    if (sortKey) { p.set('sort', sortKey); p.set('dir', sortDir); }
    return p;
  }
  // Refresh and the view switch keep their own meaning and carry the filters
  function carry() {
    each(document.querySelectorAll('a[data-fkeep]'), function (a) {
      if (!a._lfbase) a._lfbase = a.getAttribute('href');
      var u = new URL(a._lfbase, location.href);
      var mine = new URLSearchParams(u.search), now = params('');
      MINE.forEach(function (k) { mine.delete(k); });
      now.forEach(function (v, k) { mine.set(k, v); });
      var s = mine.toString();
      a.setAttribute('href', u.pathname + (s ? '?' + s : ''));
    });
  }
  function sync() {
    var s = params().toString();
    try {
      history.replaceState(history.state, '', location.pathname + (s ? '?' + s : '') + location.hash);
    } catch (e) { /* a sandboxed frame: the filter still works, the address stays */ }
    carry();
  }

  function apply(quiet) {
    var got = core(rows, box.value, want(), keys);
    rows.forEach(function (r, i) { r.el.hidden = !got.show[i]; });
    counts(got);
    var gon = fold(got.active);
    highlight(words(box.value));
    said(got, gon);
    empty(got);
    if (!quiet) sync();
    var ev;
    try { ev = new CustomEvent('listfilter', {detail: {active: got.active}}); } catch (e) { ev = null; }
    if (ev) document.dispatchEvent(ev);
    return got;
  }

  // ── sorting: a column title's first click is its own direction (a number
  // biggest first, a name A to Z), the second turns it round, the third gives
  // the page's own order back. Rows without a value go last either way.
  function cmp(a, b, kind) {
    var ea = a === null || a === '', eb = b === null || b === '';
    if (ea || eb) return ea === eb ? 0 : (ea ? 1 : -1);
    var c = kind === 'num' ? parseFloat(a) - parseFloat(b)
      : String(a).localeCompare(String(b), undefined, {numeric: true, sensitivity: 'base'});
    return (sortDir === 'desc' ? -c : c) || 0;
  }
  function sortRows() {
    var kind = 'text';
    heads.forEach(function (th) {
      var on = th.getAttribute('data-fsort') === sortKey;
      if (on) kind = th.getAttribute('data-ftype') || 'text';
      th.setAttribute('aria-sort', on ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none');
    });
    var bodies = [];
    rows.forEach(function (r) {
      if (bodies.indexOf(r.el.parentNode) === -1) bodies.push(r.el.parentNode);
    });
    bodies.forEach(function (tb) {
      var rs = rows.filter(function (r) { return r.el.parentNode === tb; });
      rs.sort(function (a, b) {
        if (!sortKey) return a.i - b.i;
        return cmp(a.el.getAttribute('data-s-' + sortKey),
                   b.el.getAttribute('data-s-' + sortKey), kind) || a.i - b.i;
      });
      rs.forEach(function (r) { tb.appendChild(r.el); });
    });
  }
  heads.forEach(function (th) {
    var s = th.getAttribute('aria-sort');
    if (s === 'ascending' || s === 'descending') {
      sortKey = th.getAttribute('data-fsort');
      sortDir = s === 'ascending' ? 'asc' : 'desc';
    }
    (th.querySelector('.fsort') || th).addEventListener('click', function () {
      var k = th.getAttribute('data-fsort'), first = th.getAttribute('data-fdir') || 'asc';
      if (sortKey !== k) { sortKey = k; sortDir = first; }
      else if (sortDir === first) sortDir = first === 'asc' ? 'desc' : 'asc';
      else { sortKey = ''; sortDir = ''; }
      sortRows();
      sync();
    });
  });

  function reset() {
    box.value = '';
    Object.keys(segs).forEach(function (k) { setSeg(k, ''); });
    Object.keys(picks).forEach(function (k) { setPick(k, ''); });
  }

  // ── the controls
  box.addEventListener('input', function () { apply(); });
  box.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
      if (box.value) { e.preventDefault(); box.value = ''; apply(); } else box.blur();
    } else if (e.key === 'Enter') {
      e.preventDefault();
      var vis = rows.filter(function (r) { return !r.el.hidden; });
      var a = vis.length === 1 && vis[0].el.querySelector('a[href]:not([target])');
      if (a) window.location.href = a.href;
    }
  });
  bar.addEventListener('submit', function (e) { e.preventDefault(); apply(); });
  Object.keys(segs).forEach(function (k) {
    segs[k].addEventListener('click', function (e) {
      var b = e.target.closest('[data-fv]');
      if (!b) return;
      e.preventDefault();
      setSeg(k, b.getAttribute('data-fv'));
      apply();
    });
  });
  Object.keys(picks).forEach(function (k) {
    picks[k].addEventListener('change', function () { apply(); });
  });
  each(document.querySelectorAll('[data-fclear]'), function (a) {
    a.addEventListener('click', function (e) {
      e.preventDefault();
      reset();
      apply();
    });
  });

  // A chart's slice that links to this same page with only filters in its
  // address IS a filter: applied here, without a reload, and the list is
  // brought into view.
  document.addEventListener('click', function (e) {
    var a = e.target.closest && e.target.closest('a[href]');
    if (!a || e.defaultPrevented || e.button || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    if (a.target || a.hasAttribute('data-fclear') || a.hasAttribute('data-fkeep')) return;
    var u = new URL(a.href, location.href);
    if (u.origin !== location.origin || u.pathname !== location.pathname) return;
    var p = new URLSearchParams(u.search), mine = true, any = false;
    p.forEach(function (v, k) { any = true; if (MINE.indexOf(k) === -1) mine = false; });
    if (!any || !mine) return;
    e.preventDefault();
    reset();
    box.value = p.get('q') || '';
    keys.forEach(function (k) {
      var v = p.get(k) || (k === 'state' && p.get('stopped_only') ? 'stopped' : '');
      if (!v) return;
      if (segs[k]) setSeg(k, v); else setPick(k, v);
    });
    apply();
    try { bar.scrollIntoView({block: 'start', behavior: 'smooth'}); } catch (e2) { bar.scrollIntoView(); }
  });

  // `/` searches this list rather than the whole portal: on a page that is a
  // list, the list is what is being looked for. The portal's own search is
  // one click away in the header.
  window.addEventListener('keydown', function (e) {
    if (e.key !== '/' || e.ctrlKey || e.metaKey || e.altKey) return;
    var t = document.activeElement;
    if (t && (/^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName) || t.isContentEditable)) return;
    if (document.querySelector('dialog[open]') || document.body.hasAttribute('data-remote-keyboard')) return;
    e.preventDefault();
    e.stopPropagation();
    box.focus();
    box.select();
  }, true);

  // The page reloads itself while hypervisors or BMCs are still answering. A
  // reload while somebody is typing here comes back with the caret where it
  // was, so the list filling in does not cost them their place.
  var CARET = 'listfilter.caret:' + location.pathname;
  window.addEventListener('pagehide', function () {
    try {
      if (document.activeElement === box) {
        sessionStorage.setItem(CARET, String(box.selectionStart == null ? box.value.length : box.selectionStart));
      } else sessionStorage.removeItem(CARET);
    } catch (e) { /* private mode: it only forgets the caret */ }
  });
  try {
    var at = sessionStorage.getItem(CARET);
    if (at !== null) {
      sessionStorage.removeItem(CARET);
      box.focus();
      box.setSelectionRange(+at, +at);
    }
  } catch (e) { /* as above */ }

  if (sortKey) sortRows();
  apply(true);
  carry();
})();
