/* Grafana-style dashboards: panel loading, time series drawing, row toggles.

   Panels load INDEPENDENTLY, the way Grafana's do. A dashboard is a dozen
   queries or a hundred, and waiting for the slowest before drawing any of
   them is the rule this product already refuses elsewhere: no page may be as
   slow as the slowest thing it reads. The server renders each panel's body;
   this file fetches them, a few at a time, and draws the time series -- the
   one panel type that needs real pixel sizes and a hover.

   CSP: loaded as a nonced external script, wired by addEventListener and
   data attributes only. There is no inline handler anywhere on the page. */
(function () {
  'use strict';
  var LIMIT = 6, queue = [], busy = 0;

  function pump() {
    while (busy < LIMIT && queue.length) {
      var body = queue.shift();
      busy++;
      load(body).then(function () { busy--; pump(); }, function () { busy--; pump(); });
    }
  }

  function load(body) {
    var src = body.getAttribute('data-src');
    if (!src) return Promise.resolve();
    var w = Math.max(200, Math.round(body.getBoundingClientRect().width || 600));
    body.classList.add('loading');
    return fetch(src + '&w=' + w, { credentials: 'same-origin' })
      .then(function (r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.text();
      })
      .then(function (html) {
        body.innerHTML = html;
        body.classList.remove('loading');
        body.setAttribute('data-loaded', '1');
        draw(body);
      })
      .catch(function (e) {
        body.classList.remove('loading');
        body.innerHTML = '<div class="gp-empty bad">could not load this panel: ' +
          String(e.message || e).replace(/[<>&"]/g, '') + '</div>';
      });
  }

  function enqueue(root) {
    [].forEach.call(root.querySelectorAll('.gp-body[data-src]:not([data-loaded])'), function (b) {
      if (b.closest('.gsec.collapsed')) return;
      queue.push(b);
    });
    pump();
  }

  // ── time series ──────────────────────────────────────────────
  var NS = 'http://www.w3.org/2000/svg';
  function el(tag, attrs) {
    var n = document.createElementNS(NS, tag);
    for (var k in attrs) n.setAttribute(k, attrs[k]);
    return n;
  }
  function pad(n) { return n < 10 ? '0' + n : '' + n; }
  function tlabel(ms, span) {
    var d = new Date(ms);
    var hm = pad(d.getHours()) + ':' + pad(d.getMinutes());
    if (span <= 600000) return hm + ':' + pad(d.getSeconds());
    if (span <= 86400000 * 1.01) return hm;
    return pad(d.getMonth() + 1) + '/' + pad(d.getDate()) + (span <= 86400000 * 8 ? ' ' + hm : '');
  }
  var STEPS = [1e3, 5e3, 1e4, 15e3, 3e4, 6e4, 12e4, 3e5, 6e5, 9e5, 18e5, 36e5, 72e5,
               108e5, 216e5, 432e5, 864e5, 1728e5, 6048e5, 2592e6];

  function drawTs(host) {
    var spec;
    try { spec = JSON.parse(host.getAttribute('data-spec')); } catch (e) { return; }
    var W = host.clientWidth, H = host.clientHeight;
    if (W < 40 || H < 40) return;
    host.textContent = '';
    var left = 12, bottom = 20, top = 6, right = 8;
    spec.yt.forEach(function (t) { left = Math.max(left, t.l.length * 6.6 + 10); });
    var pw = W - left - right, ph = H - top - bottom;
    var ymin = spec.ymin, ymax = spec.ymax, from = spec.from, to = spec.to;
    function X(t) { return left + (t - from) / (to - from) * pw; }
    function Y(v) { return top + ph - (v - ymin) / ((ymax - ymin) || 1) * ph; }
    var svg = el('svg', { width: W, height: H, class: 'gts-svg' });
    spec.yt.forEach(function (t) {
      var y = Y(t.v);
      svg.appendChild(el('line', { x1: left, x2: W - right, y1: y, y2: y, class: 'gts-grid' }));
      var tx = el('text', { x: left - 6, y: y + 3.5, 'text-anchor': 'end', class: 'gts-ax' });
      tx.textContent = t.l;
      svg.appendChild(tx);
    });
    var span = to - from, want = Math.max(2, Math.floor(pw / 90)), step = STEPS[STEPS.length - 1];
    for (var i = 0; i < STEPS.length; i++) { if (span / STEPS[i] <= want) { step = STEPS[i]; break; } }
    var tz = new Date().getTimezoneOffset() * 60000;
    for (var t0 = Math.ceil((from - tz) / step) * step + tz; t0 <= to; t0 += step) {
      var x = X(t0);
      svg.appendChild(el('line', { x1: x, x2: x, y1: top, y2: top + ph, class: 'gts-grid' }));
      var lx = el('text', { x: x, y: H - 5, 'text-anchor': 'middle', class: 'gts-ax' });
      lx.textContent = tlabel(t0, span);
      svg.appendChild(lx);
    }
    var base = spec.stack ? [] : null;
    spec.s.forEach(function (s) {
      if (s.hide) return;
      var d = '', area = '', started = false, pts = [];
      for (var k = 0; k < s.t.length; k++) {
        var v = s.v[k];
        if (v === null || v === undefined) { started = false; continue; }
        var y0 = 0;
        if (base) { y0 = base[k] || 0; v = v + y0; base[k] = v; }
        var px = X(s.t[k]), py = Y(v);
        d += (started ? 'L' : 'M') + px.toFixed(1) + ',' + py.toFixed(1);
        pts.push([px, py, k, Y(y0)]);
        started = true;
      }
      if (!pts.length) return;
      if (spec.draw === 'bars') {
        var bw = Math.max(1, pw / Math.max(1, s.t.length) * 0.7);
        pts.forEach(function (p) {
          svg.appendChild(el('rect', { x: p[0] - bw / 2, y: p[1], width: bw,
            height: Math.max(0, p[3] - p[1]), fill: s.c, opacity: 0.85 }));
        });
        return;
      }
      if (s.fo > 0 && pts.length > 1) {
        area = 'M' + pts[0][0] + ',' + pts[0][3];
        pts.forEach(function (p) { area += 'L' + p[0] + ',' + p[1]; });
        for (var q = pts.length - 1; q >= 0; q--) area += 'L' + pts[q][0] + ',' + pts[q][3];
        svg.appendChild(el('path', { d: area + 'Z', fill: s.c, opacity: s.fo / 100 }));
      }
      svg.appendChild(el('path', { d: d, fill: 'none', stroke: s.c, 'stroke-width': s.w || 1,
        'stroke-linejoin': 'round', 'vector-effect': 'non-scaling-stroke' }));
      var show = spec.pts === 'always' || (spec.pts === 'auto' && pts.length > 0 && pw / pts.length > spec.ps * 5);
      if (show) pts.forEach(function (p) {
        svg.appendChild(el('circle', { cx: p[0], cy: p[1], r: Math.max(1.5, spec.ps / 2), fill: s.c }));
      });
    });
    var cross = el('line', { class: 'gts-cross', y1: top, y2: top + ph, x1: -10, x2: -10 });
    svg.appendChild(cross);
    host.appendChild(svg);
    var tip = document.createElement('div');
    tip.className = 'gts-tip';
    host.appendChild(tip);
    host.onmousemove = null;
    host.addEventListener('mousemove', function (ev) {
      var r = host.getBoundingClientRect(), mx = ev.clientX - r.left;
      if (mx < left || mx > W - right) { tip.style.display = 'none'; cross.setAttribute('x1', -10); cross.setAttribute('x2', -10); return; }
      var tm = from + (mx - left) / pw * (to - from), rows = [], at = null;
      spec.s.forEach(function (s) {
        if (s.hide || !s.t.length) return;
        var lo = 0, hi = s.t.length - 1;
        while (hi - lo > 1) { var mid = (lo + hi) >> 1; if (s.t[mid] < tm) lo = mid; else hi = mid; }
        var k = Math.abs(s.t[lo] - tm) <= Math.abs(s.t[hi] - tm) ? lo : hi;
        if (s.v[k] === null || s.v[k] === undefined) return;
        at = at === null ? s.t[k] : at;
        rows.push([s.c, s.n, s.f[k], s.v[k]]);
      });
      if (!rows.length) { tip.style.display = 'none'; return; }
      rows.sort(function (a, b) { return b[3] - a[3]; });
      var cx = X(at);
      cross.setAttribute('x1', cx); cross.setAttribute('x2', cx);
      var d = new Date(at);
      var head = d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' +
        pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
      tip.textContent = '';
      var h = document.createElement('div'); h.className = 'gts-tip-h'; h.textContent = head; tip.appendChild(h);
      rows.slice(0, 12).forEach(function (row) {
        var line = document.createElement('div'); line.className = 'gts-tip-r';
        var sw = document.createElement('i'); sw.style.background = row[0];
        var nm = document.createElement('span'); nm.textContent = row[1];
        var vl = document.createElement('b'); vl.textContent = row[2];
        line.appendChild(sw); line.appendChild(nm); line.appendChild(vl); tip.appendChild(line);
      });
      if (rows.length > 12) { var more = document.createElement('div'); more.className = 'gts-tip-h';
        more.textContent = '+ ' + (rows.length - 12) + ' more'; tip.appendChild(more); }
      tip.style.display = 'block';
      var tw = tip.offsetWidth, tx2 = cx + 14;
      if (tx2 + tw > W) tx2 = cx - tw - 14;
      tip.style.left = Math.max(0, tx2) + 'px';
      tip.style.top = Math.max(0, ev.clientY - r.top - 20) + 'px';
    });
    host.addEventListener('mouseleave', function () {
      tip.style.display = 'none'; cross.setAttribute('x1', -10); cross.setAttribute('x2', -10);
    });
  }

  function draw(root) {
    [].forEach.call(root.querySelectorAll('.gts[data-spec]'), drawTs);
  }

  var ro = window.ResizeObserver ? new ResizeObserver(function (entries) {
    entries.forEach(function (e) {
      var host = e.target;
      if (host.getAttribute('data-spec')) drawTs(host);
    });
  }) : null;
  var mo = new MutationObserver(function (list) {
    list.forEach(function (m) {
      [].forEach.call(m.addedNodes || [], function (n) {
        if (n.nodeType === 1 && ro) [].forEach.call(n.querySelectorAll ? n.querySelectorAll('.gts[data-spec]') : [], function (h) { ro.observe(h); });
      });
    });
  });

  function rowToggle(ev) {
    var head = ev.target.closest('[data-row-toggle]');
    if (!head) return;
    var sec = head.closest('.gsec');
    sec.classList.toggle('collapsed');
    head.setAttribute('aria-expanded', sec.classList.contains('collapsed') ? 'false' : 'true');
    if (!sec.classList.contains('collapsed')) {
      enqueue(sec);
      setTimeout(function () { draw(sec); }, 30);
    }
  }

  function refreshAll() {
    [].forEach.call(document.querySelectorAll('.gp-body[data-loaded]'), function (b) {
      if (b.closest('.gsec.collapsed')) return;
      b.removeAttribute('data-loaded');
    });
    enqueue(document);
  }

  // ── playlist and TV mode ─────────────────────────────────────
  // A wall screen cycles through dashboards on its own. The server decides
  // the order and builds every URL; this only counts down, and lets somebody
  // standing at the screen pause, skip or leave. The count stops while the tab
  // is hidden: a rotation nobody can see is a page of queries for nothing.
  function fullscreen() {
    var d = document;
    if (d.fullscreenElement) { if (d.exitFullscreen) d.exitFullscreen(); return; }
    var el = d.documentElement;
    if (el.requestFullscreen) el.requestFullscreen().catch(function () {});
  }

  function playlist() {
    var bar = document.querySelector('.gplay');
    if (!bar) return;
    // A WALL SCREEN HAS TO SHOW THE WHOLE DASHBOARD, not its top half. So a
    // dashboard is shown in four phases: its panels load, it holds at the top,
    // it scrolls smoothly to the bottom, and it waits there before moving on.
    // `every` is the least time a dashboard gets; the scroll is paced to fit
    // it, but never slower than a crawl or faster than somebody can read, so a
    // very long dashboard takes as long as its scroll needs. One that fits the
    // screen does not scroll at all -- it simply waits its time.
    var every = parseInt(bar.getAttribute('data-every') || '0', 10) * 1000;
    var holdMs = parseInt(bar.getAttribute('data-hold') || '5', 10) * 1000;
    var scrollOn = bar.getAttribute('data-scroll') !== '0';
    // SPEED IS THE OPERATOR'S CALL when they make it: "auto" paces the scroll
    // to fit the time on each dashboard, a number is pixels per second. The
    // bar's - and + walk this ladder, the change applies at once, and it rides
    // on every link from here -- and on the address bar, so a bookmark made
    // after adjusting it on the wall keeps it.
    var LADDER = [10, 15, 25, 40, 60, 90, 120, 180, 250, 400, 600];
    var fixed = parseInt(bar.getAttribute('data-speed'), 10);
    if (isNaN(fixed)) fixed = null;
    var speedEl = bar.querySelector('[data-play-speed]');
    var next = bar.getAttribute('data-next'), prev = bar.getAttribute('data-prev');
    var prog = bar.querySelector('.gp-prog'), label = bar.querySelector('[data-play-left]');
    var phaseEl = bar.querySelector('[data-play-phase]');
    var pauseBtn = bar.querySelector('[data-play-pause]');
    var se = document.scrollingElement || document.documentElement;
    var reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    var MIN_PX_S = 25, MAX_PX_S = 120, LOAD_MAX = 10000;
    var topHold = Math.min(4000, every / 4);
    var phase = 'load', phaseAt = 0, elapsed = 0, last = performance.now();
    var speed = 0, pos = 0, stepAcc = 0, endFor = 0, total = every, paused = false, done = false;
    if ('scrollRestoration' in history) history.scrollRestoration = 'manual';
    se.scrollTop = 0;

    function go(url) { if (url) { done = true; window.location.href = url; } }
    function room() { return Math.max(0, se.scrollHeight - se.clientHeight); }
    function pending() {
      return document.querySelectorAll('.gsec:not(.collapsed) .gp-body[data-src]:not([data-loaded])').length;
    }
    function toEnd() {
      phase = 'end';
      phaseAt = elapsed;
      endFor = Math.max(holdMs, every - elapsed);
      total = elapsed + endFor;
    }
    function tick(dt) {
      if (phase === 'load') {
        if (!pending() || elapsed >= LOAD_MAX) { phase = 'top'; phaseAt = elapsed; }
      } else if (phase === 'top') {
        if (elapsed - phaseAt >= topHold) {
          var dist = room();
          if (!scrollOn || dist < 8) { toEnd(); return; }
          var budget = Math.max(1000, every - elapsed - holdMs);
          speed = fixed || Math.max(MIN_PX_S, Math.min(MAX_PX_S, dist / (budget / 1000)));
          total = Math.max(every, elapsed + dist / speed * 1000 + holdMs);
          pos = se.scrollTop;
          phase = 'scroll';
          phaseAt = elapsed;
        }
      } else if (phase === 'scroll') {
        var move = speed * dt / 1000;
        if (reduced) {
          // no continuous motion for somebody who asked the system for none:
          // the same pace, a screen at a time
          stepAcc += move;
          var page = se.clientHeight * 0.85;
          if (stepAcc >= page) { pos += page; stepAcc = 0; }
        } else {
          pos += move;
        }
        pos = Math.min(room(), pos);
        se.scrollTop = pos;
        if (pos >= room() - 1) toEnd();
      } else if (phase === 'end') {
        if (elapsed - phaseAt >= endFor) go(next);
      }
    }
    function withSpeed(url, v) {
      if (!url) return url;
      var u = new URL(url, window.location.origin);
      if (v === null) u.searchParams.delete('speed'); else u.searchParams.set('speed', v);
      return u.pathname + '?' + u.searchParams.toString();
    }
    function setSpeed(v) {
      fixed = v;
      if (phase === 'scroll') {
        speed = v;
        total = Math.max(every, elapsed + Math.max(0, room() - pos) / speed * 1000 + holdMs);
      }
      next = withSpeed(next, v);
      prev = withSpeed(prev, v);
      ['data-next', 'data-prev', 'data-tv-on', 'data-tv-off'].forEach(function (a) {
        if (bar.hasAttribute(a)) bar.setAttribute(a, withSpeed(bar.getAttribute(a), v));
      });
      // the form that changes a variable or the time range keeps it too
      var form = document.querySelector('form.gform');
      if (form) {
        var inp = form.querySelector('input[name="speed"]');
        if (!inp) { inp = document.createElement('input'); inp.type = 'hidden'; inp.name = 'speed'; form.appendChild(inp); }
        inp.value = v;
      }
      if (window.history && history.replaceState) history.replaceState(null, '', withSpeed(window.location.href, v));
      paint();
    }
    function nudge(dir) {
      var cur = fixed || speed || 60, i;
      if (dir > 0) { for (i = 0; i < LADDER.length && LADDER[i] <= cur + 0.5; i++) {} setSpeed(LADDER[Math.min(i, LADDER.length - 1)]); }
      else { for (i = LADDER.length - 1; i >= 0 && LADDER[i] >= cur - 0.5; i--) {} setSpeed(LADDER[Math.max(i, 0)]); }
    }
    function paint() {
      if (speedEl) speedEl.textContent = fixed ? fixed + ' px/s' :
        (phase === 'scroll' ? 'auto \u00B7 ' + Math.round(speed) + ' px/s' : 'auto');
      var left = Math.max(0, Math.ceil((total - elapsed) / 1000));
      if (prog && total) prog.style.width = Math.min(100, elapsed / total * 100).toFixed(2) + '%';
      if (label) label.textContent = paused ? 'paused' : (phase === 'end' ? left + 's' : '~' + left + 's');
      if (phaseEl) phaseEl.textContent = paused ? '' :
        phase === 'load' ? 'loading · ' : phase === 'scroll' ? 'scrolling · ' :
        phase === 'end' && scrollOn && room() >= 8 ? 'at the end · ' : '';
    }
    function loop() {
      var now = performance.now(), dt = Math.min(1000, now - last);
      last = now;
      if (!paused && !document.hidden && every && next) { elapsed += dt; tick(dt); }
      paint();
      if (done) return;
      // animation frames while somebody can see it -- smooth -- and a slow
      // timer otherwise, since a hidden page does not get frames at all
      if (document.visibilityState === 'visible' && window.requestAnimationFrame) requestAnimationFrame(loop);
      else setTimeout(loop, 250);
    }
    function setPaused(p) {
      paused = p;
      bar.classList.toggle('paused', p);
      if (pauseBtn) pauseBtn.textContent = p ? '▶ resume' : '⏸ pause';
      if (!p) { pos = se.scrollTop; last = performance.now(); }
      paint();
    }
    loop();

    bar.addEventListener('click', function (ev) {
      var t = ev.target.closest('button');
      if (!t) return;
      if (t.hasAttribute('data-play-pause')) setPaused(!paused);
      else if (t.hasAttribute('data-play-next')) go(next);
      else if (t.hasAttribute('data-play-prev')) go(prev);
      else if (t.hasAttribute('data-play-stop')) go(bar.getAttribute('data-stop'));
      else if (t.hasAttribute('data-play-tv-on')) go(bar.getAttribute('data-tv-on'));
      else if (t.hasAttribute('data-play-tv-off')) go(bar.getAttribute('data-tv-off'));
      else if (t.hasAttribute('data-play-fs')) fullscreen();
      else if (t.hasAttribute('data-play-slower')) nudge(-1);
      else if (t.hasAttribute('data-play-faster')) nudge(1);
    });
    // Somebody scrolling by hand is somebody reading: the rotation stops
    // fighting them and waits. Resume carries on from wherever they left it.
    ['wheel', 'touchmove'].forEach(function (e) {
      window.addEventListener(e, function () {
        if (!paused && (phase === 'scroll' || phase === 'top')) setPaused(true);
      }, { passive: true });
    });
    document.addEventListener('keydown', function (ev) {
      if (ev.target && /^(INPUT|SELECT|TEXTAREA)$/.test(ev.target.tagName)) return;
      if (ev.key === ' ' && every && next) { ev.preventDefault(); setPaused(!paused); }
      else if (ev.key === 'ArrowRight' && next) go(next);
      else if (ev.key === 'ArrowLeft' && prev) go(prev);
      else if (ev.key === 'Escape' && bar.hasAttribute('data-tv')) go(bar.getAttribute('data-tv-off'));
      else if ((ev.key === '-' || ev.key === '_') && scrollOn) nudge(-1);
      else if ((ev.key === '+' || ev.key === '=') && scrollOn) nudge(1);
      else if (/^(PageDown|PageUp|ArrowDown|ArrowUp|Home|End)$/.test(ev.key) && !paused) setPaused(true);
    });
    if (bar.hasAttribute('data-tv')) {
      var idle = null;
      var wake = function () {
        document.body.classList.remove('gidle');
        clearTimeout(idle);
        idle = setTimeout(function () { document.body.classList.add('gidle'); }, 4000);
      };
      ['mousemove', 'keydown', 'touchstart'].forEach(function (e) {
        document.addEventListener(e, wake, { passive: true });
      });
      wake();
    }
  }

  document.addEventListener('DOMContentLoaded', function () {
    var root = document.querySelector('.gdash');
    if (!root) return;
    mo.observe(root, { childList: true, subtree: true });
    root.addEventListener('click', rowToggle);
    playlist();
    enqueue(root);
    var every = parseInt(root.getAttribute('data-autorefresh') || '0', 10);
    if (every >= 10) setInterval(function () {
      if (!document.hidden) refreshAll();
    }, every * 1000);
    var rsel = document.getElementById('gdash-auto');
    if (rsel) rsel.addEventListener('change', function () {
      var u = new URL(window.location.href);
      if (rsel.value) u.searchParams.set('refresh_every', rsel.value); else u.searchParams.delete('refresh_every');
      window.location.href = u.toString();
    });
  });
})();
