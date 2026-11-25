/* The city: every cluster as a building, on streets you walk.

   The 3D view (cluster3d.js) is one cluster from the inside. This is the level
   above it. A project is a district, a cluster is a building, and its door
   leads into that cluster's own walk. It is drawn with cluster3d.js's engine
   and figure, handed over as `K`: this file owns the plan of the streets,
   what stands on them, and what happens there.

   A street is looked at from a distance and believed, so every thing on it is
   a fact from /clusters/city.json (app/city.py) and says the same fact to
   everybody:

     windows        one lit per pod, up to what the walls hold; red ones are
                    failing pods, and there is at least one whenever any fails
     the beacon     the building's state, with a column of light over one
                    that needs somebody
     steam          rises from a building with failing pods
     a storm        stands over one whose machines are not all ready
     the crowd      one pod outside per failing pod the portal can name, with
                    its own reason on its placard
     NO SIGNAL      a cluster that did not answer: dark, with no windows at
                    all, because nothing is known about its pods
     SURVEYING      a cluster the portal has not read yet: not calm, unknown
     the ambulance  drives to the building with the most failing pods
     the boards     at the gate: headlines and the list of who needs help
     the crier      a pod by the gate, calling out the headline of the moment
     tumbleweed     past a building that did not answer
     fireworks      only when every cluster answered and every pod is well

     the meters     two columns by each door: how much of the cluster's CPU
                    and memory is in use, as the hub counts it
     the load board a column pair for every cluster, side by side, at the gate
     the gears      at the crossings, turning as fast as the city's CPU is busy

   In the street stand the experts (cluster3d-quiz.js): eight people, one for
   each job a platform team has. Each tells you how the clusters are, from
   these same facts, and asks Kubernetes questions in its own subject. An
   answer that is right is cheered, and the first one from each is rewarded
   with something to keep. What you have won is kept in this browser and
   nowhere else: it is a game's score, and no cluster hears of it.

   The city is the inside of a machine: its streets are traces on a board,
   its parks are chips. What moves on the traces is scenery and says nothing
   about any cluster: the packets, the drones that carry BUILD, TEST, SCAN and
   DEPLOY round the ring, and the data falling beyond the last street. Nobody
   measured that traffic, and the page that explains the city says so.
   Nothing here asks a cluster anything, and nothing changes one: the street
   is for seeing and for going in. */
(function () {
  'use strict';
  var PI = Math.PI, TAU = PI * 2;
  function clamp(v, a, b) { return v < a ? a : v > b ? b : v; }
  function rnd(s) { var x = Math.sin(s * 127.1 + 311.7) * 43758.5453; return x - Math.floor(x); }
  function hash(s) { var h = 7, i; for (i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) % 100003; return h; }
  function plural(n, w) { return n + ' ' + w + (n === 1 ? '' : w === w.toUpperCase() ? 'S' : 's'); }

  /* ── the plan ────────────────────────────────────────────────────────
     Streets on one grid, so every street runs the whole way through. A
     district is a run of lots along it: districts follow one another like
     words on a line, a district starts a new line when it would not fit on
     the rest of this one, and a lot left over is a park. How many lots make a
     line is whatever leaves the fewest parks in a city about as deep as it is
     wide. The gate is at the south end, where you arrive. */
  var LOT = 22, ROAD = 10, PITCH = LOT + ROAD;
  /* A building is a Kubernetes cluster, built the way one is put together:
     a base that is its control plane, with the one door in (its API); a deck
     for each machine, stacked on a spine; the pods standing on the decks; and
     on the roof the helm that gives the thing its name, a ship's wheel of
     seven spokes. So it has a deck per machine (twelve at most are drawn), is
     as wide as a machine is full, and as many of its top decks are dark as
     machines are not ready: at least one when any is not, because which
     machine it is the street is not told. One nobody has counted yet is three
     bare decks, and says so itself. */
  var DECKS = 12, DECK = 2.4, BASE = 3.4;
  function shape(b) {
    if (!b.pods) return { w: 9, h: BASE + 3 * DECK, decks: 3, dark: 0 };
    var all = Math.max(1, b.nodes.total), n = clamp(all, 1, DECKS), un = all - b.nodes.ready;
    return { w: Math.round(clamp(7.5 + Math.sqrt(b.pods.total / all) * 0.9, 8, 14) * 2) / 2, h: BASE + n * DECK, decks: n,
      dark: un > 0 ? clamp(Math.round(un / all * n), 1, n) : 0 };
  }
  function lay(d, cols) {
    var bs = d.buildings || [], cells = [], heads = [], row = 0, col = 0;
    (d.districts || []).forEach(function (dist, di) {
      var mine = bs.filter(function (b) { return b.pid === dist.pid; });
      if (!mine.length) return;
      if (col && cols - col < Math.min(mine.length, cols)) { while (col < cols) cells.push({ row: row, col: col++ }); row++; col = 0; }
      mine.forEach(function (b, i) {
        if (col === cols) { row++; col = 0; }
        if (!i) heads.push({ pid: dist.pid, name: dist.name, di: di, n: mine.length, row: row, col: col });
        cells.push({ row: row, col: col++, b: b, di: di });
      });
    });
    while (col && col < cols) cells.push({ row: row, col: col++ });
    return { cols: cols, rows: cells.length ? cells[cells.length - 1].row + 1 : 1, cells: cells, heads: heads };
  }
  function plan(d) {
    var best = null, c, got, score, parks, x0, depth, lots = [], pk = [], xs = [], zs = [], i;
    for (c = 3; c <= 8; c++) {
      got = lay(d, c); parks = got.cells.filter(function (o) { return !o.b; }).length;
      score = parks + Math.abs(c - got.rows * 1.3) * 0.6;
      if (!best || score < best.score - 1e-9) { best = got; best.score = score; }
    }
    x0 = -((best.cols - 1) / 2) * PITCH; depth = best.rows * PITCH - ROAD;
    function at(o) { return { x: x0 + o.col * PITCH, z: -depth / 2 + o.row * PITCH + LOT / 2 }; }
    best.cells.forEach(function (o) {
      var q = at(o), s;
      if (!o.b) { pk.push(q); return; }
      s = shape(o.b);
      lots.push({ cid: o.b.cid, b: o.b, di: o.di, x: q.x, z: q.z, row: o.row, w: s.w, h: s.h, decks: s.decks, dark: s.dark, bz: q.z - 1.5, dz: q.z - 1.5 + s.w / 2,
        sz: q.z + LOT / 2 + ROAD / 2, seed: hash(o.b.cid) / 100003 });
    });
    for (i = 0; i <= best.cols; i++) xs.push(x0 + (i - 0.5) * PITCH);
    for (i = 0; i <= best.rows; i++) zs.push(-depth / 2 - ROAD / 2 + i * PITCH);
    return { cols: best.cols, rows: best.rows, lots: lots, parks: pk, xs: xs, zs: zs, w: best.cols * PITCH, d: depth,
      heads: best.heads.map(function (h) { var q = at(h); return { pid: h.pid, name: h.name, di: h.di, n: h.n, x: q.x - LOT / 2, z: q.z - LOT / 2 }; }),
      gate: { x: 0, z: depth / 2 + ROAD + 6 } };
  }
  /* How many windows are lit, and how many of those are red. Exact, because
     it is read as a count: none red unless a pod is failing, at least one
     when one is, and none lit at all in a building nobody could ask. */
  function windows(b, slots) {
    if (!b.pods || slots < 1) return { lit: 0, red: 0 };
    var lit = Math.min(slots, b.pods.total);
    return { lit: lit, red: b.pods.bad && lit ? clamp(Math.round(b.pods.bad / b.pods.total * lit), 1, lit) : 0 };
  }
  /* What a failing pod carries outside: its own reason, shouted. */
  var SHOUT = { CrashLoopBackOff: 'I KEEP FALLING OVER', OOMKilled: 'MORE MEMORY!', ImagePullBackOff: 'WHERE IS MY IMAGE?', ErrImagePull: 'WHERE IS MY IMAGE?',
    Pending: 'NO ROOM FOR ME', CreateContainerConfigError: 'MY CONFIG IS MISSING', Error: 'I STOPPED WITH AN ERROR', Evicted: 'THEY PUT ME OUT', Unknown: 'NOBODY KNOWS HOW I AM', Running: 'UP, BUT NOT READY', Failed: 'I FAILED' };
  function placard(p) { return SHOUT[p.status] || String(p.status || 'NOT WELL').toUpperCase(); }
  function plea(p) {
    return 'I am ' + p.name + ' in ' + p.ns + ': ' + (p.status || 'not well') + (p.restarts ? ', restarted ' + plural(p.restarts, 'time') : '') + '. Go in and help us.';
  }
  function sick(b) { return b.state === 'bad'; }
  function unready(b) { return b.nodes ? b.nodes.total - b.nodes.ready : 0; }
  /* Who needs somebody first: the most failing pods, then machines not ready. */
  function needy(bs) {
    return bs.filter(sick).sort(function (a, b) { return b.pods.bad - a.pods.bad || unready(b) - unready(a) || (a.name < b.name ? -1 : 1); });
  }
  /* How busy the city is: the mean of what each cluster that answered says of
     its own CPU. null when none has said, which is not the same as idle. */
  function load(bs) {
    var got = (bs || []).filter(function (b) { return b.cpu != null; });
    return got.length ? got.reduce(function (a, b) { return a + b.cpu; }, 0) / got.length : null;
  }
  /* A meter's colour: how close to full. */
  function level(pct) { return pct >= 90 ? 2 : pct >= 70 ? 1 : 0; }
  /* The board at the gate. Each line is one fact about one cluster; when every
     cluster answered and is well it says that, and it never says so while any
     is still unread or silent. */
  function headlines(d) {
    var bs = d.buildings || [], out = [], down = bs.filter(function (b) { return b.state === 'down'; }), reading = bs.filter(function (b) { return b.state === 'reading'; });
    needy(bs).forEach(function (b) {
      var u = unready(b), top = b.problems[0];
      out.push((b.prod ? 'PRODUCTION · ' : '') + b.name + ': ' + (b.pods.bad ? b.pods.bad + ' of ' + plural(b.pods.total, 'pod') + ' failing' : 'every pod running')
        + (u ? ', ' + plural(u, 'machine') + ' not ready' : ''));
      if (top) out.push(b.name + ' · ' + top.name + ': ' + (top.status || 'not well') + (top.restarts ? ', ' + plural(top.restarts, 'restart') : ''));
    });
    down.forEach(function (b) { out.push('No word from ' + b.name + ': ' + (b.why || 'it did not answer')); });
    if (reading.length) out.push(plural(reading.length, 'building') + ' still being surveyed: nothing is known about ' + (reading.length === 1 ? 'it' : 'them') + ' yet');
    if (!out.length && bs.length) out.push('All ' + plural(bs.length, 'cluster') + ' answered and every pod is well. Enjoy the walk.');
    if (!bs.length) out.push('No cluster stands here yet: add one on the Clusters page.');
    return out;
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { plan: plan, lay: lay, shape: shape, DECKS: DECKS, windows: windows, placard: placard, plea: plea, needy: needy, headlines: headlines, load: load, level: level, LOT: LOT, ROAD: ROAD, PITCH: PITCH };
  }
  if (typeof window === 'undefined') return;

  window.C3DCity = function (K, hook) {
    var stage = K.stage, g = K.g, $ = K.$, calm = K.calm, me = K.me, goal = K.goal, cam = K.cam;
    var OKC = [0.24, 0.86, 0.6], BADC = [1.0, 0.3, 0.37], WARNC = [1.0, 0.69, 0.13], DOWNC = [0.36, 0.4, 0.5], READC = [0.4, 0.62, 1.0], GOLD = [1.0, 0.78, 0.3];
    var WIN = [0.5, 0.78, 1.0], MIST = [0.5, 0.52, 0.6], ASPHALT = [0.2, 0.3, 0.55], DASH = [0.9, 0.85, 0.55], WHITE = [0.93, 0.94, 0.96], DARK = [0.07, 0.08, 0.11], LEAF = [0.2, 0.75, 0.45];
    var DCOL = [[0.3, 0.75, 1.0], [0.62, 0.45, 1.0], [0.25, 0.95, 0.7], [1.0, 0.7, 0.3], [1.0, 0.45, 0.7], [0.55, 0.9, 0.3]];
    var BITS = [[0.3, 0.9, 1.0], [0.4, 1.0, 0.6], [1.0, 0.8, 0.3], [0.8, 0.5, 1.0], [1.0, 0.45, 0.7], [0.9, 0.95, 1.0]], LEVELC = [OKC, WARNC, BADC];
    var K8S = [0.2, 0.44, 0.95], POD = [0.42, 0.72, 1.0];      // the blue a cluster is known by, and a pod's own
    var STAGES = ['BUILD', 'TEST', 'SCAN', 'DEPLOY', 'BACKUP'], CPUC = [0.3, 0.85, 1.0], MEMC = [0.7, 0.5, 1.0], PCB = [0.1, 0.42, 0.34], PIN = [0.75, 0.78, 0.82];
    var data = null, P = null, lots = {}, last = 0, lastOk = 0, timer = 0, busy = false, lost = false;
    var you = { x: 0, y: 0, z: 0, vy: 0, face: PI, step: 0, moving: false, v: 0, riding: false, move: null, zoom: 7 };
    var GATE = {};      // what the gate's own words name as theirs, so the gate does not hide them
    /* The experts, the conversation with one, and what you have won from
       them. The bag is kept in this browser when it can be, checked when it is
       read, and the city plays the same without it. */
    var QZ = window.C3DQuiz || { EXPERTS: [], SUBJECTS: {} }, folk = [], who = null, chat = null, bag = { stars: 0, gifts: {}, seen: [] }, bits2 = [], steps = [], pet = null, party = -99, sign = null;
    try {
      var kept = JSON.parse(localStorage.getItem('c3d.city') || '{}');
      if (kept && kept.stars >= 0 && kept.stars < 1e6) bag.stars = Math.floor(kept.stars);
      QZ.EXPERTS.forEach(function (ex) { if (kept && kept.gifts && kept.gifts[ex.gift]) bag.gifts[ex.gift] = 1; });
      if (kept && Array.isArray(kept.seen)) bag.seen = kept.seen.filter(function (v) { return typeof v === 'string' && v.length < 12; }).slice(0, 400);
    } catch (e) { /* nothing kept: you start with nothing, and can still win it */ }
    function save() { try { localStorage.setItem('c3d.city', JSON.stringify(bag)); } catch (e) { /* not kept */ } }
    function has(gift) { return !!bag.gifts[gift]; }
    /* The letters of the sign, five dots wide and seven high, a row to a byte. */
    var DOTS = { A: '0E11111F111111', B: '1E11111E11111E', C: '0E11101010110E', D: '1E11111111111E', E: '1F10101E10101F', F: '1F10101E101010', G: '0E11101711110F', H: '1111111F111111',
      I: '0E04040404040E', J: '0702020202120C', K: '11121418141211', L: '1010101010101F', M: '111B1515111111', N: '11191513111111', O: '0E11111111110E', P: '1E11111E101010',
      Q: '0E11111115120D', R: '1E11111E141211', S: '0F10100E01011E', T: '1F040404040404', U: '1111111111110E', V: '11111111110A04', W: '11111115151B11', X: '11110A040A1111',
      Y: '11110A04040404', Z: '1F01020408101F', 0: '0E11131519110E', 1: '040C040404040E', 2: '0E11010204081F', 3: '1F02040201110E', 4: '02060A121F0202', 5: '1F101E0101110E',
      6: '0608101E11110E', 7: '1F010204080808', 8: '0E11110E11110E', 9: '0E11110F01020C' };
    var ROOFS = 8, ROOFS_FAR = 190, CROWD = 3, BESIDE = 11;      // how much is written and drawn at once: little, on purpose
    var keys = {}, beside = null, near = null, going = null, trip = null, taxiAt = 0, notes = [], bits = [], amb = null, news = [], crowdSay = null, hitAt = -99, crier = null, busy0 = null, screens = null;
    var fade = K.el('div', 'c3d-fade'); stage.appendChild(fade);

    function toast(text, kind) { notes.push({ text: text, at: performance.now() / 1000, keep: clamp(2.5 + text.length / 22, 5, 11), kind: kind || '' }); if (notes.length > 4) notes.shift(); }
    function col(b) { return b.state === 'bad' ? BADC : b.state === 'ok' ? OKC : b.state === 'down' ? DOWNC : READC; }
    function slab(x, y, z, sx, sy, sz, c, rim) { K.cube(x, y, z, sx, sy, sz, c, 0, 0, rim, 1, 0); }
    function metal(x, y, z, sx, sy, sz, c, glow) { K.cube(x, y, z, sx, sy, sz, c, glow || 0, 0, 0, 1, 4); }
    function light(x, y, z, sx, sy, sz, c, glow) { K.cube(x, y, z, sx, sy, sz, c, glow || 0, 0, 0, 1, 3); }
    function box(x, y, z, sx, sy, sz, c, glow, yaw) { K.solid(K.BOX, x, y, z, sx, sy, sz, c, glow || 0, yaw || 0, 0, 0); }
    function ball(x, y, z, sx, sy, sz, c, glow) { K.solid(K.BALL, x, y, z, sx, sy, sz, c, glow || 0, 0, 0, 0); }

    /* ── reading the city ────────────────────────────────────────────── */
    function take(d) {
      var first = !data, same, L, s, bs;
      if (d.error) { lost = true; live('could not read the city: ' + d.error, true); if (first) K.veil('The city could not be read (' + d.error + '). Trying again…', true); return; }
      bs = d.buildings || [];
      same = P && P.lots.length === bs.length && bs.every(function (b) { return lots[b.cid]; });
      data = d; lastOk = Date.now(); lost = false;
      if (!same) {      // a cluster was added or removed: the streets are laid again, and what stood keeps its height
        var old = lots; P = plan(d); lots = {};
        P.lots.forEach(function (o) { lots[o.cid] = o; o.hh = old[o.cid] ? old[o.cid].hh : 0.2; o.order = null; });
        flow(); people(); letters();
      }
      bs.forEach(function (b) {
        L = lots[b.cid]; if (!L) return;
        s = shape(b);
        if (L.b !== b && L.b.state !== b.state && !first) toast(b.name + (b.state === 'bad' ? ' needs help' : b.state === 'ok' ? ' is well' : b.state === 'down' ? ' stopped answering' : ' is being read again'), b.state === 'bad' ? 'kill' : '');
        L.b = b; L.h = s.h; L.decks = s.decks; L.dark = s.dark; if (L.w !== s.w) { L.w = s.w; L.order = null; } L.dz = L.bz + L.w / 2;
        s = b.state + '|' + b.problems.map(function (q) { return q.name + ':' + q.status + ':' + q.restarts; }).join(',') + '|' + (b.pods ? b.pods.total : '');
        if (L.sig !== s) { L.sig = s; L.crowd = null; }      // the same crowd until its pods change: a new one would start its sentence again
      });
      news = headlines(d); busy0 = load(bs);
      if (first) { arrive(); K.veil('', false); }
      totals();
    }
    function poll() {
      if (busy) return;
      clearTimeout(timer);
      if (document.hidden) { timer = setTimeout(poll, 4000); return; }
      busy = true;
      fetch(stage.getAttribute('data-json'), { credentials: 'same-origin', headers: { Accept: 'application/json' } })
        .then(function (r) { if (!r.ok) throw new Error('the portal answered ' + r.status); return r.json(); })
        .then(take)
        .catch(function (e) { lost = true; live('lost contact with the portal, retrying', true); if (!data) K.veil('Could not load the city: ' + (e && e.message || 'no answer') + '. Trying again…', true); })
        .then(function () { busy = false; timer = setTimeout(poll, data && data.totals.reading ? 2500 : 12000); });
    }
    function live(text, bad) { var n = $('c3dLive'); n.className = 'c3d-live ' + (bad ? 'bad' : 'on'); n.textContent = text; }
    function totals() {
      var t = data.totals, box0 = $('c3dTotals'); K.clear(box0);
      function chip(n, word, c) {
        var b = K.el('span', 'c3d-tot' + (n ? '' : ' quiet')), dot = K.el('i'); b.style.cursor = 'default';
        dot.style.setProperty('--c', c); b.appendChild(dot); b.appendChild(K.el('b', '', String(n))); b.appendChild(K.el('span', '', word)); box0.appendChild(b);
      }
      chip(t.ok, 'well', '#3ddc97'); chip(t.bad, t.bad === 1 ? 'needs help' : 'need help', '#ff4d5e');
      if (t.down) chip(t.down, 'no signal', '#8a93a8');
      if (t.reading) chip(t.reading, 'being read', '#6aa0ff');
      var m = K.el('span', 'c3d-tot quiet'); m.style.cursor = 'default';
      m.textContent = plural(t.clusters, 'cluster') + ' · ' + plural(t.pods, 'pod') + ' and ' + plural(t.nodes, 'machine') + ' in those that answered';
      box0.appendChild(m);
    }
    /* Where you arrive: outside the building you came out of, or at the gate. */
    function arrive() {
      var L = lots[stage.getAttribute('data-city') || ''];
      if (L) { you.x = L.x; you.z = L.dz + 2.6; you.face = 0; goal.yaw = 0; toast('Back on the street, outside ' + L.b.name); }
      else { you.x = P.gate.x; you.z = P.gate.z + 31; you.face = PI; goal.yaw = 0; }
      goal.pitch = L ? 0.16 : 0.05; goal.dist = you.zoom; goal.tx = cam.tx = you.x; goal.tz = cam.tz = you.z; goal.ty = cam.ty = 1.2; cam.dist = 26; cam.yaw = goal.yaw; cam.pitch = 0.5;
      you.riding = false;
      amb = { x: P.gate.x + 26, z: P.gate.z + 4, face: PI / 2, path: [], to: '', lit: false };
      // Coming in from the Clusters page you choose who you are, the way you do entering a cluster.
      // Coming back out of a building you are already somebody.
      if (!L) choose(true); else you.riding = me.ride > 0;
    }
    /* The chooser of who you are and what you ride: the same one a cluster
       opens, on its stage over where you stand. P opens it again. */
    function choose(first) {
      if (trip || going || K.pick.on()) return;
      keys = {};
      K.pick.open(you.x, 12, you.z, first, { quit: function () { K.pick.close(); }, done: function (was) {
        you.riding = me.ride > 0; you.move = null;
        if (was) { you.y = 11.6; you.vy = 0; }      // you come down from the stage into the street
        toast(K.HEROES[me.hero].name + (me.ride ? ' on a ' + K.RIDES[me.ride].name.toLowerCase() : '') + (was ? ' arrives in the city. Every building is a cluster: walk in by its door' : ' walks on'));
        K.grab(); K.cv.focus({ preventScroll: true });
      } });
    }
    /* Where the experts stand: four on the square at the gate, and four out
       in the city, each beside a building's door. In a city too small for
       that they all stand on the square. */
    function people() {
      var gz = P.gate.z, square = [[-12, gz + 22], [12, gz + 22], [-21, gz + 29], [21, gz + 29], [-12, gz + 36], [12, gz + 36], [-27, gz + 20], [27, gz + 20]];
      var first = ['ceo', 'devops', 'noc', 'pm'], n = P.lots.length, on = 0, out = 0;
      folk = [];
      QZ.EXPERTS.forEach(function (ex) {
        var L, at;
        if (first.indexOf(ex.key) >= 0 || n < 4) at = square[on++];
        else { L = P.lots[Math.floor(n * out++ / 4)]; at = [L.x - L.w / 2 - 2.6, L.dz + 2.8]; }
        folk.push({ ex: ex, x: at[0], z: at[1], home: Math.atan2(-at[0], gz + 30 - at[1]), face: 0, cheer: -99 });
      });
      folk.forEach(function (f) { f.face = f.home; });
    }
    /* The sign every city has: I, a heart, and the name of the place, in
       letters you walk round. The name is the installation's own. */
    function letters() {
      var name = String(stage.getAttribute('data-love') || '').toUpperCase().replace(/[^A-Z0-9 ]/g, '').replace(/\s+/g, ' ').trim().slice(0, 14) || 'KUBERNETES';
      var text = ['I', '\u2665', ' '].concat(name.split('')), px = 0, glyphs = [], s, x0, z = P.gate.z + 13;
      text.forEach(function (ch) {
        var wide = ch === '\u2665' ? 7 : ch === ' ' ? 4 : 5, rows = ch === '\u2665' ? [0x36, 0x7F, 0x7F, 0x7F, 0x3E, 0x1C, 0x08] : null, hex = DOTS[ch], r;
        if (ch !== ' ' && !rows) { if (!hex) return; rows = []; for (r = 0; r < 7; r++) rows.push(parseInt(hex.substr(r * 2, 2), 16)); }
        if (rows) glyphs.push({ px: px, wide: wide, rows: rows, heart: ch === '\u2665' });
        px += wide + 1;
      });
      px -= 1; s = Math.min(0.5, 30 / px); x0 = -px * s / 2;
      sign = { z: z, s: s, w: px * s, bars: [], solid: [], name: name };
      glyphs.forEach(function (gl) {
        var r, c, run;
        sign.solid.push([x0 + gl.px * s, x0 + (gl.px + gl.wide) * s]);
        for (r = 0; r < 7; r++) for (c = 0, run = 0; c <= gl.wide; c++) {      // each run of dots in a row is one bar
          if (c < gl.wide && (gl.rows[r] >> (gl.wide - 1 - c)) & 1) { run++; continue; }
          if (run) sign.bars.push({ x: x0 + (gl.px + c - run / 2) * s, y: 0.3 + (6.5 - r) * s, w: run * s, heart: gl.heart });
          run = 0;
        }
      });
    }

    /* The packets that run the traces. They are scenery: how many there are
       follows only how big the city is. */
    function flow() {
      var n = clamp(P.lots.length + 4, 6, 16), i;
      bits = [];
      for (i = 0; i < n; i++) bits.push({ ns: i % 2 === 0, lane: i % 2 ? P.zs[(i >> 1) % P.zs.length] : P.xs[(i >> 1) % P.xs.length], dir: i % 4 < 2 ? 1 : -1,
        off: (i % 4 < 2 ? 1 : -1) * 1.6, s: rnd(i + 3) * 400, v: 9 + rnd(i * 5 + 1) * 11, c: BITS[i % BITS.length], hex: ('0000' + Math.floor(rnd(i * 9.1) * 65535).toString(16).toUpperCase()).slice(-4) });
    }

    /* ── moving ──────────────────────────────────────────────────────── */
    function door(L) { return { x: L.x, z: L.dz }; }
    function step(t, dt) {
      var mx = (keys.d || keys.ArrowRight ? 1 : 0) - (keys.a || keys.ArrowLeft ? 1 : 0), mz = (keys.w || keys.ArrowUp ? 1 : 0) - (keys.s || keys.ArrowDown ? 1 : 0);
      var sy = Math.sin(goal.yaw), cy = Math.cos(goal.yaw), len = Math.hypot(mx, mz) || 1, ride = you.riding ? K.RIDES[me.ride] : null, sp, vx, vz, key, L, hw, dx, dz, px, pz, best = null, bd = 3.2, d;
      while (steps.length && t - steps[0].at > 2.2) steps.shift();
      if (going || K.pick.on()) { you.moving = false; you.v = 0; return; }
      if (trip) {      // the flying taxi: up over the roofs and down at the door
        var u = clamp((t - trip.at) / trip.dur, 0, 1), e = K.ease(u);
        you.x = trip.x0 + (trip.x1 - trip.x0) * e; you.z = trip.z0 + (trip.z1 - trip.z0) * e; you.y = Math.sin(u * PI) * trip.high;
        you.face = Math.atan2(trip.x1 - trip.x0, trip.z1 - trip.z0); you.moving = false; you.v = 0;
        goal.pitch = trip.pitch + (0.6 - trip.pitch) * Math.sin(u * PI);      // and you look down on the city from it
        if (u >= 1) { you.y = 0; goal.pitch = trip.pitch; toast('The taxi set you down outside ' + trip.name); trip = null; K.sfx('tick'); }
        return;
      }
      sp = 4.8 * (ride ? ride.speed * (keys.Shift ? 1.5 : 1) : keys.Shift ? 1.96 : 1) * (has('coffee') ? 1.2 : 1);
      vx = (cy * mx - sy * mz) / len * sp; vz = (-sy * mx - cy * mz) / len * sp;
      you.moving = !!(mx || mz); you.v = you.moving ? sp : 0;
      if (you.moving) { you.x += vx * dt; you.z += vz * dt; you.face = Math.atan2(vx, vz); you.step += dt * sp; you.move = null; }
      // a jump, because a street wants one
      if (keys[' '] && you.y <= 0 && !you.riding) { you.vy = 6.2; K.sfx('tick'); }
      if (you.y > 0 || you.vy > 0) { you.y += you.vy * dt; you.vy -= 17 * dt; if (you.y <= 0) { you.y = 0; you.vy = 0; } }
      // buildings are solid; the nearest door within reach is the one E opens
      for (key in lots) {
        L = lots[key]; hw = L.w / 2 + 0.45; dx = you.x - L.x; dz = you.z - L.bz;
        if (Math.abs(dx) < hw && Math.abs(dz) < hw && you.y < L.hh) {
          // walking in at the door is going in
          if (dz > 0 && Math.abs(dx) < 1.0 && vz < -0.5 && you.moving) { enter(L); return; }
          px = hw - Math.abs(dx); pz = hw - Math.abs(dz);
          if (px < pz) you.x = L.x + (dx < 0 ? -hw : hw); else you.z = L.bz + (dz < 0 ? -hw : hw);
        }
        d = Math.hypot(you.x - L.x, you.z - (L.dz + 0.8));
        if (d < bd) { bd = d; best = L; }
      }
      // the letters of the sign are solid, and so is anybody standing in the street
      if (sign && Math.abs(you.z - sign.z) < 1.0 && you.y < 3.6) sign.solid.forEach(function (g2) {
        if (you.x > g2[0] - 0.4 && you.x < g2[1] + 0.4) you.z = sign.z + (you.z < sign.z ? -1.0 : 1.0);
      });
      who = null;
      folk.forEach(function (f) {
        d = Math.hypot(you.x - f.x, you.z - f.z);
        if (d < 0.8 && d > 1e-4) { you.x = f.x + (you.x - f.x) / d * 0.8; you.z = f.z + (you.z - f.z) / d * 0.8; }
        if (d < (who ? who.d : 3.2)) who = { f: f, d: d };
      });
      who = who && who.f;
      if (chat && Math.hypot(you.x - chat.f.x, you.z - chat.f.z) > 6.5) chatClose();      // walking away ends the conversation
      if (you.moving && has('trail') && (!steps.length || Math.hypot(steps[steps.length - 1].x - you.x, steps[steps.length - 1].z - you.z) > 0.7)) steps.push({ x: you.x, z: you.z, at: t });
      near = best; beside = null;
      for (key in lots) { L = lots[key]; d = Math.hypot(you.x - L.x, you.z - (L.dz + 2)); if (d < (beside ? beside.d : BESIDE)) beside = { L: L, d: d }; }
      beside = beside && beside.L;
      var lim = P.w / 2 + 26, lz = P.d / 2 + 40;
      you.x = clamp(you.x, -lim, lim); you.z = clamp(you.z, -lz, lz);
    }
    function enter(L) {
      if (going || trip) return;
      going = { L: L, at: performance.now() / 1000 };
      keys = {}; stage.classList.add('going'); fade.classList.add('on'); K.sfx('whoosh');
      if (K.locked()) document.exitPointerLock();
      setTimeout(function () {
        location.href = '/clusters/3d?project=' + encodeURIComponent(L.b.pid) + '&cluster=' + encodeURIComponent(L.cid) + '&from=city';
      }, 520);
    }
    /* A conversation with an expert. It is held in the same panel a pod's is,
       with the same number keys. It asks nothing of the portal: what an
       expert says of the clusters is made from what the street already
       holds, and its questions come with the page. */
    function chatSay(text) { $('c3dTalkSay').textContent = text; }
    function chatOpts(opts) {
      var box2 = $('c3dTalkOpts'); chat.opts = opts; K.clear(box2);
      opts.forEach(function (op, i) {
        var b = K.el('button', 'c3d-opt'); b.type = 'button';
        b.appendChild(K.el('kbd', '', i < 9 ? String(i + 1) : '')); b.appendChild(K.el('span', '', op[0]));
        b.addEventListener('click', function () { if (chat) op[1](); });
        box2.appendChild(b);
      });
    }
    function chatOpen(f) {
      if (chat || trip || going || K.pick.on()) return;
      chat = { f: f, opts: [], q: null }; keys = {};
      if (K.locked()) document.exitPointerLock();
      $('c3dTalk').hidden = false; $('c3dTalkOut').hidden = true; stage.classList.add('talking');
      $('c3dTalkWho').textContent = f.ex.role + '   ·   ' + QZ.SUBJECTS[f.ex.subjects[0]];
      chatHome(f.ex.hello);
    }
    function chatHome(line) {
      var ex = chat.f.ex;
      chatSay(line);
      chatOpts([['How are our clusters?', function () { chatHome(QZ.brief(ex, data)); }], ['Ask me a Kubernetes question', quiz],
        ['What have I won?', function () { chatHome(prizes()); }], ['Goodbye', chatClose]]);
    }
    function prizes() {
      var got = QZ.EXPERTS.filter(function (ex) { return has(ex.gift); });
      return 'You have ' + plural(bag.stars, 'star') + (got.length ? ', and ' + got.map(function (ex) { return ex.has; }).join('; ') + '.' : '. Nobody has given you anything yet: answer one of us rightly.')
        + (got.length < QZ.EXPERTS.length ? ' ' + plural(QZ.EXPERTS.length - got.length, 'expert') + ' still ' + (QZ.EXPERTS.length - got.length === 1 ? 'has' : 'have') + ' something for you.' : ' That is everything we have to give.');
    }
    function quiz() {
      var q = QZ.next(chat.f.ex, bag.seen, data, Math.random);
      save(); chat.q = q; chatSay(q.q);
      chatOpts(q.options.map(function (o, i) { return [o, function () { answer(i); }]; }));
    }
    function answer(i) {
      var q = chat.q, f = chat.f, ex = f.ex, right = q && i === q.right, first;
      if (!q) return;
      chat.q = null;
      if (right) {
        bag.stars++; first = !has(ex.gift); if (first) bag.gifts[ex.gift] = 1; save(); celebrate(f, first);
        chatSay('Yes! ' + q.why + (first ? ' Here, this is for you: ' + ex.has + '.' : ' That makes ' + plural(bag.stars, 'star') + '.'));
      } else { K.beep(196, 0.22, 0.05, 'sawtooth'); chatSay('Not quite. It is: ' + q.options[q.right] + '. ' + q.why); }
      chatOpts([['Another question', quiz], ['How are our clusters?', function () { chatHome(QZ.brief(ex, data)); }], ['Goodbye', chatClose]]);
    }
    function chatClose() {
      if (!chat) return;
      chat = null; $('c3dTalk').hidden = true; stage.classList.remove('talking');
    }
    /* A right answer: the expert does its own move and so do you, paper flies,
       and a few notes go up. The first from each expert is its gift, and
       every fifth star sets off the fireworks. */
    function celebrate(f, first) {
      var now = performance.now() / 1000, i;
      f.cheer = now; if (!you.riding) you.move = { at: now, dur: 1.6 };
      confetti((you.x + f.x) / 2, 2.6, (you.z + f.z) / 2, first ? 70 : 34);
      [523, 659, 784, 1047].forEach(function (hz, n) { K.beep(hz, 0.16, 0.05, 'triangle', n * 0.09); });
      if (first) { K.sfx('heal'); toast('The ' + f.ex.role + ' gave you ' + f.ex.has); } else toast('Right! ' + plural(bag.stars, 'star'));
      if (bag.stars % 5 === 0) { party = now; toast(plural(bag.stars, 'star') + '! The city puts on fireworks for you'); }
    }
    function confetti(x, y, z, n) {
      var i, a, up, now = performance.now() / 1000;
      if (calm) return;
      for (i = 0; i < n; i++) { a = Math.random() * TAU; up = Math.random(); bits2.push({ x: x, y: y, z: z, vx: Math.cos(a) * (1 + up * 2.4), vy: 2.5 + up * 4.5, vz: Math.sin(a) * (1 + up * 2.4), c: DCOL[i % DCOL.length], at: now }); }
      if (bits2.length > 400) bits2.splice(0, bits2.length - 400);
    }
    /* The taxi takes you to whoever needs help most, and to the next one on
       the next call. With nobody in trouble it has nowhere urgent to go. */
    function taxi() {
      var list = needy(data.buildings), now = performance.now() / 1000, b, L;
      if (trip || going) return;
      if (!list.length) { toast(data.totals.reading ? 'The taxi is waiting: the city is still being read' : 'The taxi has nowhere urgent to take you: no building is asking for help'); return; }
      b = list[taxiAt++ % list.length]; L = lots[b.cid];
      trip = { x0: you.x, z0: you.z, x1: L.x + 5.2, z1: L.dz + 5.6, at: now, name: b.name, high: 0, dur: 0, pitch: goal.pitch };
      trip.dur = clamp(Math.hypot(trip.x1 - trip.x0, trip.z1 - trip.z0) / 55, 1.4, 4); trip.high = clamp(Math.hypot(trip.x1 - trip.x0, trip.z1 - trip.z0) * 0.35, 6, 54);
      you.riding = false; K.sfx('whoosh'); toast('Taxi! To ' + b.name + ': ' + plural(b.pods.bad, 'pod') + ' failing');
    }
    /* The camera stays outside the walls: where a building stands between it
       and you, it comes in to just this side of it. */
    function clip(dist) {
      var cp = Math.cos(goal.pitch), ox = cp * Math.sin(goal.yaw), oy = Math.sin(goal.pitch), oz = cp * Math.cos(goal.yaw), tx = you.x, ty = you.y + 1.2, tz = you.z, best = dist, key, L, hw, t0, t1, a, b, i, o, dir, lo, hi;
      for (key in lots) {
        L = lots[key]; hw = L.w / 2 + 0.3; t0 = 0; t1 = best;
        o = [tx - L.x, ty, tz - L.bz]; dir = [ox, oy, oz]; lo = [-hw, -1, -hw]; hi = [hw, L.hh + 0.4, hw];
        for (i = 0; i < 3 && t0 <= t1; i++) {
          if (Math.abs(dir[i]) < 1e-6) { if (o[i] < lo[i] || o[i] > hi[i]) t0 = t1 + 1; continue; }
          a = (lo[i] - o[i]) / dir[i]; b = (hi[i] - o[i]) / dir[i];
          t0 = Math.max(t0, Math.min(a, b)); t1 = Math.min(t1, Math.max(a, b));
        }
        if (t0 <= t1 && t0 > 0.05) best = Math.min(best, t0 * 0.94);
      }
      return Math.max(0.9, best);
    }
    /* Whether a point can be seen from the camera, or a building is in the way. */
    function seen(x, y, z, own) {
      var e = K.eye(), dx = x - e[0], dy = y - e[1], dz = z - e[2], key, L, hw, t0, t1, a, b, i, o, dir, lo, hi, n, gz = P.gate.z;
      // the gate's two boards and its arch hide what stands behind them, like a building does; in a hall, the screens, where they stand
      var walls = own === GATE ? [] : screens ? screens.map(function (s) { return [s.x, s.z, s.w / 2 + 0.2, s.y - s.h / 2 - 0.2, s.y + s.h / 2 + 0.2]; })
        : [[-15, gz, 5.2, 3.0, 7.9], [15, gz, 5.2, 3.0, 7.9], [0, gz, 7.4, 6.7, 8.5]];
      for (n = 0; n < walls.length; n++) {
        t0 = 0; t1 = 0.985; o = [e[0] - walls[n][0], e[1], e[2] - walls[n][1]]; dir = [dx, dy, dz]; lo = [-walls[n][2], walls[n][3], -0.3]; hi = [walls[n][2], walls[n][4], 0.3];
        for (i = 0; i < 3 && t0 <= t1; i++) {
          if (Math.abs(dir[i]) < 1e-6) { if (o[i] < lo[i] || o[i] > hi[i]) t0 = t1 + 1; continue; }
          a = (lo[i] - o[i]) / dir[i]; b = (hi[i] - o[i]) / dir[i];
          t0 = Math.max(t0, Math.min(a, b)); t1 = Math.min(t1, Math.max(a, b));
        }
        if (t0 <= t1) return false;
      }
      for (key in lots) {
        L = lots[key]; if (L === own) continue;
        hw = L.w / 2; t0 = 0; t1 = 0.985; o = [e[0] - L.x, e[1], e[2] - L.bz]; dir = [dx, dy, dz]; lo = [-hw, 0, -hw]; hi = [hw, L.hh, hw];
        for (i = 0; i < 3 && t0 <= t1; i++) {
          if (Math.abs(dir[i]) < 1e-6) { if (o[i] < lo[i] || o[i] > hi[i]) t0 = t1 + 1; continue; }
          a = (lo[i] - o[i]) / dir[i]; b = (hi[i] - o[i]) / dir[i];
          t0 = Math.max(t0, Math.min(a, b)); t1 = Math.min(t1, Math.max(a, b));
        }
        if (t0 <= t1) return false;
      }
      return true;
    }

    /* ── what stands on the street ───────────────────────────────────── */
    function ground(t) {
      var c, i, z, x;
      slab(0, -0.3, 8, P.w + 90, 0.6, P.d + 130, ASPHALT, 0.05);
      // the lots: a pavement in its district's colour, and bare board where no building stands
      P.lots.forEach(function (o) { c = DCOL[o.di % DCOL.length]; slab(o.x, 0.07, o.z, LOT, 0.14, LOT, [c[0] * 0.55, c[1] * 0.55, c[2] * 0.55], 0.5); });
      P.parks.forEach(function (o) { slab(o.x, 0.07, o.z, LOT, 0.14, LOT, PCB, 0.35); });
      P.heads.forEach(function (hd) { metal(hd.x + 0.6, 2.7, hd.z + 0.6, 0.22, 5.4, 0.22, DCOL[hd.di % DCOL.length], 0.6); });      // where a district begins
      // a lamp at each corner of a lot, and a chip where no building stands
      P.lots.forEach(function (o) {
        if (Math.hypot(o.x - you.x, o.z - you.z) > 70) return;
        for (i = 0; i < 2; i++) {      // two, on the street side
          x = o.x + (i % 2 ? 1 : -1) * (LOT / 2 - 0.7); z = o.z + (LOT / 2 - 0.7);
          metal(x, 1.9, z, 0.14, 3.8, 0.14, DCOL[o.di % DCOL.length], 0.2); K.glo(x, 3.9, z, 1.5, K.TONEF.idle || WHITE, 0.55); K.glo(x, 0.3, z, 5.2, [1.0, 0.86, 0.6], 0.12);
        }
      });
      if (!K.hall) P.parks.forEach(function (o) { if (Math.hypot(o.x - you.x, o.z - you.z) < 95) chip(o, t); });      // in a hall a rack block stands there instead
    }
    /* Which window is which: the same windows are lit on every visit, and the
       wall with the door is filled first, so a failing pod shows where you
       walk up. */
    function order(L, cols, rows) {
      var n = cols * rows * 4, idx = [], i;
      for (i = 0; i < n; i++) idx.push(i);
      idx.sort(function (a, b) { return (a < cols * rows ? 0 : 1) + rnd(L.seed * 97 + a) - ((b < cols * rows ? 0 : 1) + rnd(L.seed * 97 + b)); });
      L.order = new Array(n); idx.forEach(function (k, rank) { L.order[k] = rank; }); L.cols = cols; L.rows = rows;
    }
    /* The helm on a roof: a ship's wheel of seven spokes, turned to face
       whoever is looking, so it is a wheel from every street. */
    function helm(x, y, z, R, yaw, a0, c, rim, glow) {
      var cs = Math.cos(yaw), sn = Math.sin(yaw), i, a;
      function at(ox, oy, sx, sy, sz, tip, col2) { K.solid(K.BOX, x + ox * cs, y + oy, z - ox * sn, sx, sy, sz, col2, glow, yaw, 0, tip); }
      for (i = 0; i < 7; i++) { a = a0 + i * TAU / 7; at(-Math.sin(a) * R * 0.56, Math.cos(a) * R * 0.56, R * 0.13, R * 1.12, R * 0.13, a, c); }
      for (i = 0; i < 14; i++) { a = a0 + i * TAU / 14; at(-Math.sin(a) * R * 0.8, Math.cos(a) * R * 0.8, R * 0.4, R * 0.15, R * 0.17, a, rim); }
      K.solid(K.BALL, x, y, z, R * 0.44, R * 0.44, R * 0.3, c, glow, yaw, 0, 0);
    }
    function building(L, t, dt, e) {
      var b = L.b, st = b.state, w = L.w, x = L.x, z = L.bz, hw = w / 2, dc = DCOL[L.di % DCOL.length], sc = col(b), far = Math.hypot(x - you.x, z - you.z);
      var h, g0, i, f, j, k, n, wn, pulse, u, y, c, dw = w - 1.0, live, yb, dead, R, cy, wx, out, red;
      L.hh += (L.h - L.hh) * (calm ? 1 : Math.min(1, dt * 1.6)); h = L.hh; g0 = h / L.h;      // it rises to its height when it is first read
      pulse = calm ? 1 : 0.75 + 0.25 * Math.sin(t * (st === 'bad' ? 5 : 1.4) + L.seed * 9);
      // the base: the control plane, in the blue of the thing, with the one door in
      metal(x, BASE * g0 / 2, z, w, BASE * g0, w, st === 'down' ? DOWNC : K8S, st === 'down' ? 0 : 0.4);
      for (i = 0; i < 4; i++) light(x + (i < 2 ? (i ? hw : -hw) : 0), BASE * g0, z + (i > 1 ? (i > 2 ? hw : -hw) : 0), i < 2 ? 0.16 : w + 0.16, 0.16, i < 2 ? w + 0.16 : 0.16, b.prod ? GOLD : sc, st === 'down' ? 0.02 : 0.5 * pulse);
      light(x, 1.3, z + hw + 0.04, 1.9, 2.6, 0.1, st === 'down' ? DOWNC : sc, st === 'down' ? 0.02 : 0.45 + (L === near ? 0.5 : 0));
      box(x, 1.25, z + hw + 0.1, 1.5, 2.3, 0.06, DARK); light(x, 2.75, z + hw + 0.5, 3.4, 0.14, 1.0, K8S, 0.6);
      K.cube(x, 0.16, z + hw + 1.3, 2.2, 0.04, 2.4, sc, 0, 0, 0, st === 'down' ? 0.25 : 0.9, 1);
      if (st !== 'down') K.glo(x, 1.4, z + hw + 0.5, 3.2, sc, 0.35 * pulse);
      // the spine, and a deck for each machine. The top ones are dark where machines are not ready
      metal(x, (BASE + (h - BASE * g0) / 2 / g0) * g0, z, w - 3.6, h - BASE * g0, w - 3.6, st === 'reading' ? READC : dc, 0.1);
      live = Math.max(1, L.decks - L.dark);
      for (i = 0; i < L.decks; i++) {
        yb = (BASE + (i + 1) * DECK) * g0; dead = L.dark && i >= L.decks - L.dark;
        metal(x, yb - 0.16, z, dw, 0.32, dw, st === 'down' ? DOWNC : st === 'reading' ? READC : dead ? BADC : dc, st === 'down' ? 0 : dead ? (calm ? 0.5 : 0.25 + 0.5 * Math.max(0, Math.sin(t * 7 + i * 2))) : 0.3);
      }
      if (st === 'reading') light(x, (calm ? 0.5 : 0.5 + 0.5 * Math.sin(t * 1.1 + L.seed * 6)) * h, z, w + 0.4, 0.1, w + 0.4, READC, 1.2);      // being measured
      if (st === 'down') {
        for (i = 0; i < 3; i++) box(x - 1.6 + i * 1.6, 0.42, z + hw + 2.2, 0.36, 0.56, 0.36, WARNC, calm ? 0.2 : 0.2 + 0.5 * Math.max(0, Math.sin(t * 4 + i)));
        u = calm ? 0.5 : (t * 0.09 + L.seed) % 1;      // nobody home: something dry blows past
        ball(x - 13 + u * 26, 0.55 + Math.abs(Math.sin(u * 40)) * 0.3, z + hw + 6.5, 1.0, 1.0, 1.0, [0.42, 0.33, 0.2], 0);
      }
      // the helm: turning while the cluster answers, still when it does not, gold where it serves production
      R = clamp(w * 0.3, 2.5, 4.0); cy = h + R + 0.9; c = st === 'ok' ? K8S : sc;
      metal(x, h + 0.45, z, 0.34, 0.9, 0.34, c, 0.3);
      helm(x, cy, z, R, Math.atan2(e[0] - x, e[2] - z), calm || st === 'down' ? 0 : t * (st === 'reading' ? 0.9 : st === 'bad' ? 0.1 : 0.25) + L.seed * 6, c, b.prod && st !== 'down' ? GOLD : c, st === 'down' ? 0 : 0.35 * pulse);
      L.top = cy + R;
      if (st !== 'down') K.glo(x, cy, z, R * 2.4, c, 0.3 * pulse);
      if (st === 'bad') K.beam(x, cy + R, z, x, cy + 70, z, BADC, 0.5, 0.5, 0, 1, 0.8, 3, L.seed);
      if (far > 130) return;
      // steam off a building with failing pods; a storm over one whose machines are not all ready
      if (st === 'bad' && b.pods.bad) for (n = clamp(b.pods.bad, 1, 4), i = 0; i < n; i++) {
        u = calm ? i / n : (t * 0.22 + i / n) % 1;
        K.glo(x + Math.sin(i * 2.4) * w * 0.3 + u * 1.6, h + 1 + u * 10, z + Math.cos(i * 1.7) * w * 0.3, 1.3 + u * 3, i % 3 ? MIST : [1.0, 0.5, 0.25], (1 - u) * 0.42);
      }
      if (unready(b)) {
        for (i = 0; i < 5; i++) ball(x + (i - 2) * 1.9, cy + R + 4 + (i % 2) * 0.7, z + (i % 2 ? 0.8 : -0.6), 4.4, 2.3, 3.6, [0.34, 0.36, 0.46], 0.04);
        if (!calm) for (i = 0; i < 9; i++) { u = (t * 1.6 + i / 9) % 1; y = cy + R + 3.2 - u * 5.4; wx = x + (rnd(i + L.seed * 5) - 0.5) * 8; K.beam(wx, y, z + (rnd(i * 3 + 1) - 0.5) * 5, wx - 0.15, y - 0.9, z + (rnd(i * 3 + 1) - 0.5) * 5, [0.5, 0.7, 1.0], 0.5, 0.05, 0, 1, 0, 0, 0); }
        if (!calm && (t + L.seed * 7) % 5.5 < 0.12) K.glo(x, cy + R + 3.4, z, 12, WHITE, 1.6);
      }
      if (far > 100 || st === 'down' || st === 'reading' || !b.pods) return;
      // the pods, standing on the decks of the machines that are ready: one for each pod, as many
      // as the decks hold, and the red ones failing. Only the sides you can see are drawn
      c = clamp(Math.round(dw / 1.5), 3, 7);
      if (!L.order || L.cols !== c || L.rows !== live) order(L, c, live);
      wn = windows(b, c * live * 4); out = dw / 2 - 0.42;
      for (f = 0; f < 4; f++) {
        if (f === 0 ? e[2] < z + hw : f === 1 ? e[2] > z - hw : f === 2 ? e[0] < x + hw : e[0] > x - hw) continue;
        for (i = 0; i < c * live; i++) {
          k = L.order[f * c * live + i]; if (k >= wn.lit) continue;
          j = i % c; wx = ((j + 0.5) / c - 0.5) * (dw - 1.1); y = (BASE + (Math.floor(i / c) + 1) * DECK) * g0 + 0.36; red = k < wn.red;
          u = red ? (calm ? 0.8 : 0.4 + 0.7 * Math.abs(Math.sin(t * 3 + k))) : 0.06 + rnd(k + L.seed) * 0.1;
          if (f < 2) light(x + wx, y, z + (f ? -out : out), 0.82, 0.66, 0.62, red ? BADC : POD, u);
          else light(x + (f === 2 ? out : -out), y, z + wx, 0.62, 0.66, 0.82, red ? BADC : POD, u);
        }
      }
    }
    /* The crowd outside: a pod for each failing pod the portal can name, with
       its reason on a placard; outside a building that is well, one pod with
       nothing to complain of. Outside one nobody could ask, nobody: there is
       nobody to speak for. */
    function crowd(L, t) {
      var b = L.b, i, m, x, z, y, hop, face, n;
      if (!L.crowd) {
        L.crowd = [];
        if (b.state === 'bad') b.problems.slice(0, CROWD).forEach(function (p, j, all) { L.crowd.push({ p: p, ox: (j - (all.length - 1) / 2) * 2.0, oz: 3.6, seed: rnd(j + L.seed * 3) }); });
        else if (b.state === 'ok') L.crowd.push({ ox: 0, oz: 4.2, seed: L.seed, well: true });
      }
      if (Math.hypot(L.x - you.x, L.dz - you.z) > 60) return;
      for (i = 0; i < L.crowd.length; i++) {
        m = L.crowd[i]; x = L.x + m.ox + (m.well && !calm ? Math.sin(t * 0.35 + m.seed * 9) * 4.2 : 0); z = L.dz + m.oz;
        hop = calm ? 0 : m.well ? Math.abs(Math.sin(t * 2 + m.seed * 9)) * 0.08 : Math.abs(Math.sin(t * 4.2 + m.seed * 20)) * 0.3; y = 0.6 + hop;
        face = Math.atan2(you.x - x, you.z - z); m.x = x; m.z = z; m.y = y;
        K.orb(x, y, z, 0.44, m.well ? OKC : BADC, 1, face, 0.1, K.MOOD[m.well ? 'happy' : m.p.status === 'Pending' ? 'sleeping' : m.p.restarts ? 'dizzy' : 'crying'], m.seed, -1, -1, 1, 0);
        K.shad(x, z, 0.5, 0.5);
        // the placards come down while one of the crowd is speaking to you
        if (!m.well && !crowdSay) { box(x + 0.5, y + 0.75, z, 0.07, 1.5, 0.07, [0.5, 0.4, 0.3]); box(x + 0.5, y + 1.7, z, 1.6, 0.6, 0.06, [0.8, 0.82, 0.86], 0, face); }
      }
    }
    /* The streets are traces on a board: lines of light with data running
       along them, and a pad where two cross. On the pads the city's gears
       turn, as fast as its clusters say their CPU is busy, and not at all
       when none has said. */
    function traces(t) {
      var x0 = P.xs[0], x1 = P.xs[P.xs.length - 1], z0 = P.zs[0], z1 = P.zs[P.zs.length - 1], spin = busy0 == null || calm ? 0 : t * (0.25 + busy0 / 100 * 2.6), i, j, k, a, x, z;
      P.xs.forEach(function (sx, n) {
        if (Math.abs(sx - you.x) > 120) return;
        K.beam(sx, 0.05, z0, sx, 0.05, z1, BITS[n % 2], 0.6, 0.1, 0, 1, n % 2 ? 1.3 : -1.3, 2, n * 0.37);
      });
      P.zs.forEach(function (sz, n) {
        if (Math.abs(sz - you.z) > 120) return;
        K.beam(x0, 0.05, sz, x1, 0.05, sz, BITS[n % 2], 0.6, 0.1, 0, 1, n % 2 ? -1.3 : 1.3, 2, n * 0.53);
      });
      for (i = 0; i < P.xs.length; i++) for (j = 0; j < P.zs.length; j++) {
        x = P.xs[i]; z = P.zs[j]; if (Math.hypot(x - you.x, z - you.z) > 75) continue;
        if ((i + j) % 2) continue;
        ball(x, 0.2, z, 2.0, 0.3, 2.0, [0.2, 0.22, 0.28], 0);      // and, on every other, a gear
        for (k = 0; k < 8; k++) { a = spin * ((i + j) % 4 ? 1 : -1) + k * TAU / 8; box(x + Math.sin(a) * 1.15, 0.2, z + Math.cos(a) * 1.15, 0.46, 0.26, 0.7, [0.3, 0.33, 0.4], 0, a); }
        light(x, 0.37, z, 0.5, 0.06, 0.5, busy0 == null ? DOWNC : LEVELC[level(busy0)], 0.6);
      }
    }
    /* A packet: a crystal of light with a tail, hurrying along a trace. One
       that meets you goes straight through, and says so now and then. */
    function packets(t, dt) {
      bits.forEach(function (c) {
        var span = (c.ns ? P.d : P.w) + ROAD * 2 + 40, u = ((c.s % span) + span) % span - span / 2, x, z, hx, hz;
        if (!calm) c.s += c.v * dt * c.dir;
        x = c.ns ? c.lane + c.off : u; z = c.ns ? u : c.lane + c.off;
        if (Math.hypot(x - you.x, z - you.z) > 110) return;
        hx = c.ns ? 0 : -c.dir; hz = c.ns ? -c.dir : 0;
        K.cube(x, 0.75, z, 0.5, 0.5, 0.5, c.c, 1, t * 3 + c.s, 0, 1, 2);
        K.beam(x, 0.75, z, x + hx * 3.4, 0.75, z + hz * 3.4, c.c, 0.7, 0.12, 0, 1, 0, 0, 0); K.glo(x, 0.75, z, 1.3, c.c, 0.8);
        c.x = x; c.z = z;
        if (Math.hypot(x - you.x, z - you.z) < 0.8 && you.y < 1.3 && !trip && t - hitAt > 14) {
          hitAt = t; K.beep(1320, 0.07, 0.04, 'square'); K.beep(1760, 0.09, 0.04, 'square', 0.07);
          toast('Packet 0x' + c.hex + ' went straight through you. That is what packets do.');
        }
      });
    }
    /* The pipeline, flying the ring: one drone for each stage, each with its
       crate. They are the city's own machinery and belong to no cluster. */
    function drones(t) {
      var w = P.xs[P.xs.length - 1] - P.xs[0], d = P.zs[P.zs.length - 1] - P.zs[0], per = 2 * (w + d), x0 = P.xs[0], z0 = P.zs[0];
      droneAt.length = 0;
      STAGES.forEach(function (name, i) {
        var u = (((calm ? 0 : t * 11) + i * 13) % per + per) % per, x, z, yaw, y = 6.4 + (calm ? 0 : Math.sin(t * 1.3 + i) * 0.35), k, c = BITS[i % BITS.length];
        if (u < w) { x = x0 + u; z = z0; yaw = PI / 2; } else if (u < w + d) { x = x0 + w; z = z0 + u - w; yaw = 0; }
        else if (u < 2 * w + d) { x = x0 + w - (u - w - d); z = z0 + d; yaw = -PI / 2; } else { x = x0; z = z0 + d - (u - 2 * w - d); yaw = PI; }
        droneAt.push({ x: x, y: y, z: z, name: name });
        if (Math.hypot(x - you.x, z - you.z) > 140) return;
        box(x, y, z, 1.5, 0.3, 1.5, [0.16, 0.18, 0.24], 0, yaw); light(x, y + 0.18, z, 0.5, 0.06, 0.5, c, 1.2);
        for (k = 0; k < 4; k++) K.glo(x + (k % 2 ? 0.95 : -0.95), y + 0.2, z + (k < 2 ? 0.95 : -0.95), 1.0, c, calm ? 0.5 : 0.5 + 0.3 * Math.sin(t * 30 + k));
        metal(x, y - 0.55, z, 0.05, 0.8, 0.05, c, 0.4); box(x, y - 1.35, z, 1.3, 0.9, 1.9, [c[0] * 0.55, c[1] * 0.55, c[2] * 0.55], 0.1, yaw);
        K.shad(x, z, 1.4, 0.3);
      });
    }
    var droneAt = [];
    /* Data falling beyond the last street, the way a machine looks from the
       inside when it is working. Scenery. */
    function rain(t) {
      var r = Math.max(P.w, P.d) / 2 + 46, i, a, x, z;
      if (calm) return;
      for (i = 0; i < 18; i++) {
        a = i / 18 * TAU + rnd(i) * 0.1; x = Math.cos(a) * r * (0.92 + rnd(i * 3) * 0.3); z = Math.sin(a) * r * (0.92 + rnd(i * 7) * 0.3) + 8;
        K.beam(x, 62, z, x, 0.5, z, BITS[i % 2], 0.2, 0.18, 0, 1, 1.1 + rnd(i) * 1.6, 3, rnd(i * 5) * 9);
      }
    }
    /* Where no building stands, the board carries a chip: its pins down two
       sides, a heat sink on its back, and a row of capacitors beside it. */
    function chip(o, t) {
      var i, x = o.x, z = o.z;
      box(x, 0.55, z, 9, 0.8, 9, [0.05, 0.055, 0.07], 0); light(x, 0.97, z, 9.1, 0.04, 9.1, PCB, 0.25);
      for (i = 0; i < 9; i++) { box(x - 4.9, 0.3, z - 4 + i, 0.8, 0.14, 0.34, PIN); box(x + 4.9, 0.3, z - 4 + i, 0.8, 0.14, 0.34, PIN); }
      for (i = 0; i < 7; i++) box(x - 2.7 + i * 0.9, 1.5, z, 0.22, 1.1, 6.4, [0.5, 0.53, 0.6]);      // the fins of its heat sink
      for (i = 0; i < 4; i++) { ball(x - 3.3 + i * 2.2, 1.0, z + 7.6, 1.1, 2.0, 1.1, [0.12, 0.2, 0.5], 0); ball(x - 3.3 + i * 2.2, 2.0, z + 7.6, 0.9, 0.2, 0.9, PIN, 0); }
      light(x + 3.6, 1.0, z + 3.6, 0.5, 0.06, 0.5, OKC, calm ? 0.6 : 0.4 + 0.6 * Math.max(0, Math.sin(t * 2 + o.x)));
    }
    /* Two columns by a door: how much of the cluster's CPU and memory is in
       use, as the hub counts it. A frame stands for all of it, and the column
       in it for the part in use. A cluster that gave no figure has no column. */
    function meters(L) {
      var b = L.b, x = L.x + L.w / 2 + 1.6, z = L.dz + 1.6, i, v, FULL = 4.6;
      if (b.cpu == null && b.mem == null) return;
      for (i = 0; i < 2; i++) {
        v = i ? b.mem : b.cpu; if (v == null) continue;
        metal(x + i * 1.1, FULL / 2 + 0.14, z, 0.74, FULL, 0.74, i ? MEMC : CPUC, 0.15);
        light(x + i * 1.1, 0.14 + FULL * clamp(v, 0, 100) / 200, z, 0.6, Math.max(0.05, FULL * clamp(v, 0, 100) / 100), 0.6, LEVELC[level(v)], 0.04);
      }
    }
    /* The load board at the gate: every cluster's two columns side by side.
       A cluster with no figure keeps its place and stands empty. */
    function loadBoard() {
      var n = P.lots.length, gap = Math.min(1.2, 18 / Math.max(1, n)), x0 = 31 - (n - 1) * gap / 2, z = P.gate.z + 6, FULL = 4;
      box(31, 0.12, z, Math.max(8, n * gap + 3), 0.24, 4.6, [0.04, 0.05, 0.08]); light(31, 0.25, z + 2.2, Math.max(8, n * gap + 3), 0.05, 0.1, CPUC, 0.8);
      board0.x = 31; board0.z = z; board0.cols = [];
      P.lots.forEach(function (L, i) {
        var b = L.b, x = x0 + i * gap;
        board0.cols.push({ x: x, b: b });
        if (b.cpu == null) { box(x, 0.4, z, gap * 0.5, 0.3, 0.5, DOWNC); return; }
        light(x - gap * 0.2, 0.25 + FULL * clamp(b.cpu, 0, 100) / 200, z, gap * 0.32, Math.max(0.05, FULL * clamp(b.cpu, 0, 100) / 100), 0.6, CPUC, 0.02);
        if (b.mem != null) light(x + gap * 0.2, 0.25 + FULL * clamp(b.mem, 0, 100) / 200, z, gap * 0.32, Math.max(0.05, FULL * clamp(b.mem, 0, 100) / 100), 0.6, MEMC, 0.02);
      });
    }
    var board0 = { x: 0, z: 0, cols: [] };
    /* The medic: a drone with a red cross and two lamps. */
    function medic(x, y, z, yaw, lit, t) {
      var k, c = Math.floor(t * 4) % 2 ? BADC : [0.3, 0.5, 1.0];
      box(x, y, z, 1.9, 0.6, 2.6, WHITE, 0.05, yaw); box(x, y + 0.32, z, 0.34, 0.06, 1.2, BADC, 0.5, yaw); box(x, y + 0.32, z, 1.2, 0.06, 0.34, BADC, 0.5, yaw);
      for (k = 0; k < 4; k++) K.glo(x + (k % 2 ? 1.3 : -1.3), y + 0.25, z + (k < 2 ? 1.5 : -1.5), 1.1, WHITE, calm ? 0.5 : 0.45 + 0.3 * Math.sin(t * 28 + k));
      if (lit) { K.glo(x, y + 0.6, z, 3.4, c, calm ? 0.8 : 1.6); K.beam(x, y - 0.3, z, x, 0.1, z, c, 0.35, 0.5, 0, 1, 1.2, 3, 0); }
      K.shad(x, z, 1.8, 0.45);
    }
    /* The ambulance, a medic drone, goes to the building with the most
       failing pods, along the streets, and waits over its forecourt with its
       lamps going. With nobody failing it hangs at the gate with them off. */
    function ambulance(t, dt) {
      var list = needy(data.buildings).filter(function (b) { return b.pods.bad; }), want = list.length ? list[0].cid : '', L, vx, p, d, k;
      if (want !== amb.to) {
        amb.to = want; L = lots[want];
        if (L) { vx = P.xs.reduce(function (a, b) { return Math.abs(b - amb.x) < Math.abs(a - amb.x) ? b : a; }); amb.path = [[vx, amb.z], [vx, L.sz + 2.3], [L.x - 3.5, L.sz + 2.3]]; }
        else amb.path = [[P.gate.x + 26, P.gate.z + 4]];
      }
      amb.lit = !!want;
      if (amb.path.length) {
        p = amb.path[0]; d = Math.hypot(p[0] - amb.x, p[1] - amb.z); k = (calm ? 1e9 : 15 * dt);
        if (d <= k) { amb.x = p[0]; amb.z = p[1]; amb.path.shift(); } else { amb.face = Math.atan2(p[0] - amb.x, p[1] - amb.z); amb.x += (p[0] - amb.x) / d * k; amb.z += (p[1] - amb.z) / d * k; }
        // its siren, where you can hear it
        if (amb.lit && !calm && Math.hypot(amb.x - you.x, amb.z - you.z) < 45 && Math.floor(t * 2) !== amb.beat) { amb.beat = Math.floor(t * 2); K.beep(amb.beat % 2 ? 660 : 880, 0.42, 0.025, 'sine'); }
      }
      if (Math.hypot(amb.x - you.x, amb.z - you.z) > 130) return;
      medic(amb.x, 3.1 + (calm ? 0 : Math.sin(t * 1.7) * 0.2), amb.z, amb.face, amb.lit, t);
    }
    function gate(t) {
      var z = P.gate.z, i;
      for (i = -1; i <= 1; i += 2) metal(i * 6.5, 3.6, z, 0.7, 7.2, 0.7, DCOL[0], 0.5);
      metal(0, 7.6, z, 14.4, 1.6, 0.8, DCOL[0], 0.6); light(0, 6.7, z, 13, 0.1, 0.9, data.totals.bad ? BADC : data.totals.reading || data.totals.down ? READC : OKC, 0.9);
      // the two boards, one each side of the gate
      for (i = -1; i <= 1; i += 2) {
        if (!K.hall) {      // a hall's engine stands a screen there, on feet of its own
          metal(i * 10.4, 1.6, z, 0.3, 3.2, 0.3, DCOL[1], 0.3); metal(i * 19.6, 1.6, z, 0.3, 3.2, 0.3, DCOL[1], 0.3);
          box(i * 15, 5.4, z, 10, 4.6, 0.3, [0.03, 0.04, 0.07]); light(i * 15, 5.4, z - 0.17, 10.3, 4.9, 0.04, i < 0 ? WARNC : DCOL[0], 0.12);
        }
      }
      // the crier, under the news: it looks the way the news is
      var tt = data.totals, cm = tt.bad ? 'worried' : tt.reading || tt.down ? 'hatching' : 'happy';
      crier = { x: -9, y: 0.62 + (calm ? 0 : Math.abs(Math.sin(t * 3)) * (tt.bad ? 0.22 : 0.07)), z: z + 5 };
      K.orb(crier.x, crier.y, crier.z, 0.46, tt.bad ? WARNC : OKC, 1, Math.atan2(you.x - crier.x, you.z - crier.z), 0.1, K.MOOD[cm], 0.37, -1, -1, 1, 0); K.shad(crier.x, crier.z, 0.5, 0.5);
      box(crier.x - 0.75, 0.3, crier.z, 0.6, 0.6, 0.5, [0.75, 0.75, 0.7]);      // its pile of papers
      // fireworks, and only when there is nothing left to say: every cluster answered, every pod well
      if (!calm && tt.clusters && !tt.bad && !tt.down && !tt.reading) for (i = 0; i < 3; i++) {
        var fu = (t * 0.33 + i / 3) % 1, fk = Math.floor(t * 0.33 + i / 3), fxx = (rnd(fk * 3.1 + i) - 0.5) * P.w * 0.8, fzz = (rnd(fk * 7.7 + i) - 0.5) * P.d * 0.8, fr = (fu - 0.25) * 24, j, fa;
        if (fu < 0.25) { K.glo(fxx, 6 + fu * 190, fzz, 1.2, GOLD, 1); continue; }      // it climbs, then it opens
        for (j = 0; j < 14; j++) { fa = j / 14 * TAU; K.glo(fxx + Math.cos(fa) * fr, 53 + Math.sin(fa) * fr * 0.8 - fr * fr * 0.02, fzz + Math.sin(fa * 2.3) * fr * 0.5, 1.6, DCOL[(fk + j) % DCOL.length], (1 - fu) * 1.4); }
      }
    }
    /* The square at the gate: paving, the sign, and two lights sweeping the
       sky from the gate's posts, the way a place announces itself. */
    function square(t) {
      var gz = P.gate.z, i, b, beat = calm ? 0.6 : 0.45 + 0.55 * Math.pow(Math.abs(Math.sin(t * 2.2)), 6);
      slab(0, 0.04, gz + 23, 70, 0.08, 40, [0.26, 0.32, 0.56], 0.45);
      if (!calm) for (i = -1; i <= 1; i += 2) K.beam(i * 6.5, 7.4, gz, i * 6.5 + Math.sin(t * 0.37 + i) * 46, 96, gz - 50 + Math.cos(t * 0.29 + i) * 34, WHITE, 0.16, 1.3, 0, 1, 0, 0, 0);
      if (!sign || Math.hypot(you.x, you.z - sign.z) > 150) return;
      metal(0, 0.15, sign.z, sign.w + 2.4, 0.3, 2.6, DCOL[0], 0.6);
      if (!K.hall) for (i = 0; i < sign.bars.length; i++) {      // a hall's engine sets the same words up in letters of its own, on this plinth
        b = sign.bars[i];
        if (b.heart) box(b.x, b.y, sign.z, b.w, sign.s, 1.1, [0.95, 0.16, 0.26], 0.04 + beat * 0.22); else box(b.x, b.y, sign.z, b.w, sign.s, 1.0, [0.8, 0.83, 0.92], 0);
      }
      K.glo(0, 0.6, sign.z + 1.6, sign.w * 0.5, [0.5, 0.7, 1.0], 0.1);
    }
    /* The sky and what is far off: stars and a moon that keep their place as
       you walk, and a ring of towers beyond the last street. None of it is a
       cluster, and none of it is lit like one. */
    function sky(t) {
      var i, a, r, h0, far = Math.max(P.w, P.d) / 2 + 62, x, z;
      for (i = 0; i < 46; i++) {
        a = rnd(i * 1.7) * TAU; r = 120 + rnd(i * 3.3) * 40;
        K.glo(you.x + Math.cos(a) * r, 34 + rnd(i * 5.1) * 90, you.z + Math.sin(a) * r, 0.9 + rnd(i) * 0.9, WHITE, calm ? 0.5 : 0.35 + 0.3 * Math.sin(t * (0.6 + rnd(i * 7)) + i));
      }
      ball(you.x - 70, 78, you.z - 118, 22, 22, 22, [0.72, 0.78, 0.95], 0.45); K.glo(you.x - 70, 78, you.z - 118, 60, [0.6, 0.7, 1.0], 0.22);
      for (i = 0; i < 34; i++) {
        a = i / 34 * TAU; r = far + rnd(i * 2.9) * 26; h0 = 12 + rnd(i * 4.3) * 36; x = Math.cos(a) * r; z = Math.sin(a) * r + 10;
        if (z > P.d / 2 + 20 && Math.abs(x) < 46) continue;      // the square looks out to open sky
        metal(x, h0 / 2, z, 9 + rnd(i) * 7, h0, 9 + rnd(i * 6) * 7, [0.18, 0.24, 0.42], 0.06);
        light(x, h0 * (0.35 + rnd(i * 8) * 0.4), z + (z < 0 ? 5.6 : -5.6), 3 + rnd(i * 9) * 3, 0.5, 0.1, [0.4, 0.55, 0.9], 0.02);
      }
    }
    /* The experts, standing where they stand: turning to you when you come
       near, doing their own move when you have answered them rightly, and
       carrying a light over their heads while they still have a gift to give. */
    function experts(t) {
      folk.forEach(function (f) {
        var d = Math.hypot(f.x - you.x, f.z - you.z), want, u;
        if (d > 110) return;
        want = d < 10 ? Math.atan2(you.x - f.x, you.z - f.z) : f.home;
        f.face += Math.atan2(Math.sin(want - f.face), Math.cos(want - f.face)) * (calm ? 1 : 0.1);
        u = (t - f.cheer) / 1.6; u = u >= 0 && u < 2 ? u % 1 : null;
        K.person(f.x, 0, f.z, f.face, t, { hero: f.ex.hero, pose: 0, step: 0, moving: false, hold: '', emote: u != null ? f.ex.hero : null, eu: u });
        K.shad(f.x, f.z, 0.4, 0.5);
        K.cube(f.x, 2.25 + (calm ? 0 : Math.sin(t * 2 + f.x) * 0.08), f.z, 0.26, 0.26, 0.26, has(f.ex.gift) ? [0.4, 0.8, 1.0] : GOLD, 1, t * 1.5, 0, 1, 2);
        if (!has(f.ex.gift)) K.glo(f.x, 2.25, f.z, 1.2, GOLD, 0.5);
      });
    }
    /* What you have won, worn and carried: each is a thing to look at, and the
       line on the ground is the one that is of use. */
    function prizesDraw(t, dt) {
      var x = you.x, y = you.y, z = you.z, on = you.riding ? me.ride : 0, top = y + K.RIDES[on].sit + 1.5, i, a, L, list, px, pz;
      for (i = bits2.length - 1; i >= 0; i--) {      // paper in the air
        a = (t - bits2[i].at) / 2.4; if (a > 1) { bits2.splice(i, 1); continue; }
        K.glo(bits2[i].x + bits2[i].vx * a * 2.4, Math.max(0.1, bits2[i].y + bits2[i].vy * a * 2.4 - 9 * a * a * 2.4), bits2[i].z + bits2[i].vz * a * 2.4, 0.26, bits2[i].c, (1 - a) * 1.0);
      }
      if (!calm && t - party < 7 && Math.random() < 0.25) confetti(you.x + (Math.random() - 0.5) * 30, 14 + Math.random() * 12, you.z + (Math.random() - 0.5) * 30, 26);
      if (trip || cam.dist <= 1.1) return;
      if (has('crown')) for (i = 0; i < 6; i++) { a = i / 6 * TAU + (calm ? 0 : t * 0.6); box(x + Math.cos(a) * 0.2, top + 0.07, z + Math.sin(a) * 0.2, 0.09, 0.16, 0.09, GOLD, 0.5, a); }
      if (has('shield')) { K.glo(x, y + 0.95, z, 2.6, [0.3, 0.75, 1.0], 0.2); for (i = 0; i < 6; i++) { a = i / 6 * TAU + (calm ? 0 : t * 1.4); K.glo(x + Math.cos(a) * 0.95, y + 0.95 + Math.sin(a * 2 + t) * 0.2, z + Math.sin(a) * 0.95, 0.32, [0.4, 0.85, 1.0], 0.9); } }
      if (has('drone')) { a = calm ? 0.8 : t * 0.9; px = x + Math.cos(a) * 1.15; pz = z + Math.sin(a) * 1.15; box(px, top + 0.75, pz, 0.46, 0.12, 0.46, DARK, 0, a); light(px, top + 0.83, pz, 0.14, 0.04, 0.14, CPUC, 1); for (i = 0; i < 4; i++) K.glo(px + (i % 2 ? 0.3 : -0.3), top + 0.8, pz + (i < 2 ? 0.3 : -0.3), 0.36, CPUC, 0.7); }
      if (has('trail')) steps.forEach(function (o) { a = (t - o.at) / 2.2; K.glo(o.x, 0.25, o.z, 0.9 * (1 - a), DCOL[1], (1 - a) * 0.9); });
      if (has('bug')) {      // it trots after you, a step behind
        pet = pet || { x: x, z: z };
        px = x - Math.sin(you.face) * 1.3 + Math.cos(you.face) * 0.6; pz = z - Math.cos(you.face) * 1.3 - Math.sin(you.face) * 0.6;
        pet.x += (px - pet.x) * Math.min(1, dt * 4); pet.z += (pz - pet.z) * Math.min(1, dt * 4);
        ball(pet.x, 0.26 + (calm ? 0 : Math.abs(Math.sin(t * 9)) * 0.05), pet.z, 0.42, 0.3, 0.52, [0.35, 0.85, 0.4], 0.1);
        for (i = 0; i < 6; i++) box(pet.x + (i % 2 ? 0.24 : -0.24), 0.1, pet.z - 0.18 + Math.floor(i / 2) * 0.18, 0.16, 0.05, 0.04, DARK);
        K.glo(pet.x, 0.4, pet.z + 0.2, 0.4, [1.0, 0.9, 0.4], 0.6);
      }
      if (has('radar') && !chat) { list = needy(data.buildings); if (list.length) { L = lots[list[0].cid]; K.beam(x, 0.12, z, L.x, 0.12, L.dz + 2, BADC, 0.6, 0.16, 0, 1, 1.6, 3, 0); } }
    }
    function world(t, dt) {
      var e = K.eye(), key, on = you.riding ? me.ride : 0, mv, cy2;
      sky(t); ground(t); gate(t); square(t); experts(t);
      for (key in lots) { building(lots[key], t, dt, e); crowd(lots[key], t); if (Math.hypot(lots[key].x - you.x, lots[key].dz - you.z) < 80) meters(lots[key]); }
      traces(t); packets(t, dt); drones(t); rain(t); loadBoard(); ambulance(t, dt);
      if (trip) {      // the flying taxi carries you; nobody is drawn hanging in the air
        box(you.x, you.y + 0.55, you.z, 1.8, 0.6, 4.0, [1.0, 0.82, 0.2], 0.15, you.face); box(you.x, you.y + 1.05, you.z, 1.6, 0.5, 2.1, DARK, 0, you.face);
        K.glo(you.x, you.y - 0.2, you.z, 3.4, [0.4, 0.8, 1.0], 1.2); K.shad(you.x, you.z, 2.2, 0.4 * clamp(1 - you.y / 30, 0, 1));
        return;
      }
      prizesDraw(t, dt);
      if (K.pick.on()) { K.pick.scene(t); return; }      // the line-up, and you are not yet anybody in the street
      if (cam.dist <= 1.1) return;      // scrolled all the way in, you are looking out of its eyes
      mv = you.move && (t - you.move.at) / you.move.dur; if (mv > 1) you.move = mv = null;
      if (on) K.rideDraw(K.stand(you.x, you.y, you.z, you.face), on, t, you.moving);
      K.person(you.x, you.y + K.RIDES[on].sit - (K.RIDES[on].pose === 2 ? 0.18 : 0), you.z, you.face, t, { hero: me.hero, pose: K.RIDES[on].pose, step: you.step, moving: you.moving, run: !!keys.Shift,
        hold: '', ready: false, act: null, emote: mv != null && mv >= 0 ? me.hero : null, eu: mv });
      cy2 = you.y + 0.5; K.glo(you.x, cy2, you.z, 1.6, [0.35, 0.85, 1.0], 0.3); K.shad(you.x, you.z, on ? 0.8 : 0.4, 0.5 * clamp(1 - you.y / 5, 0, 1));
    }

    /* ── what is written over the picture ────────────────────────────── */
    /* Words standing in the world: where the place is on screen, as big as it
       is near, and not at all when a building is in the way. They are gathered
       first and written nearest first, and one that would land on another is
       left out: a street of signs written over each other says nothing. `fit`
       is how wide the thing they are written on is, so they stay on it. */
    var signs = [];
    function board(x, y, z, linesIn, o) {
      var v = K.view(x, y, z), S = K.size(), q, k, w = 0, size, lh, h0, wide;
      o = o || {};
      if (v[2] < 0.8 || v[2] > (o.far || 80)) return;
      q = K.scr(v); k = clamp(S.F / v[2] * (o.scale || 0.34), 0.42, 1.7); size = Math.max(o.min || 0, (o.size || 12) * k);      // `min`: never smaller than can be read
      if (q[0] < -260 || q[0] > S.W + 260 || q[1] < -120 || q[1] > S.H + 120) return;
      g.font = '800 ' + Math.round(size) + 'px ' + K.FONT; if ('letterSpacing' in g) g.letterSpacing = '0.6px';
      linesIn.forEach(function (l) { w = Math.max(w, g.measureText(l[0]).width); });
      if ('letterSpacing' in g) g.letterSpacing = '0px';
      if (o.fit && w > o.fit * S.F / v[2]) { size *= o.fit * S.F / v[2] / w; w = o.fit * S.F / v[2]; }
      size = Math.round(size); if (size < 6) return;
      if (!seen(x, y, z, o.own)) return;
      lh = size * 1.42; h0 = lh * linesIn.length + size * 0.7; wide = w + size * 1.4;
      signs.push({ x: q[0], y: q[1], w: wide, h: h0, size: size, lh: lh, lines: linesIn, o: o, depth: o.must ? 0 : v[2] });
    }
    /* A screen a hall's engine draws is not in this list, so it is held a place in it: what would be written over it
       gives way, as it gave way to the board that stood there. */
    function hold(sc) {
      var lo = [1e9, 1e9], hi = [-1e9, -1e9], i, v, q;
      for (i = 0; i < 4; i++) {
        v = K.view(sc.x + (i & 1 ? 0.5 : -0.5) * sc.w, sc.y + (i & 2 ? 0.5 : -0.5) * sc.h, sc.z);
        if (v[2] < 0.8) return;
        q = K.scr(v); lo = [Math.min(lo[0], q[0]), Math.min(lo[1], q[1])]; hi = [Math.max(hi[0], q[0]), Math.max(hi[1], q[1])];
      }
      signs.push({ x: (lo[0] + hi[0]) / 2, y: (lo[1] + hi[1]) / 2, w: hi[0] - lo[0], h: hi[1] - lo[1], lines: [], o: { hold: true }, depth: 0 });
    }
    function written() {
      var put = [], i, j, r, o, x0, y0, hit;
      signs.sort(function (a, b) { return a.depth - b.depth; });
      for (i = 0; i < signs.length; i++) {
        r = signs[i]; o = r.o; x0 = r.x - r.w / 2; y0 = r.y - r.h / 2;
        if (o.hold) { put.push([x0, y0, r.w, r.h]); continue; }
        for (hit = false, j = 0; j < put.length && !hit; j++) hit = x0 < put[j][0] + put[j][2] && x0 + r.w > put[j][0] && y0 < put[j][1] + put[j][3] && y0 + r.h > put[j][1];
        if (hit || (!o.must && y0 < 66)) continue;      // nor one that would slide under the display at the top
        put.push([x0 - 4, y0 - 3, r.w + 8, r.h + 6]);
        if (o.solid) { g.globalAlpha = 1; g.fillStyle = 'rgba(5,7,11,.95)'; g.fillRect(x0, y0, r.w, r.h); g.fillStyle = o.accent || '#fff'; g.fillRect(x0, y0 + r.h - 3, r.w, 3); }      // over lit windows, glass cannot be read
        else if (o.plate !== false) K.plate(x0, y0, r.w, r.h, o.accent || null, 0.9);
        g.globalAlpha = 1;
        for (j = 0; j < r.lines.length; j++) K.ink(r.lines[j][0], r.x, y0 + r.size * 0.35 + r.lh * (j + 0.5), j ? Math.round(r.size * 0.82) : r.size, r.lines[j][1] || K.HUDC.ink, 'center', j ? 700 : 900, 0.6);
      }
      signs.length = 0; g.globalAlpha = 1;
    }
    function names(t) {
      var S = K.size(), key, L, b, c, lines, i, m, d, bestD = 5.5, who = null, z = P.gate.z, list, hl;
      // Every building carries its name over its helm, where nothing stands in
      // front of it, on a board that is never too small to read; and under the
      // name, only what is wrong. Its figures are on the card you get at its
      // door (hud), not hung over the pods who are speaking there.
      var close = [], cards = [];
      for (key in lots) {
        L = lots[key]; d = Math.hypot(L.x - you.x, L.dz - you.z); if (d >= ROOFS_FAR || L.top == null) continue;
        i = K.view(L.x, L.top + 2.4, L.bz); if (i[2] < 0.8) continue;
        i = K.scr(i); if (i[0] > 0 && i[0] < S.W && i[1] > -20 && i[1] < S.H) close.push([d, L]);
      }
      close.sort(function (a, b2) { return a[0] - b2[0]; });
      close.slice(0, ROOFS).forEach(function (o) {
        L = o[1]; b = L.b;
        c = b.state === 'bad' ? K.HUDC.red : b.state === 'ok' ? K.HUDC.ok : b.state === 'down' ? '#8a93a8' : '#8ab4ff';
        lines = [[(b.prod ? '★ ' : '') + b.name.toUpperCase(), K.HUDC.ink]];
        if (b.state === 'bad') lines.push([(b.pods.bad ? b.pods.bad + ' FAILING' : '') + (b.pods.bad && unready(b) ? ' · ' : '') + (unready(b) ? plural(unready(b), 'MACHINE') + ' DOWN' : ''), K.HUDC.red]);
        else if (b.state !== 'ok') lines.push([b.state === 'down' ? 'NO SIGNAL' : 'NOT READ YET', c]);
        board(L.x, L.top + 2.4, L.bz, lines, { own: L, accent: c, far: ROOFS_FAR, size: 13, scale: 0.5, min: 12, solid: true });
      });
      for (key in lots) {
        L = lots[key]; d = Math.hypot(L.x - you.x, L.dz - you.z);
        if (!L.crowd || d > 26) continue;
        for (i = 0; i < L.crowd.length; i++) {
          m = L.crowd[i]; if (m.x == null) continue;
          d = Math.hypot(m.x - you.x, m.z - you.z);
          if (!m.well && d < 11) cards.push([m, L]);
          if (d < bestD) { bestD = d; who = { m: m, L: L }; }
        }
      }
      // the placards are read from a few steps off; once one of the crowd is speaking to you, its words are enough
      if (!who) cards.forEach(function (o) { board(o[0].x + 0.5, o[0].y + 1.7, o[0].z, [[placard(o[0].p), '#1a1a22']], { own: o[1], plate: false, far: 14, size: 9, scale: 0.3, fit: 1.4 }); });
      // the crier calls out the headline of the moment to whoever stands by it
      if (crier && !who && !trip && !going && Math.hypot(crier.x - you.x, crier.z - you.z) < 7 && news.length) {
        i = K.view(crier.x, crier.y + 0.8, crier.z);
        if (i[2] > 0.8) { d = K.scr(i); K.bubble(d[0], d[1] - 8, 'Extra, extra! ' + news[Math.floor(t / 5) % news.length], 'the crier', { tone: data.totals.bad ? 'bad' : 'ok' }); }
      }
      // whoever of the crowd you are standing by says its piece
      if (who && !trip && !going) {
        if (!crowdSay || crowdSay.m !== who.m) crowdSay = { m: who.m, at: t };
        m = who.m; b = who.L.b; i = K.view(m.x, m.y + 0.8, m.z);
        if (i[2] > 0.8) { d = K.scr(i); K.bubble(d[0], d[1] - 8, m.well ? 'All ' + b.pods.total + ' of us are well in ' + b.name + '. The door is open: go on in.' : plea(m.p), m.well ? 'a pod of ' + b.name : m.p.name, { at: crowdSay.at, tone: m.well ? 'ok' : 'bad' }); }
      } else crowdSay = null;
      // the gate, and its two boards: the headlines, and who needs help
      // In a hall the three are screens the engine sets up with these same words (`screens`); anywhere else they are
      // written over the picture, as they were. `more` is what only a screen has: where it stands when that differs
      // (the two boards stand higher, on feet of their own, so the sign's letters do not hide them from the square),
      // and for the news the story itself, every headline for its foot, which one it is and how far to the next.
      var lit = K.hall ? [] : null, tt = data.totals, nk = Math.floor(t / 5);
      function post(kind, x, y, zz, w, h, lines, o, more) {
        if (!lit) return board(x, y, zz, lines, o);
        var sc = { kind: kind, x: x, y: y, z: zz, w: w, h: h, lines: lines }, key;
        for (key in more || {}) sc[key] = more[key];
        lit.push(sc); hold(sc);
      }
      post('gate', 0, 7.6, z + 0.5, 14.4, 1.6, [[stage.getAttribute('data-name').toUpperCase(), K.HUDC.amber], [plural(data.totals.clusters, 'CLUSTER') + ' · ' + plural(data.totals.pods, 'POD') + (data.totals.bad ? ' · ' + data.totals.bad + ' NEED' + (data.totals.bad === 1 ? 'S' : '') + ' HELP' : ''), K.HUDC.ink]], { far: 140, plate: false, size: 15, scale: 0.42, fit: 12.5, must: true, own: GATE });
      hl = news.length ? news[nk % news.length] : '';
      post('news', -15, 5.4, z + 0.3, 10, 4.6, [['THE CITY NEWS', K.HUDC.amber]].concat(wrap(hl, 30).map(function (l) { return [l, K.HUDC.ink]; })), { far: 120, plate: false, size: 12, scale: 0.4, fit: 9, must: true, own: GATE },
        { y: 9.3, w: 12, h: 6, feet: 0, story: hl, ticker: news, at: news.length ? nk % news.length : 0, of: news.length, beat: (t / 5) % 1, tone: tt.bad ? K.HUDC.red : tt.reading || tt.down ? '#8ab4ff' : K.HUDC.ok });
      list = needy(data.buildings).slice(0, 4);
      post('help', 15, 5.4, z + 0.3, 10, 4.6, [[list.length ? 'WHO NEEDS HELP' : data.totals.reading || data.totals.down ? 'NOT ALL KNOWN YET' : 'ALL IS WELL', list.length ? K.HUDC.red : data.totals.reading || data.totals.down ? '#8ab4ff' : K.HUDC.ok]]
        .concat(list.length ? list.map(function (b) { return [b.name + ' · ' + b.pods.bad + ' failing' + (unready(b) ? ', ' + plural(unready(b), 'machine') + ' down' : ''), K.HUDC.ink]; })
          : [[data.totals.reading ? plural(data.totals.reading, 'building') + ' being read' : data.totals.down ? plural(data.totals.down, 'cluster') + ' did not answer' : 'every pod in every cluster', K.HUDC.dim]]), { far: 120, plate: false, size: 12, scale: 0.4, fit: 9, must: true, own: GATE },
        { y: 9.3, w: 12, h: 6, feet: 0 });
      screens = lit;
      board(board0.x, 5.6, board0.z, [['CITY LOAD', K.HUDC.amber], ['CPU AND MEMORY IN USE', K.HUDC.dim]], { far: 46, size: 10, scale: 0.36 });
      if (Math.hypot(board0.x - you.x, board0.z - you.z) < 22) board0.cols.forEach(function (o) {
        if (Math.abs(o.x - you.x) > 2.2) return;
        board(o.x, 0.9, board0.z + 2.6, [[o.b.name.toUpperCase(), K.HUDC.ink], [o.b.cpu == null ? (o.b.state === 'down' ? 'NO SIGNAL' : 'NOT READ YET') : 'CPU ' + Math.round(o.b.cpu) + '% · RAM ' + Math.round(o.b.mem == null ? 0 : o.b.mem) + '%', o.b.cpu == null ? K.HUDC.dim : '#7fdcff']], { far: 30, size: 10, scale: 0.34, must: true });
      });
      droneAt.forEach(function (o) { board(o.x, o.y - 1.35, o.z, [[o.name, K.HUDC.ink]], { far: 26, plate: false, size: 10, scale: 0.34, fit: 1.7 }); });
      // the districts, named at the corner where each begins
      P.heads.forEach(function (hd) { board(hd.x + 0.6, 6.0, hd.z + 0.6, [[hd.name.toUpperCase(), K.HUDC.amber]], { far: 40, size: 10, scale: 0.34 }); });
    }
    function wrap(text, n) {
      var out = [], cur = '';
      String(text).split(' ').forEach(function (w) { if ((cur + ' ' + w).trim().length > n) { out.push(cur); cur = w; } else cur = (cur + ' ' + w).trim(); });
      if (cur) out.push(cur);
      return out.slice(0, 4);
    }
    /* The edges of the picture fall away to dark, the way a lens does it, so
       the eye stays on the street. Under the display, never over it. */
    var vig = null;
    function shade(S) {
      if (!vig || vig.w !== S.W || vig.h !== S.H) {
        vig = { w: S.W, h: S.H, g: g.createRadialGradient(S.W / 2, S.H * 0.52, S.H * 0.42, S.W / 2, S.H * 0.52, Math.max(S.W, S.H) * 0.78) };
        vig.g.addColorStop(0, 'rgba(0,0,0,0)'); vig.g.addColorStop(1, 'rgba(2,3,10,.62)');
      }
      g.globalAlpha = 1; g.fillStyle = vig.g; g.fillRect(0, 0, S.W, S.H);
    }
    function card(b, reach, W, H) {
      var u = unready(b), rows = b.state === 'bad' ? 3 : 2, has = b.cpu != null, bw = Math.min(430, W - 40), bh = 58 + rows * 17 + (has ? 26 : 0), x = W / 2 - bw / 2, y = H - bh - 96, yy, i, v, bx;
      var c = b.state === 'bad' ? K.HUDC.red : b.state === 'ok' ? K.HUDC.ok : b.state === 'down' ? '#8a93a8' : '#8ab4ff';
      g.globalAlpha = 1; g.fillStyle = 'rgba(5,7,11,.93)'; g.fillRect(x, y, bw, bh); g.fillStyle = c; g.fillRect(x, y, 4, bh);
      K.ink('KUBERNETES CLUSTER', x + 18, y + 15, 9, K.HUDC.dim, 'left', 800, 1.6);
      K.ink(b.state === 'bad' ? 'NEEDS HELP' : b.state === 'ok' ? 'ALL WELL' : b.state === 'down' ? 'NO SIGNAL' : 'NOT READ YET', x + bw - 16, y + 15, 10, c, 'right', 800, 1.2);
      K.ink((b.prod ? '\u2605 ' : '') + b.name.toUpperCase(), x + 18, y + 37, 19, K.HUDC.ink, 'left', 900, 0.6);
      yy = y + 59;
      K.ink(b.state === 'down' ? String(b.why).slice(0, 62) : b.state === 'reading' ? 'EnvMap has not read this cluster yet' : plural(b.pods.total, 'pod') + '  ·  ' + b.nodes.ready + ' of ' + plural(b.nodes.total, 'machine') + ' ready', x + 18, yy, 12, K.HUDC.ink, 'left', 600, 0.2);
      if (b.state === 'bad') { yy += 17; K.ink((b.pods.bad ? plural(b.pods.bad, 'pod') + ' failing' : '') + (b.pods.bad && u ? '  ·  ' : '') + (u ? plural(u, 'machine') + ' not ready' : ''), x + 18, yy, 12, K.HUDC.red, 'left', 800, 0.2); }
      if (has) for (yy += 22, i = 0; i < 2; i++) {      // CPU and memory in use, as the hub counts them
        v = i ? b.mem : b.cpu; if (v == null) continue; bx = x + 18 + i * (bw / 2 - 8);
        K.ink((i ? 'RAM' : 'CPU') + (b.cpu_src === 'live' ? '' : ' ASKED'), bx, yy, 9, K.HUDC.dim, 'left', 800, 1.2);
        g.fillStyle = 'rgba(255,255,255,.12)'; g.fillRect(bx + 74, yy - 3, bw / 2 - 150, 6);
        g.fillStyle = v >= 90 ? K.HUDC.red : v >= 70 ? K.HUDC.amber : K.HUDC.ok; g.fillRect(bx + 74, yy - 3, (bw / 2 - 150) * clamp(v, 0, 100) / 100, 6);
        K.ink(Math.round(v) + '%', bx + bw / 2 - 68, yy, 11, K.HUDC.ink, 'left', 800, 0.4);
      }
      K.ink(reach ? 'E   ENTER' : 'WALK UP TO THE DOOR', x + bw / 2, y + bh - 13, 10, reach ? K.HUDC.amber : K.HUDC.dim, 'center', 800, 1.6);
    }
    function hud(t) {
      var S = K.size(), W = S.W, H = S.H, list = needy(data.buildings), now = performance.now() / 1000, i, L, b, d, a, x, y, bw, s, key, cx, cy, n, text, wide, c;
      // In a narrow window the panel at the top left reaches under these: they step down past it.
      var top = W < 1040 ? Math.round($('c3dTotals').parentNode.getBoundingClientRect().bottom - stage.getBoundingClientRect().top) + 8 : 0;
      g.save(); g.translate(0, top);
      // the compass, with every building that needs somebody marked on it
      bw = Math.min(360, W - 40); x = W / 2 - bw / 2; K.plate(x, 10, bw, 22, null, 0.9); g.globalAlpha = 1;
      ['N', 'E', 'S', 'W'].forEach(function (nm, j) {
        a = Math.atan2(Math.sin(-goal.yaw - j * PI / 2), Math.cos(-goal.yaw - j * PI / 2));
        if (Math.abs(a) < 1.25) K.ink(nm, W / 2 - a / 1.25 * bw / 2, 21, 10, K.HUDC.dim, 'center', 800, 1);
      });
      list.forEach(function (bb) {
        L = lots[bb.cid]; a = Math.atan2(L.x - you.x, L.dz - you.z) - (goal.yaw + PI); a = Math.atan2(Math.sin(a), Math.cos(a));
        g.fillStyle = K.HUDC.red; cx = W / 2 - clamp(a, -1.25, 1.25) / 1.25 * (bw / 2 - 6); g.beginPath(); g.moveTo(cx, 27); g.lineTo(cx - 4, 33); g.lineTo(cx + 4, 33); g.closePath(); g.fill();
      });
      // what the city asks of you
      text = list.length ? plural(list.length, 'BUILDING') + (list.length === 1 ? ' NEEDS' : ' NEED') + ' HELP · G TAKES YOU THERE' : data.totals.reading ? 'THE CITY IS STILL BEING READ' : data.totals.down ? 'NO BUILDING IS FAILING · ' + data.totals.down + ' DID NOT ANSWER' : 'EVERY BUILDING IS WELL';
      g.font = '800 10px ' + K.FONT; wide = g.measureText('CITY WATCH   ' + text).width + 70; K.plate(W / 2 - wide / 2, 38, wide, 20, list.length ? K.HUDC.red : K.HUDC.amber, 0.9); g.globalAlpha = 1;
      s = K.ink('CITY WATCH', W / 2 - wide / 2 + 12, 48, 9, K.HUDC.amber, 'left', 800, 1.6); K.ink(text, W / 2 - wide / 2 + 24 + s, 48, 10, K.HUDC.ink, 'left', 800, 1);
      // what just happened
      n = notes[notes.length - 1]; a = n ? now - n.at : 1e9;      // the last thing that happened, and only that
      if (n && a < n.keep) { g.globalAlpha = Math.min(1, (n.keep - a) * 2); K.ink(n.text, W / 2, 74, 11.5, n.kind === 'kill' ? K.HUDC.red : K.HUDC.ink, 'center', 700, 0.4); }
      g.globalAlpha = 1; g.restore();
      // The building you are standing at, on a card of its own: its name, how it
      // is, and its figures. Here, and not hung over its door, so that it is
      // never behind what the pods outside are saying.
      if (who && !chat && !trip && !going) {      // somebody to talk to, nearer than any door
        text = 'E   TALK TO THE ' + who.ex.role.toUpperCase(); g.font = '800 11px ' + K.FONT; wide = g.measureText(text).width + 70;
        K.plate(W / 2 - wide / 2, H - 150, wide, 40, has(who.ex.gift) ? K.HUDC.ok : K.HUDC.amber, 0.94); g.globalAlpha = 1;
        K.ink(text, W / 2, H - 138, 11, K.HUDC.ink, 'center', 800, 1);
        K.ink(has(who.ex.gift) ? 'MORE QUESTIONS · MORE STARS' : 'ANSWER ONE RIGHT AND IT HAS SOMETHING FOR YOU', W / 2, H - 122, 9, K.HUDC.dim, 'center', 700, 1.2);
      } else if (chat) { /* the conversation has the foot of the screen */ }
      else if (beside && !trip && !going) card(beside.b, near === beside, W, H);
      else if (!K.locked() && !trip && !going) { g.textAlign = 'center'; K.tag(W / 2, H - 132, 'Click the street to look around with the mouse', false, 0.9, true); }
      // what you have won
      if (bag.stars) {
        n = QZ.EXPERTS.filter(function (ex) { return has(ex.gift); }).length; bw = 250; x = W - bw - 16; y = H - 96;
        K.plate(x, y, bw, 28, K.HUDC.amber, 0.9); g.globalAlpha = 1;
        K.ink('\u2605 ' + bag.stars, x + 16, y + 14, 12, K.HUDC.amber, 'left', 900, 0.6); K.ink(n + ' OF ' + QZ.EXPERTS.length + ' GIFTS', x + bw - 12, y + 14, 9, K.HUDC.dim, 'right', 700, 1.2);
      }
      // how you travel
      bw = 250; x = W - bw - 16; y = H - 62; K.plate(x, y, bw, 28, null, 0.9); g.globalAlpha = 1;
      s = x + 14 + K.ink(trip ? 'TAXI' : you.riding ? K.RIDES[me.ride].name.toUpperCase() : 'ON FOOT', x + 14, y + 14, 10, K.HUDC.ink, 'left', 800, 1) + 12;
      g.fillStyle = 'rgba(255,255,255,.14)'; g.fillRect(s, y + 11, 64, 6); g.fillStyle = K.HUDC.amber; g.fillRect(s, y + 11, 64 * clamp((you.v || 0) / 24.9, 0, 1), 6);
      K.ink(Math.round(you.v || 0) + ' M/S', s + 72, y + 14, 9.5, K.HUDC.dim, 'left', 700, 1); K.ink(me.ride ? (you.riding ? 'V OFF' : 'V RIDE') : 'G TAXI', x + bw - 12, y + 14, 9, K.HUDC.dim, 'right', 700, 1.2);
      // the map: every lot in the colour of its state, and you
      n = 158; x = 16; y = H - n - 26; s = (n - 18) / Math.max(P.w, P.d + 60); cx = x + n / 2; cy = y + n / 2 - 6;
      K.plate(x, y, n, n, null, 0.9); g.globalAlpha = 1; K.ink('CITY MAP', x + 10, y + 11, 8.5, K.HUDC.dim, 'left', 800, 1.6);
      for (key in lots) {
        L = lots[key]; b = L.b; g.fillStyle = b.state === 'bad' ? '#ff4d5e' : b.state === 'ok' ? '#39d98a' : b.state === 'down' ? '#5d667c' : '#6aa0ff';
        d = b.state === 'bad' && !calm ? 1 + 0.25 * Math.sin(t * 5) : 1; a = Math.max(3, L.w * s * d);
        g.fillRect(cx + L.x * s - a / 2, cy + L.bz * s - a / 2, a, a);
      }
      g.fillStyle = '#ffffff'; g.fillRect(cx + amb.x * s - 1.5, cy + amb.z * s - 1.5, 3, 3);
      g.save(); g.translate(clamp(cx + you.x * s, x + 6, x + n - 6), clamp(cy + you.z * s, y + 6, y + n - 6)); g.rotate(Math.atan2(-Math.cos(goal.yaw), -Math.sin(goal.yaw)));
      g.fillStyle = '#ffc857'; g.beginPath(); g.moveTo(7, 0); g.lineTo(-5, 4.5); g.lineTo(-5, -4.5); g.closePath(); g.fill(); g.restore();
    }

    function frame(ms) {
      requestAnimationFrame(frame);
      var t = ms / 1000, dt = Math.min(0.05, t - last || 0.016), list, moodWant = 0, key, L, d; last = t;
      if (!data) { K.begin(dt); return; }
      step(t, dt);
      if (K.pick.on()) K.pick.aim(dt);
      else { goal.tx = you.x; goal.ty = you.y + 1.2; goal.tz = you.z; goal.dist = clip(trip ? 18 : you.zoom); if (cam.dist > goal.dist) cam.dist = goal.dist; }
      K.begin(dt);
      // the sky darkens as you come near a building in trouble
      for (key in lots) { L = lots[key]; if (L.b.state === 'bad') { d = Math.hypot(L.x - you.x, L.bz - you.z); moodWant = Math.max(moodWant, clamp(1 - d / 60, 0, 1) * 0.5); } }
      frame.mood = (frame.mood || 0) + (moodWant - (frame.mood || 0)) * (calm ? 1 : Math.min(1, dt * 1.5));
      world(t, dt);
      // An engine that draws the city as a hall is told where the streets and the empty lots are, so it can lay the
      // bus down the one and stand racks on the other. It is the plan itself, made once for each plan.
      if (K.hall && (!P.town || (sign && !P.town.love))) P.town = { xs: P.xs, zs: P.zs, parks: P.parks, w: P.w, d: P.d, road: ROAD, lot: LOT, gate: P.gate.z,
        love: sign ? { name: sign.name, w: sign.w, z: sign.z, tall: sign.s * 7 } : null };      // and the words of the sign in the square, and how much room they have
      K.paint(t, { span: Math.max(120, P.w, P.d), mood: frame.mood, pulse: 99, gridY: -0.62, bloom: 0.44, town: P.town || null, screens: screens });
      shade(K.size());
      if (!K.pick.on()) { names(t); written(); hud(t); }      // the chooser has the screen to itself
      if (!lost) { d = Math.round((Date.now() - lastOk) / 1000); live('live · read ' + (d < 2 ? 'just now' : d + 's ago') + (data.stale ? ' · the clusters are being read again' : ''), false); }
      g.globalAlpha = 1;
    }

    /* ── hands ───────────────────────────────────────────────────────── */
    window.addEventListener('keydown', function (e) {
      if (e.metaKey || e.ctrlKey || e.altKey || !data) return;
      var at = e.target, typing = at && (at.tagName === 'INPUT' || at.tagName === 'TEXTAREA' || at.isContentEditable), k;
      if (typing || document.querySelector('dialog[open]')) { keys = {}; return; }
      k = e.key.length === 1 ? e.key.toLowerCase() : e.key; keys[k] = 1; $('c3dHint').className = 'c3d-hint gone';
      if (going) { e.preventDefault(); return; }
      if (K.pick.on()) { K.pick.key(k); e.preventDefault(); return; }
      if (chat) {      // a conversation takes the numbers, and Esc ends it; your feet are still yours
        if (k >= '1' && k <= '9' && !e.repeat) { if (chat.opts[+k - 1]) chat.opts[+k - 1][1](); e.preventDefault(); return; }
        if (k === 'Escape') { chatClose(); e.preventDefault(); return; }
      }
      if ((k === 'e' || k === 'f' || k === 'Enter') && !e.repeat && who && !chat) chatOpen(who);
      else if ((k === 'e' || k === 'f' || k === 'Enter') && !e.repeat && near && !chat) enter(near);
      else if (k === 'g' && !e.repeat) taxi();
      else if (k === 'p' && !e.repeat) choose(false);
      else if (k === 'v' && !e.repeat) { if (!me.ride) toast('You have nothing to ride: P chooses one'); else if (!trip) { you.riding = !you.riding; K.sfx('tick'); } }
      else if (k === 'b' && !e.repeat) { if (has('confetti')) confetti(you.x, you.y + 2.2, you.z, 40); if (!you.riding && !you.moving) you.move = { at: performance.now() / 1000, dur: 1.6 }; }
      else if (k === 'm' && !e.repeat) { me.mute = !me.mute; K.keep(); toast('Sound ' + (me.mute ? 'off' : 'on')); K.sfx('tick'); }
      if (' wasdefgvbmp'.indexOf(k) >= 0 || !k.indexOf('Arrow')) e.preventDefault();
    });
    window.addEventListener('keyup', function (e) { delete keys[e.key.length === 1 ? e.key.toLowerCase() : e.key]; });
    window.addEventListener('blur', function () { keys = {}; });
    hook.click = function () { if (K.pick.on() || chat) return; if (who && K.locked()) chatOpen(who); else if (near && K.locked()) enter(near); else if (!K.locked()) K.grab(); };
    hook.wheel = function (e) { you.zoom = clamp(you.zoom * Math.exp(e.deltaY * (e.deltaMode ? 0.05 : 0.0016)), 0.02, 60); };
    document.addEventListener('visibilitychange', function () { if (!document.hidden) poll(); });

    $('c3dHint').textContent = 'W A S D walk · Shift run · Space jump · V ride · E enters a building · G taxi · P character · B your move · M sound';
    $('c3dHint').className = 'c3d-hint';
    K.atlas();
    poll(); requestAnimationFrame(frame);
    // for the test that drives the page, and for nobody else
    window.__c3d = { state: function () {
      return { city: true, lots: P ? P.lots.length : -1, parks: P ? P.parks.length : -1, you: { x: you.x, y: you.y, z: you.z }, near: near && near.cid, who: who && who.ex.key, chat: chat && { say: $('c3dTalkSay').textContent, opts: chat.opts.map(function (o) { return o[0]; }), right: chat.q && chat.q.right }, stars: bag.stars, gifts: Object.keys(bag.gifts), folk: folk.map(function (f) { return { key: f.ex.key, x: f.x, z: f.z }; }), sign: sign && sign.bars.length, picking: K.pick.on(), hero: me.hero, ride: me.ride, riding: you.riding, going: going && going.L.cid, trip: trip && trip.name,
        amb: amb && { x: amb.x, z: amb.z, to: amb.to, lit: amb.lit }, news: news, notes: notes.map(function (n) { return n.text; }), bits: bits.length, busy: busy0, drones: droneAt.length,
        buildings: P ? P.lots.map(function (L) { return { cid: L.cid, state: L.b.state, x: L.x, dz: L.dz, h: L.hh, crowd: L.crowd ? L.crowd.length : -1 }; }) : [] };
    }, put: function (x, z) { you.x = x; you.z = z; }, look: function (yaw, pitch, zoom) { goal.yaw = yaw; goal.pitch = pitch; you.zoom = zoom; } };
  };
})();
