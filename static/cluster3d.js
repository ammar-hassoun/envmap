/* The cluster in three dimensions (templates/cluster_3d.html, app/scene.py).

   TWO FILES. This one decides what is where: the layout, the camera, what
   each pod is doing this frame, the panels and the pointer. cluster3d-gl.js
   draws it on the GPU, from flat arrays this file fills once a frame. Neither
   uses a library: the scene is six shapes repeated, which is a few hundred
   lines of shader, against half a megabyte of somebody else's renderer shipped
   into every install for the sake of one page. The names are the one thing
   still drawn in 2D, on a clear canvas over the picture.

   WHAT IS A FACT AND WHAT IS A GUESS, ON SCREEN
   Three kinds of line are stated by the cluster (a Service to the pods it
   selects, a route to its Service, a pod to the volume it mounts). The fourth
   is inferred by app/scene.py from a workload's configuration naming a
   Service. The card says "names", never "calls": nothing here measured
   traffic.

   NOTHING THE CLUSTER NAMES BECOMES MARKUP. A pod is called whatever somebody
   typed, so every panel is built from elements and text nodes, and a canvas
   only ever fillText()s. There is no innerHTML in this file. */
(function () {
  'use strict';

  var PI = Math.PI, TAU = PI * 2;
  var S = 2.3;            // a pod's place on the floor, in world units: wide enough to walk between two
  var R = 0.5;            // a pod's radius
  var TH = 0.45;          // how thick a platform is
  var SKY = 3.4;          // where Services float
  var GATE = 6.6;         // where routes float, above the Services they feed
  var CELLAR = -2.6;      // where volumes hang, under the pods that mount them

  function clamp(v, a, b) { return v < a ? a : v > b ? b : v; }
  function hash(s) {
    var h = 2166136261;
    for (var i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
    return h >>> 0;
  }
  function fmtCpu(m) {
    if (m == null) return '';
    return m < 1000 ? Math.round(m) + 'm' : (m / 1000).toFixed(m % 1000 ? 1 : 0) + ' cores';
  }
  function fmtMem(mib) {
    if (mib == null) return '';
    return mib < 1024 ? Math.round(mib) + ' MiB' : (mib / 1024).toFixed(1) + ' GiB';
  }

  /* ── layout: where everything stands ─────────────────────────────────
     Pure, so it can be run under node against a fixture. Pods stand on a
     platform (their machine, or their namespace), in a block per namespace
     (or machine), and blocks and platforms are packed in rows. Names are the
     sort keys throughout: a pod restarting must not reshuffle the city. */
  function shelf(boxes, gap, wide) {
    var x = 0, z = 0, rowD = 0, W = 0;
    boxes.forEach(function (b) {
      if (x > 0 && x + b.w > wide) { x = 0; z += rowD + gap; rowD = 0; }
      b.x = x; b.z = z; x += b.w + gap;
      rowD = Math.max(rowD, b.d); W = Math.max(W, b.x + b.w);
    });
    return { w: W, d: z + rowD };
  }
  /* The other way to stand the platforms: either side of one aisle, each with
     its back to a wall, the way racks stand in a hall. The same boxes in the
     same order, so the first is nearest the way in, and each goes to whichever
     side is shorter. `half` is half the aisle's width. */
  var AISLE = 3.6;
  function aisle(boxes, gap, half) {
    var run = [0, 0], deep = 0;
    boxes.forEach(function (b) {
      var s = run[0] <= run[1] ? 0 : 1;
      b.x = run[s]; b.z = s ? half : -half - b.d; b.side = s ? 1 : -1; run[s] += b.w + gap; deep = Math.max(deep, b.d);
    });
    return { w: Math.max(run[0], run[1]) - gap, d: (half + deep) * 2, flat: true };
  }
  function by(key) {
    return function (a, b) { var x = key(a), y = key(b); return x < y ? -1 : x > y ? 1 : 0; };
  }
  function centre(pts) {
    var x = 0, z = 0;
    pts.forEach(function (p) { x += p.x; z += p.z; });
    return { x: x / pts.length, z: z / pts.length };
  }

  function layout(data, groupBy, hall) {
    var byNs = groupBy === 'ns';
    var sys = {};
    (data.namespaces || []).forEach(function (n) { sys[n.name] = n.system; });
    var groups = {};
    if (!byNs) (data.nodes || []).forEach(function (n) { groups[n.name] = { key: n.name, node: n, pods: [] }; });
    (data.pods || []).forEach(function (p) {
      var k = byNs ? p.ns : (p.node || '');
      (groups[k] || (groups[k] = { key: k, pods: [] })).pods.push(p);
    });
    var plats = Object.keys(groups).map(function (k) { return groups[k]; });
    plats.forEach(function (pl) {
      pl.limbo = !byNs && !pl.node;
      // the machines that run the cluster first, the waiting room last
      pl.rank = byNs ? (sys[pl.key] ? 1 : 0)
        : pl.limbo ? 9 : (pl.node.roles || []).some(function (r) {
          return r === 'control-plane' || r === 'master'; }) ? 0 : 1;
    });
    plats.sort(function (a, b) { return a.rank - b.rank || by(function (p) { return p.key; })(a, b); });

    var PAD = 0.3, M = 0.9, pos = {};
    plats.forEach(function (pl) {
      var blocks = {};
      pl.pods.forEach(function (p) {
        var k = byNs ? (p.node || '') : p.ns;
        (blocks[k] || (blocks[k] = { key: k, pods: [] })).pods.push(p);
      });
      pl.blocks = Object.keys(blocks).map(function (k) { return blocks[k]; });
      var area = 0, widest = 0;
      pl.blocks.forEach(function (b) {
        b.pods.sort(by(function (p) { return p.wl + '\u0000' + p.name; }));
        b.cols = Math.max(1, Math.ceil(Math.sqrt(b.pods.length)));
        b.rows = Math.max(1, Math.ceil(b.pods.length / b.cols));
        b.w = b.cols * S + PAD * 2; b.d = b.rows * S + PAD * 2;
        area += (b.w + 0.5) * (b.d + 0.5); widest = Math.max(widest, b.w);
      });
      pl.blocks.sort(function (a, b) { return b.d - a.d || by(function (x) { return x.key; })(a, b); });
      var inner = shelf(pl.blocks, 0.5, Math.max(widest, Math.sqrt(area) * 1.3));
      pl.w = Math.max(4, inner.w + M * 2); pl.d = Math.max(4, inner.d + M * 2);
      pl.count = pl.pods.length;
      pl.bad = pl.pods.filter(function (p) { return p.tone === 'bad'; }).length;
    });
    var G = 3.2, area = 0, widest = 0;
    plats.forEach(function (pl) { area += (pl.w + G) * (pl.d + G); widest = Math.max(widest, pl.w); });
    // packed in rows, or in a hall stood along an aisle that runs through the middle (so nothing is moved across it)
    var all = hall ? aisle(plats, G, AISLE) : shelf(plats, G, Math.max(widest, Math.sqrt(area) * 1.25));
    var ox = all.w / 2, oz = all.flat ? 0 : all.d / 2;
    plats.forEach(function (pl) {
      pl.x -= ox; pl.z -= oz;
      pl.blocks.forEach(function (b) {
        b.x += pl.x + M; b.z += pl.z + M;
        b.pods.forEach(function (p, i) {
          pos['pod:' + p.id] = {
            x: b.x + PAD + (i % b.cols + 0.5) * S, y: R + 0.06,
            z: b.z + PAD + (Math.floor(i / b.cols) + 0.5) * S };
        });
      });
    });

    var edges = [], members = {};
    function jit(id, n, step) { return ((hash(id) >> 3) % n - (n - 1) / 2) * step; }
    var dockS = [], dockR = [], dockC = [];
    var named = {};
    (data.links || []).forEach(function (l) { named[l.to] = 1; });
    (data.routes || []).forEach(function (r) { (r.services || []).forEach(function (s) { named[s] = 1; }); });
    (data.services || []).forEach(function (s) {
      var pts = (s.pods || []).map(function (id) { return pos['pod:' + id]; }).filter(Boolean);
      if (pts.length) {
        var c = centre(pts);
        pos['svc:' + s.id] = { x: c.x + jit(s.id, 7, 0.14), y: SKY + (hash(s.id) % 5) * 0.32, z: c.z + jit('z' + s.id, 7, 0.14) };
        s.pods.forEach(function (id) { if (pos['pod:' + id]) edges.push({ kind: 'svc', a: 'svc:' + s.id, b: 'pod:' + id }); });
      } else if (named[s.id] || s.selects) dockS.push(s);
      // a Service that selects nothing and that nothing names is not drawn
    });
    dockS.sort(by(function (s) { return s.id; })).forEach(function (s, i) {
      pos['svc:' + s.id] = hall ? { x: ox + 3 + i * 1.9, y: SKY, z: -1.4 } : { x: -ox + 1 + i * 1.9, y: SKY, z: -oz - 3.4 };
    });
    (data.routes || []).forEach(function (r) {
      var pts = (r.services || []).map(function (id) { return pos['svc:' + id]; }).filter(Boolean);
      if (!pts.length) { dockR.push(r); return; }
      var c = centre(pts);
      pos['route:' + r.id] = { x: c.x + jit(r.id, 5, 0.3), y: GATE + (hash(r.id) % 4) * 0.4, z: c.z + jit('z' + r.id, 5, 0.3) };
      r.services.forEach(function (id) { if (pos['svc:' + id]) edges.push({ kind: 'route', a: 'route:' + r.id, b: 'svc:' + id }); });
    });
    dockR.sort(by(function (r) { return r.id; })).forEach(function (r, i) {
      pos['route:' + r.id] = hall ? { x: ox + 3 + i * 2.2, y: GATE, z: 1.4 } : { x: -ox + 1 + i * 2.2, y: GATE, z: -oz - 3.4 };
    });
    (data.claims || []).forEach(function (c) {
      var pts = (c.pods || []).map(function (id) { return pos['pod:' + id]; }).filter(Boolean);
      if (!pts.length) { dockC.push(c); return; }
      var m = centre(pts);
      pos['claim:' + c.id] = { x: m.x + jit(c.id, 5, 0.22), y: CELLAR - (hash(c.id) % 3) * 0.35, z: m.z + jit('z' + c.id, 5, 0.22) };
      c.pods.forEach(function (id) { if (pos['pod:' + id]) edges.push({ kind: 'claim', a: 'pod:' + id, b: 'claim:' + c.id }); });
    });
    dockC.sort(by(function (c) { return c.id; })).forEach(function (c, i) {
      pos['claim:' + c.id] = hall ? { x: -ox + 1 + i * 1.7, y: CELLAR, z: 0 } : { x: -ox + 1 + i * 1.7, y: CELLAR, z: oz + 3.2 };
    });
    (data.pods || []).forEach(function (p) { (members[p.wl] || (members[p.wl] = [])).push(p.id); });
    (data.links || []).forEach(function (l) {
      if (members[l.from] && pos['svc:' + l.to]) edges.push({ kind: 'link', a: 'wl:' + l.from, b: 'svc:' + l.to, via: l.via });
    });
    return { plats: plats, pos: pos, edges: edges, members: members, w: all.w, d: all.d };
  }

  /* Who is connected to whom, looked up from either end. */
  function buildIndex(data) {
    var ix = { podSvcs: {}, svcRoutes: {}, podClaims: {}, wlPods: {}, wlOut: {}, svcIn: {}, ref: {} };
    function push(m, k, v) { (m[k] || (m[k] = [])).push(v); }
    (data.pods || []).forEach(function (p) { ix.ref['pod:' + p.id] = p; push(ix.wlPods, p.wl, p.id); });
    (data.services || []).forEach(function (s) {
      ix.ref['svc:' + s.id] = s;
      (s.pods || []).forEach(function (id) { push(ix.podSvcs, id, s.id); });
    });
    (data.routes || []).forEach(function (r) {
      ix.ref['route:' + r.id] = r;
      (r.services || []).forEach(function (id) { push(ix.svcRoutes, id, r.id); });
    });
    (data.claims || []).forEach(function (c) {
      ix.ref['claim:' + c.id] = c;
      (c.pods || []).forEach(function (id) { push(ix.podClaims, id, c.id); });
    });
    (data.links || []).forEach(function (l) { push(ix.wlOut, l.from, l); push(ix.svcIn, l.to, l); });
    return ix;
  }

  /* Everything one thing touches, as a set of keys: what stays lit when it is
     selected, and which lines are drawn for it. */
  function related(key, ix, plats) {
    var out = {}, i = key.indexOf(':'), kind = key.slice(0, i), id = key.slice(i + 1);
    out[key] = 1;
    function svc(sid, down) {
      out['svc:' + sid] = 1;
      (ix.svcRoutes[sid] || []).forEach(function (r) { out['route:' + r] = 1; });
      (ix.svcIn[sid] || []).forEach(function (l) {
        out['wl:' + l.from] = 1;
        (ix.wlPods[l.from] || []).forEach(function (p) { out['pod:' + p] = 1; });
      });
      if (down) ((ix.ref['svc:' + sid] || {}).pods || []).forEach(function (p) { out['pod:' + p] = 1; });
    }
    if (kind === 'pod') {
      var p = ix.ref[key] || {};
      (ix.podSvcs[id] || []).forEach(function (s) { svc(s, false); });
      (ix.podClaims[id] || []).forEach(function (c) { out['claim:' + c] = 1; });
      out['wl:' + p.wl] = 1;
      (ix.wlOut[p.wl] || []).forEach(function (l) { out['svc:' + l.to] = 1; });
    } else if (kind === 'svc') svc(id, true);
    else if (kind === 'route') ((ix.ref[key] || {}).services || []).forEach(function (s) { svc(s, true); });
    else if (kind === 'claim') ((ix.ref[key] || {}).pods || []).forEach(function (p) { out['pod:' + p] = 1; });
    else if (kind === 'plat') (plats || []).forEach(function (pl) {
      if (pl.key === id) pl.pods.forEach(function (p) { out['pod:' + p.id] = 1; });
    });
    return out;
  }

  /* What a thing says when you walk up to it. Every word is a fact the scene
     already holds about it (its problem, its restarts, its limit): a pod that
     made things up would be worse than one that said nothing. */
  function plural(count, word) { return count + ' ' + word + (count === 1 ? '' : 's'); }
  function span(sec) {
    if (sec < 90) return plural(sec, 'second');
    if (sec < 5400) return plural(Math.round(sec / 60), 'minute');
    if (sec < 129600) return plural(Math.round(sec / 3600), 'hour');
    return plural(Math.round(sec / 86400), 'day');
  }
  /* How the run before this one ended, as the kubelet kept it. It is the one
     thing a pod knows about why it fell over without anybody reading its log. */
  function exitLine(r) {
    var x = r.last_exit;
    if (!x) return '';
    return 'My last run ended ' + span(x.ago) + ' ago' + (x.reason ? ' with ' + x.reason : '') + (x.code != null ? ' (exit code ' + x.code + ')' : '')
      + (x.ran != null ? ', after ' + span(x.ran) : '') + '.';
  }
  function speech(key, ix, techs) {
    var r = ix.ref[key], kind = key.slice(0, key.indexOf(':'));
    if (!r) return '';
    var n = plural;
    if (kind === 'pod') {
      var tech = r.tech && techs[r.tech], who = tech ? 'I am ' + tech.label + '. ' : '';
      var use = r.mem != null && r.mem_lim ? ' I am using ' + fmtMem(r.mem) + ' of my ' + fmtMem(r.mem_lim) + '.'
        : r.mem_lim == null ? ' Nobody set me a memory limit.' : '';
      if (r.mood === 'crying') return who + r.problem + '. I have restarted ' + n(r.restarts, 'time') + '.';
      if (r.mood === 'dizzy') return who + [r.problem === 'Crash loop' ? 'I keep falling over. I am up this minute, but not for long.' : r.problem + '.',
        exitLine(r), n(r.restarts, 'restart') + ' and counting.'].filter(Boolean).join(' ');
      if (r.mood === 'worried') return who + 'I am running, but not ready (' + r.ready + ').';
      if (r.mood === 'hot') return who + 'I am nearly at my limit.' + use;
      if (r.mood === 'sleeping') return who + 'No machine has room for me (' + r.problem + ').';
      if (r.mood === 'hatching') return who + 'I am just starting.';
      if (r.mood === 'leaving') return who + 'I am shutting down.';
      if (r.mood === 'done') return who + 'My job is finished.';
      return who + 'All good. Ready ' + r.ready + ', ' + r.age + ' old.' + use;
    }
    if (kind === 'svc') return (r.pods || []).length ? 'I send to ' + n(r.pods.length, 'pod') + ' on ' + ((r.ports || []).join(', ') || 'no port') + '.'
      : r.selects ? 'Nobody answers behind me: my selector matches no pod.' : 'I point outside the cluster.';
    if (kind === 'route') return 'I let ' + ((r.hosts || []).join(', ') || 'traffic') + ' in' + (r.tls ? ', over TLS.' : '.');
    return (r.size || 'No size') + ', ' + String(r.status || '').toLowerCase() + ((r.pods || []).length ? ', mounted by ' + n(r.pods.length, 'pod') + '.' : ', and nobody mounts me.');
  }

  /* "Who manages you?" The answer is the verdict app/scene.py read off the
     workload's own labels, said plainly, and it says so when nothing on the
     workload tells: an invented "GitOps" sends somebody to edit the wrong place. */
  function managedLine(r) {
    var m = r.mgr || {}, own = r.workload ? ' I belong to the ' + r.kind + ' ' + r.workload + '.' : ' Nothing owns me: I am a bare pod.';
    if (m.by === 'gitops') return m.tool + ' manages me' + (m.detail ? ', through its application ' + m.detail : '') + '. That is GitOps: change me in Git, because a change made here is put back.' + own;
    if (m.by === 'helm') return 'I was installed with Helm' + (m.detail ? ', as the release ' + m.detail : '') + '. Nothing on me says a GitOps tool is watching, so that was a direct install.' + own;
    if (m.by === 'operator') return 'An operator made me: I am owned by the ' + m.tool + ' ' + m.detail + '. Change that object, not me.' + own;
    if (m.by === 'direct') return 'Somebody applied me directly with kubectl. No GitOps tool is managing me.' + own;
    if (m.by === 'node') return 'The machine runs me itself, from a file on ' + m.detail + '. Nothing in the cluster manages me.';
    return 'Nothing on me says who put me here: no GitOps mark, no Helm release and no kubectl mark.' + own;
  }
  function linksLine(key, ix) {
    var id = key.slice(4), r = ix.ref[key] || {}, parts = [], ins = {}, names;
    var svcs = ix.podSvcs[id] || [], outs = ix.wlOut[r.wl] || [], vols = ix.podClaims[id] || [];
    svcs.forEach(function (s) { (ix.svcIn[s] || []).forEach(function (l) { ins[l.from] = 1; }); });
    names = Object.keys(ins);
    if (svcs.length) parts.push('The Service ' + svcs.join(', ') + ' sends to me.');
    if (outs.length) parts.push('My settings name ' + outs.map(function (l) { return l.to; }).join(', ') + '.');
    if (names.length) parts.push(names.join(', ') + (names.length === 1 ? ' names' : ' name') + ' me in ' + (names.length === 1 ? 'its' : 'their') + ' settings.');
    if (vols.length) parts.push('I keep my data on ' + vols.join(', ') + '.');
    return parts.length ? parts.join(' ') + ' All of that is read from selectors and settings: nobody measured the traffic.'
      : 'Nothing in the cluster points at me, and my settings name no Service.';
  }

  /* Why a pod cannot be killed for good, or '': only an owner that counts its
     pods can be told to keep one fewer. The portal decides this again, from
     the cluster and in its own words (kmanage.kill_pod); this is so the line
     is offered disabled with its reason and not pressed to be refused. */
  function killWhy(r, ix) {
    var last = -1;
    if (!r.workload || r.kind === 'Deployment' || r.kind === 'ReplicaSet' || cleared(r)) return '';
    if (r.kind === 'DaemonSet') return 'one on every machine: it would come back';
    if (r.kind === 'Job') return 'its Job is still running it, and would start another';
    if (r.kind !== 'StatefulSet') return 'its ' + r.kind + ' would start another';
    (ix.wlPods[r.wl] || []).forEach(function (id) { var o = ix.ref['pod:' + id], m = o && /-(\d+)$/.exec(o.name); if (m) last = Math.max(last, +m[1]); });
    return r.name === r.workload + '-' + last ? '' : 'it gives up its last pod first: ' + r.workload + '-' + last;
  }
  /* A pod that has stopped, of an owner that will not start it again: a kill
     only clears it away, and no count changes (kmanage.STOPPED_OF). */
  function cleared(r) { return (r.phase === 'Succeeded' || r.phase === 'Failed') && /^(Deployment|ReplicaSet|Job)$/.test(r.kind); }
  /* What a kill did, for the feed and under the verdict. */
  function killed(r) {
    return !r.workload ? 'Nothing owns it: it will not come back' : cleared(r) ? 'It had already stopped: nothing starts another'
      : r.kind + ' ' + r.workload + ' keeps one fewer: nothing starts another';
  }
  function killLine(r) {
    var m = r.mgr || {};
    if (!r.workload) return 'Nothing owns me, so once I go I am gone. Choose your weapon.';
    if (cleared(r)) return 'I have already stopped, so a kill only clears me away: nothing starts another me, and no count changes. Choose your weapon.';
    return 'A kill is not a restart: I go, and ' + r.kind + ' ' + r.workload + ' is told to keep one fewer of us, so nothing starts another me.'
      + (m.by === 'gitops' ? ' ' + m.tool + ' keeps us as Git says, though, and may put me back: to keep me gone, change the count in Git.' : ' An autoscaler could still put me back.')
      + ' Choose your weapon.';
  }

  /* What a pod answers when the doctor asks it what is wrong: the facts
     speech() gives, said the way a patient says them, and ending with what it
     needs. The view uses it when whoever is being the doctor sends no answer
     in the pod's voice, so an examination is never one-sided. The reasons are
     Kubernetes's own, put into words; one it does not know is quoted as is. */
  var WHY = {
    ImagePullBackOff: 'I cannot fetch my image', ErrImagePull: 'I cannot fetch my image', InvalidImageName: 'The name of my image is not a valid one',
    CreateContainerConfigError: 'My settings name a ConfigMap or a Secret that is not there', CreateContainerError: 'My container could not be created',
    OOMKilled: 'I was killed for using more memory than I am allowed', Error: 'My program stopped with an error',
    ContainerCannotRun: 'My program could not be started', Evicted: 'The machine put me out to save itself',
    Unschedulable: 'No machine has room for me', NotReady: 'I am running, but my readiness check does not pass',
    CrashLoopBackOff: 'I keep falling over, and I am made to wait longer before every try',
    'Crash loop': 'I keep falling over: I am up this minute, but not for long'
  };
  function plea(key, ix, techs) {
    var r = ix.ref[key], m, parts;
    if (!r) return '';
    if (key.indexOf('pod:') || (r.tone !== 'bad' && r.tone !== 'warn')) return speech(key, ix, techs);
    m = r.mgr || {};
    if (r.mood === 'hot') parts = ['I am nearly at my limit' + (r.mem != null && r.mem_lim ? ': I am using ' + fmtMem(r.mem) + ' of my ' + fmtMem(r.mem_lim) : '') + '.'];
    else parts = [WHY[r.problem] ? WHY[r.problem] + (/loop/i.test(r.problem) ? '.' : ' (' + r.problem + ').') : 'Kubernetes says ' + (r.problem || r.phase) + ' about me.'];
    if (/Image/.test(r.problem) && (r.images || []).length) parts.push('It is ' + r.images[0] + '.');
    if (r.problem === 'NotReady') parts.push('Ready ' + r.ready + '.');
    parts.push(exitLine(r));
    if (r.restarts) parts.push('That is ' + plural(r.restarts, 'restart') + '.');
    if (m.by === 'gitops') parts.push(m.tool + ' keeps me the way Git says, so my cure is in Git.');
    else if (m.by === 'operator') parts.push('An operator made me, so my cure is in the ' + m.tool + ' that owns me.');
    parts.push('Can you help me?');
    return parts.filter(Boolean).join(' ');
  }

  /* What a thing mutters as you walk past it. A soul, but an honest one: every
     line is one fact off its own row, in the first person. `to` names the
     Service a line is about, so a pod behind that Service can answer. */
  function murmurs(key, ix, techs) {
    var r = ix.ref[key], cut = key.indexOf(':'), kind = key.slice(0, cut), id = key.slice(cut + 1), out = [], tech, sibs, m;
    if (!r) return out;
    function say(text, to) { out.push({ text: text, to: to || '' }); }
    function last(path) { return String(path).split('/').pop(); }
    if (kind !== 'pod') { say(speech(key, ix, techs)); return out; }
    if (r.tone === 'bad') {
      say('Help! ' + (WHY[r.problem] || 'Kubernetes says ' + (r.problem || r.phase)) + '.');
      if (r.restarts) say(plural(r.restarts, 'restart') + ', and I am still trying.');
      return out;
    }
    if (r.mood === 'worried') say('Running, but not ready yet (' + r.ready + ').');
    else if (r.mood === 'hot') say('So close to my limit…');
    else if (r.mood === 'sleeping') say('Still waiting for a machine with room for me.');
    else if (r.mood === 'hatching') say('Just waking up…');
    else if (r.mood === 'leaving') say('My time is up. Goodbye.');
    else if (r.mood === 'done') say('My job is finished.');
    if (r.tone !== 'ok') return out;
    tech = r.tech && techs[r.tech]; sibs = (ix.wlPods[r.wl] || []).length; m = r.mgr || {};
    if (tech) say('I am ' + tech.label + '.');
    say(r.restarts ? 'I have fallen over ' + plural(r.restarts, 'time') + '. Still here.' : r.age + ' up, and not one restart.');
    if (r.mem != null && r.mem_lim) say('Using ' + fmtMem(r.mem) + ' of my ' + fmtMem(r.mem_lim) + '.');
    else if (r.mem_lim == null) say('Nobody set me a memory limit.');
    if (r.cpu != null) say(fmtCpu(r.cpu) + ' of CPU right now.');
    if (sibs > 1 && r.workload) say('There are ' + sibs + ' of us in ' + r.workload + '.');
    (ix.podSvcs[id] || []).slice(0, 1).forEach(function (sv) { say('I answer for the Service ' + last(sv) + '.'); });
    (ix.wlOut[r.wl] || []).slice(0, 2).forEach(function (l) { say('My settings name ' + last(l.to) + '.', l.to); });
    (ix.podClaims[id] || []).slice(0, 1).forEach(function (c) { say('My data lives on ' + last(c) + '.'); });
    if (m.by === 'gitops') say(m.tool + ' keeps me the way Git says.');
    else if (m.by === 'direct') say('Somebody applied me by hand.');
    else if (m.by === 'helm') say('Helm put me here.');
    else if (m.by === 'operator') say('An operator made me.');
    if (r.node) say('I live on ' + r.node + '.');
    return out;
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { layout: layout, buildIndex: buildIndex, related: related, speech: speech, plea: plea, murmurs: murmurs,
      managedLine: managedLine, linksLine: linksLine, killWhy: killWhy, killLine: killLine, killed: killed, fmtCpu: fmtCpu, fmtMem: fmtMem, hash: hash };
  }
  if (typeof document === 'undefined') return;
  var stage = document.getElementById('c3d');
  if (!stage) return;
  /* Two worlds share this stage. A cluster is this file's own. The CITY
     (data-city) is every cluster as a building, drawn by cluster3d-city.js
     with this file's engine and figure: it is handed them at the foot of the
     file, and until then `city` only keeps this file's own hands off the
     stage. A cluster entered through a building's door (?from=city) starts in
     its walk and leaves back to the street. */
  var city = stage.getAttribute('data-city') != null, cityHook = {}, VIA = new URLSearchParams(location.search);
  var fromCity = !city && VIA.get('from') === 'city', cameIn = false;

  /* ── looks ───────────────────────────────────────────────────────── */
  var BODY = { happy: '#ffd23f', hot: '#ff9a3d', worried: '#f7c95a', sleeping: '#b9c4ff',
    hatching: '#ffe9a8', leaving: '#dfe9ff', crying: '#7fa8ff', dizzy: '#ff7a7a', done: '#9aa7b8' };
  var INK = { sleeping: '#1c2740', leaving: '#1c2740', crying: '#14224a', done: '#1c2740' };
  var TONE = { ok: [61, 220, 151], warn: [255, 176, 32], bad: [255, 70, 90], info: [90, 180, 255], idle: [138, 148, 166] };
  var FAM = { db: '#3f7fe0', queue: '#8f63e6', cache: '#e8743b', storage: '#2fae9c', workflow: '#d9a520',
    observability: '#d85c97', network: '#3f9fd0', security: '#5fa83a', system: '#5c6780', delivery: '#c9803e' };
  var EDGE = { svc: [80, 215, 255], route: [255, 200, 90], claim: [176, 148, 255], link: [110, 245, 165] };
  var MOOD_WORDS = [['happy', 'Healthy'], ['crying', 'Failing'], ['dizzy', 'Crash-looping'],
    ['worried', 'Not ready'], ['hot', 'Near its limit'], ['sleeping', 'No machine for it'],
    ['hatching', 'Starting'], ['leaving', 'Terminating'], ['done', 'Completed']];
  var TONE_WORDS = [['ok', 'healthy'], ['bad', 'failing'], ['warn', 'need a look'], ['info', 'changing'], ['idle', 'completed']];
  var FONT = 'ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif';
  var EMOJI = '"Apple Color Emoji","Segoe UI Emoji","Noto Color Emoji",sans-serif';

  function rgb(hex) { var n = parseInt(hex.slice(1), 16); return [n >> 16, (n >> 8) & 255, n & 255]; }
  function mix(c, to, f) { return 'rgb(' + c.map(function (v) { return Math.round(v + (to - v) * f); }).join(',') + ')'; }
  function rgba(c, a) { return 'rgba(' + c[0] + ',' + c[1] + ',' + c[2] + ',' + a + ')'; }
  var sprites = {};
  function sprite(key, draw) {
    if (sprites[key]) return sprites[key];
    var cv = document.createElement('canvas'); cv.width = cv.height = 128;
    draw(cv.getContext('2d')); return (sprites[key] = cv);
  }
  function ball(hex) {
    return sprite('b' + hex, function (g) {
      var c = rgb(hex), grad = g.createRadialGradient(46, 40, 6, 64, 64, 62);
      grad.addColorStop(0, mix(c, 255, 0.6)); grad.addColorStop(0.45, hex); grad.addColorStop(1, mix(c, 0, 0.5));
      g.fillStyle = grad; g.beginPath(); g.arc(64, 64, 62, 0, TAU); g.fill();
      var rim = g.createRadialGradient(64, 64, 44, 64, 64, 62);
      rim.addColorStop(0, 'rgba(255,255,255,0)'); rim.addColorStop(1, 'rgba(255,255,255,.2)');
      g.fillStyle = rim; g.fill();
      g.fillStyle = 'rgba(255,255,255,.5)'; g.beginPath(); g.ellipse(44, 33, 15, 8, -0.6, 0, TAU); g.fill();
    });
  }
  /* The doctor's badge beside its name. A client that says it is Claude is
     drawn as the small orange block creature people know Claude Code by; any
     other client gets a plain cross. Both are drawn here, stroke by stroke:
     no image file is fetched or shipped. */
  var CLAUDE = '#d97757';
  function critter(k, cx, cy, r) {
    k.fillStyle = CLAUDE;
    k.fillRect(cx - r * 0.8, cy - r * 0.62, r * 1.6, r * 0.92);      // the body
    k.fillRect(cx - r, cy - r * 0.3, r * 2, r * 0.3);                 // an arm each side
    for (var i = 0; i < 4; i++) k.fillRect(cx - r * 0.7 + i * r * 0.4, cy + r * 0.3, r * 0.2, r * 0.36);      // four legs
    k.fillStyle = '#1b1210'; k.fillRect(cx - r * 0.42, cy - r * 0.4, r * 0.18, r * 0.42); k.fillRect(cx + r * 0.24, cy - r * 0.4, r * 0.18, r * 0.42);
  }
  function cross(k, cx, cy, r) {
    k.fillStyle = '#3ddc97';
    k.fillRect(cx - r * 0.2, cy - r * 0.7, r * 0.4, r * 1.4); k.fillRect(cx - r * 0.7, cy - r * 0.2, r * 1.4, r * 0.4);
  }
  function isClaude(who) { return /claude/i.test(who || ''); }
  function glyph(ch) {
    return sprite('e' + ch, function (g) {
      g.font = '96px ' + EMOJI; g.textAlign = 'center'; g.textBaseline = 'middle'; g.fillText(ch, 64, 70);
    });
  }

  /* The same robot in 2D, for the key and the card: a visor and two eyes. */
  var CERAMIC = '#dfe4ee';
  var EYES = { happy: '#3ddc97', hot: '#ff9a3d', worried: '#ffb020', sleeping: '#8a94a6', hatching: '#5ab4ff', leaving: '#5ab4ff', crying: '#ff465a', dizzy: '#ff465a', done: '#8a94a6' };
  function face(g, x, y, r, mood) {
    if (r < 5) return;
    var ex = r * 0.27, ey = -r * 0.1, er = r * 0.1;
    g.save(); g.translate(x, y); g.fillStyle = '#080d1a'; g.beginPath();
    if (g.roundRect) g.roundRect(-r * 0.66, -r * 0.4, r * 1.32, r * 0.6, r * 0.28); else g.rect(-r * 0.66, -r * 0.4, r * 1.32, r * 0.6);
    g.fill();
    g.strokeStyle = g.fillStyle = EYES[mood] || EYES.done; g.lineWidth = Math.max(1.2, r * 0.085); g.lineCap = 'round';
    [-1, 1].forEach(function (s) {
      var cx = s * ex; g.beginPath();
      if (mood === 'happy') g.arc(cx, ey + er * 0.7, er * 1.15, PI * 1.12, PI * 1.88);
      else if (mood === 'crying') { g.moveTo(cx - s * er, ey - er * 0.6); g.lineTo(cx + s * er, ey + er * 0.6); }
      else if (mood === 'dizzy') { g.moveTo(cx - er, ey - er); g.lineTo(cx + er, ey + er); g.moveTo(cx - er, ey + er); g.lineTo(cx + er, ey - er); }
      else if (mood === 'hatching') g.arc(cx, ey, er, 0.4, PI * 1.5);
      else if (mood === 'hot' || mood === 'worried') { g.arc(cx, ey, er * 0.8, 0, TAU); g.fill(); g.beginPath(); }
      else { g.moveTo(cx - er, ey); g.lineTo(cx + er, ey); }
      g.stroke();
    });
    g.restore();
  }

  /* ── state ───────────────────────────────────────────────────────── */
  var $ = function (id) { return document.getElementById(id); };
  var cv = $('c3dCanvas'), ov = $('c3dOver'), g = ov.getContext('2d');
  var gpu = window.C3DGL ? window.C3DGL(cv) : null;
  /* An engine may draw the cluster as a hall (`hall`, which only the prototype's engine says of itself). Then the
     machines stand along an aisle, and the engine is told where each one's bay is so it can stand a rack behind it.
     Nothing else differs: what a pod is, says and does is the same either way. */
  var HALL = !!(gpu && gpu.hall);
  var calm = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var W = 1, H = 1, DPR = 1, F = 1;
  var cam = { yaw: 0.62, pitch: 0.5, dist: 60, tx: 0, ty: 0, tz: 0 };
  var goal = { yaw: 0.62, pitch: 0.5, dist: 60, tx: 0, ty: 0, tz: 0 };
  var ex = 0, ey = 0, ez = 0, fx = 0, fy = 0, fz = -1, rx = 1, rz = 0, ux = 0, uy = 1, uz = 0;
  var NEAR = 0.6;
  var data = null, lay = null, ix = null, items = {}, list = [];
  var groupBy = 'node', lines = 'all', labels = true, spin = true, touring = false;
  var selKey = '', selRel = null, hoverKey = '', hoverRel = null, focusNs = '', toneOnly = '', found = null;
  var lastInput = 0, lastOk = 0, started = 0, fit = 60, tourAt = 0, tourList = [], tourI = 0;
  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }
  function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); }

  function resize() {
    var b = stage.getBoundingClientRect();
    DPR = Math.min(window.devicePixelRatio || 1, 2);
    W = Math.max(1, b.width); H = Math.max(1, b.height);
    ov.width = Math.round(W * DPR); ov.height = Math.round(H * DPR);
    F = (H / 2) / Math.tan(25 * PI / 180);
    // The picture itself is drawn a little under full sharpness on a dense
    // screen: it is all soft light, and the names above it stay at full.
    if (gpu) gpu.resize(W, H, Math.min(DPR, 1.5));
  }

  function basis() {
    var cp = Math.cos(cam.pitch), sp = Math.sin(cam.pitch), cy = Math.cos(cam.yaw), sy = Math.sin(cam.yaw);
    ex = cam.tx + cam.dist * cp * sy; ey = cam.ty + cam.dist * sp; ez = cam.tz + cam.dist * cp * cy;
    fx = -cp * sy; fy = -sp; fz = -cp * cy;
    rx = -fz / cp; rz = fx / cp;
    ux = -rz * fy; uy = rz * fx - rx * fz; uz = rx * fy;
  }
  function view(x, y, z) {
    var dx = x - ex, dy = y - ey, dz = z - ez;
    return [dx * rx + dz * rz, dx * ux + dy * uy + dz * uz, dx * fx + dy * fy + dz * fz];
  }
  function scr(v) { var k = F / v[2]; return [W / 2 + v[0] * k, H / 2 - v[1] * k]; }
  function ringOf(pl) {
    var c = 0.8, pts = [], x0 = pl.x, z0 = pl.z, x1 = pl.x + pl.w, z1 = pl.z + pl.d;
    [[x1 - c, z0 + c, -PI / 2], [x1 - c, z1 - c, 0], [x0 + c, z1 - c, PI / 2], [x0 + c, z0 + c, PI]].forEach(function (k) {
      for (var i = 0; i <= 3; i++) { var a = k[2] + i * PI / 6; pts.push([k[0] + Math.cos(a) * c, k[1] + Math.sin(a) * c]); }
    });
    return pts;
  }

  /* ── data in ─────────────────────────────────────────────────────── */
  function bounce(u) {
    if (u < 1 / 2.75) return 7.5625 * u * u;
    if (u < 2 / 2.75) { u -= 1.5 / 2.75; return 7.5625 * u * u + 0.75; }
    if (u < 2.5 / 2.75) { u -= 2.25 / 2.75; return 7.5625 * u * u + 0.9375; }
    u -= 2.625 / 2.75; return 7.5625 * u * u + 0.984375;
  }
  function relayout(first) {
    lay = layout(data, groupBy, HALL);
    lay.bays = null;
    if (HALL) {      // a bay: where it stands, how big, which side of the aisle, and what kind (1 control plane, 2 no machine, 3 not ready)
      lay.bays = new Float32Array(lay.plats.length * 6);
      lay.plats.forEach(function (pl, i) { lay.bays.set([pl.x, pl.z, pl.w, pl.d, pl.side || 0, pl.limbo ? 2 : pl.node && !pl.node.ready ? 3 : pl.rank === 0 ? 1 : 0], i * 6); });
    }
    lay.plats.forEach(function (pl) { pl.ring = ringOf(pl); });
    var now = performance.now() / 1000, seen = {}, order = 0;
    Object.keys(lay.pos).forEach(function (key) {
      var p = lay.pos[key], it = items[key], kind = key.slice(0, key.indexOf(':')), fresh = !it;
      seen[key] = 1;
      if (!it) {
        it = items[key] = { key: key, kind: kind, x: p.x, y: p.y, z: p.z, seed: (hash(key) % 1000) / 1000,
          // the first picture assembles itself; after that a new pod just lands
          born: now + (first && !calm ? Math.min(2.2, order * 0.004) + 0.25 : 0), flash: first ? 0 : now };
      } else if (kind === 'pod' && it.ref && it.ref.mood !== ix.ref[key].mood) it.flash = now;
      it.gx = p.x; it.gy = p.y; it.gz = p.z; it.ref = ix.ref[key]; it.dead = 0;
      if (fresh && !first && kind === 'pod') healed(it, now);
      order++;
    });
    Object.keys(items).forEach(function (key) {
      if (seen[key]) return;
      // a pod that has gone floats away; nothing else is worth a farewell
      if (items[key].kind === 'pod' && !items[key].dead && !first) {
        items[key].dead = now; graves.push({ wl: items[key].ref.wl, x: items[key].x, y: items[key].y, z: items[key].z, at: now });
      }
      else if (items[key].kind !== 'pod' || first) delete items[key];
    });
    var rad = Math.hypot(lay.w, lay.d) / 2 + 5;
    fit = clamp(rad / Math.tan(25 * PI / 180) * 0.52, 16, 600);
    if (selKey && !ix.ref[selKey] && selKey.indexOf('plat:')) select('', false);
    selRel = selKey ? related(selKey, ix, lay.plats) : null;
    hoverRel = hoverKey ? related(hoverKey, ix, lay.plats) : null;
  }
  function home(jump) {
    goal.tx = 0; goal.ty = 0; goal.tz = 0; goal.dist = fit; goal.pitch = 0.44;
    if (jump) { cam.tx = cam.ty = cam.tz = 0; cam.dist = fit * 2.6; cam.pitch = 1.25; cam.yaw = goal.yaw - 1.6; }
  }
  function take(d) {
    var first = !data;
    if (d.error) {
      lost = true;
      $('c3dLive').className = 'c3d-live bad';
      $('c3dLive').textContent = 'could not read the cluster: ' + d.error;
      if (first) veil('This cluster did not answer (' + d.error + '). Nothing is drawn, because an empty picture would look like a healthy one. Trying again…', true);
      return;
    }
    data = d; ix = buildIndex(d); lastOk = Date.now(); lost = false;
    M = gpu.atlas(MARKS.concat(Object.keys(d.techs || {}).map(function (k) { return d.techs[k].glyph; }),
      [{ key: 'cross', draw: cross }]));
    pulseAt = performance.now() / 1000;
    relayout(first);
    if (first) { home(!calm); started = performance.now() / 1000; veil('', false); }
    hud(); if (selKey) card();
    // through a building's door: you are already walking, as who you were in the street
    if (fromCity && !cameIn) { cameIn = true; enterWalk(); pickClose(); }
    if (found) search($('c3dSearch').value);
    if (walk && game && !game.won && game.sick0 && !needy().length) win();
  }
  function veil(text, bad) {
    var v = $('c3dVeil');
    v.className = 'c3d-veil' + (text ? '' : ' gone') + (bad ? ' err' : '');
    if (text) $('c3dVeilText').textContent = text;
  }
  var timer = 0, busy = false;
  function poll(refresh) {
    if (busy) return;       // a second chain would poll twice as often for ever
    clearTimeout(timer);
    if (fin) { timer = setTimeout(function () { poll(refresh); }, 500); return; }      // not under a finisher: its pod would be gone before the blow lands
    if (document.hidden) { timer = setTimeout(poll, 4000); return; }
    busy = true;
    fetch(stage.getAttribute('data-json') + (refresh ? '&refresh=1' : ''), { credentials: 'same-origin', headers: { Accept: 'application/json' } })
      .then(function (r) { if (!r.ok) throw new Error('the portal answered ' + r.status); return r.json(); })
      .then(take)
      .catch(function (e) {
        lost = true;
        $('c3dLive').className = 'c3d-live bad';
        $('c3dLive').textContent = 'lost contact with the portal, retrying';
        if (!data) veil('Could not load the cluster: ' + (e && e.message || 'no answer') + '. Trying again…', true);
      })
      .then(function () { busy = false; timer = setTimeout(poll, 8000); });
  }

  /* ── panels ──────────────────────────────────────────────────────── */
  function hud() {
    var t = data.totals || {}, box = $('c3dTotals'); clear(box);
    TONE_WORDS.forEach(function (w) {
      var n = t[w[0]] || 0;
      if (!n && w[0] !== 'ok' && w[0] !== 'bad') return;
      var b = el('button', 'c3d-tot' + (n ? '' : ' quiet') + (toneOnly === w[0] ? ' on' : ''));
      b.type = 'button'; b.title = 'Light only these, and fly to the first';
      var dot = el('i'); dot.style.setProperty('--c', rgba(TONE[w[0]], 1));
      b.appendChild(dot); b.appendChild(el('b', '', String(n))); b.appendChild(el('span', '', w[1]));
      b.addEventListener('click', function () { onlyTone(w[0]); });
      box.appendChild(b);
    });
    var m = el('span', 'c3d-tot quiet'); m.style.cursor = 'default';
    m.textContent = (t.nodes_ready || 0) + ' of ' + (t.nodes || 0) + ' machines ready · ' + (t.services || 0) + ' services · ' + (t.claims || 0) + ' volumes';
    box.appendChild(m);
    if (t.unlimited) {
      var u = el('span', 'c3d-tot quiet'); u.style.cursor = 'default';
      u.textContent = t.unlimited + ' pod' + (t.unlimited === 1 ? '' : 's') + ' with no limit';
      u.title = 'Pods that set neither a CPU nor a memory limit: they can take whatever the machine has';
      box.appendChild(u);
    }
    var sp = $('c3dSpaces'); clear(sp);
    (data.namespaces || []).forEach(function (n) {
      var c = el('button', 'c3d-chip' + (focusNs === n.name ? ' on' : focusNs ? ' off' : '')); c.type = 'button';
      c.title = 'Light only ' + n.name;
      var sw = el('i'); sw.style.setProperty('--c', 'hsl(' + hash(n.name) % 360 + ',70%,62%)');
      c.appendChild(sw); c.appendChild(el('span', '', n.name));
      c.appendChild(el('em', n.bad ? 'bad' : '', n.bad ? n.bad + ' failing' : String(n.pods)));
      c.addEventListener('click', function () { focusNs = focusNs === n.name ? '' : n.name; hud(); });
      sp.appendChild(c);
    });
    var th = $('c3dTechs'), keys = Object.keys(data.techs || {}); clear(th);
    $('c3dTechHead').hidden = !keys.length;
    keys.sort().forEach(function (k) {
      var row = el('div', 'c3d-leg'), cap = el('i'); cap.style.setProperty('--c', FAM[data.techs[k].family] || FAM.system); row.appendChild(cap);
      row.appendChild(el('span', '', data.techs[k].label)); row.title = data.techs[k].label; th.appendChild(row);
    });
  }
  function legend() {
    var box = $('c3dFaces'); clear(box);
    MOOD_WORDS.forEach(function (m) {
      var row = el('div', 'c3d-leg'), c = el('canvas'); c.width = c.height = 36;
      var k = c.getContext('2d'); k.drawImage(ball(CERAMIC), 2, 2, 32, 32);
      face(k, 18, 18, 16, m[0]);
      row.appendChild(c); row.appendChild(el('span', '', m[1])); row.title = m[1]; box.appendChild(row);
    });
    var note = el('div', 'c3d-note', 'The eyes are the state. A cap is the software it runs. A bubble is its memory limit, filled to what it uses: it appears on the pod you pick and on any that is getting tight.');
    note.style.gridColumn = '1 / -1'; box.appendChild(note);
    var ln = $('c3dLines'); clear(ln);
    [['svc', 'Service to its pods'], ['route', 'Route to a Service'], ['link', 'Named in its settings'], ['claim', 'Volume']].forEach(function (k) {
      var row = el('div', 'c3d-leg'), sw = el('i'); sw.style.setProperty('--c', rgba(EDGE[k[0]], 1));
      row.appendChild(sw); row.appendChild(el('span', '', k[1])); row.title = k[1]; ln.appendChild(row);
    });
  }

  function meter(box, name, used, req, lim, fmt, metrics) {
    var m = el('div', 'c3d-meter'), top = el('div', 'c3d-meter-top');
    top.appendChild(el('b', '', name));
    top.appendChild(el('span', '', used == null ? (lim == null ? 'no limit' : 'limit ' + fmt(lim))
      : fmt(used) + (lim == null ? ' used' : ' of ' + fmt(lim))));
    m.appendChild(top);
    var max = lim || Math.max(used || 0, req || 0) * 1.25 || 1, bar = el('div', 'c3d-bar');
    if (used != null) {
      var f = clamp(used / max, 0, 1), fill = el('u'); fill.style.width = (f * 100).toFixed(1) + '%';
      fill.style.setProperty('--c', lim == null ? '#8fa0d0' : f >= 0.9 ? '#ff5d6c' : f >= 0.7 ? '#ffb020' : '#3ddc97');
      bar.appendChild(fill);
    }
    if (req != null) { var mark = el('s'); mark.style.left = (clamp(req / max, 0, 1) * 100).toFixed(1) + '%'; mark.title = 'what it asked for'; bar.appendChild(mark); }
    m.appendChild(bar);
    var words = [];
    if (req != null) words.push('asked for ' + fmt(req));
    if (used == null) words.push(metrics ? 'no usage reported for it' : 'usage unknown: this cluster has no metrics server');
    var s = el('small', lim == null ? 'warn' : '', (lim == null ? 'No limit: it can take whatever the machine has. ' : '') + words.join(' · '));
    m.appendChild(s); box.appendChild(m);
  }
  function linkRow(box, key, text, note, kind) {
    var b = el('button', 'c3d-link'); b.type = 'button';
    b.style.setProperty('--c', rgba(EDGE[kind] || TONE.idle, 1));
    b.appendChild(el('span', '', text)); if (note) b.appendChild(el('em', '', note));
    b.addEventListener('click', function () {
      // a workload is not a thing on the stage; its first pod is
      var k = key.indexOf('wl:') ? key : 'pod:' + (ix.wlPods[key.slice(3)] || [''])[0];
      select(k, true);
    });
    box.appendChild(b);
  }
  function section(box, title, rows, kind) {
    if (!rows.length) return 0;
    box.appendChild(el('div', 'c3d-h', title));
    var l = el('div', 'c3d-links'); rows.forEach(function (r) { linkRow(l, r[0], r[1], r[2], kind); }); box.appendChild(l);
    return rows.length;
  }
  function kv(box, pairs) {
    var dl = el('dl', 'c3d-kv');
    pairs.forEach(function (p) { if (p[1] == null || p[1] === '') return; dl.appendChild(el('dt', '', p[0])); dl.appendChild(el('dd', '', String(p[1]))); });
    box.appendChild(dl);
  }
  function card() {
    var box = $('c3dCard'); clear(box);
    if (!selKey) { box.hidden = true; return; }
    var i = selKey.indexOf(':'), kind = selKey.slice(0, i), id = selKey.slice(i + 1), ref = ix.ref[selKey];
    var base = stage.getAttribute('data-base'), head = el('div', 'c3d-card-head'), n = 0;
    var close = el('button', 'c3d-x', '×'); close.type = 'button'; close.title = 'Close (Esc)';
    close.addEventListener('click', function () { select('', false); });
    function title(mark, kindWord, name) {
      head.appendChild(mark); var w = el('div');
      w.appendChild(el('div', 'c3d-kind', kindWord)); w.appendChild(el('h2', '', name));
      head.appendChild(w); head.appendChild(close); box.appendChild(head);
    }
    function state(text, tone) { var s = el('div', 'c3d-state', text); s.style.setProperty('--c', rgba(TONE[tone], 1)); box.appendChild(s); }
    if (kind === 'pod' && ref) {
      var c = el('canvas'); c.width = c.height = 92; var k = c.getContext('2d');
      var tech = ref.tech && data.techs[ref.tech];
      k.drawImage(ball(CERAMIC), 4, 4, 84, 84); face(k, 46, 46, 42, ref.mood);
      title(c, (tech ? tech.label + ' pod' : 'Pod') + ' · ' + ref.ns, ref.name);
      var word = (MOOD_WORDS.filter(function (m) { return m[0] === ref.mood; })[0] || [])[1];
      state((ref.problem || word) + ' · ready ' + ref.ready + ' · ' + ref.restarts + ' restart' + (ref.restarts === 1 ? '' : 's') + ' · ' + ref.age + ' old', ref.tone);
      kv(box, [['Machine', ref.node || 'none yet'], ['Belongs to', ref.workload ? ref.kind + ' ' + ref.workload : 'nothing (a bare pod)'],
        ['Image', (ref.images || []).join(', ')], ['Address', ref.ip], ['Class', ref.qos]]);
      box.appendChild(el('div', 'c3d-h', 'Limits'));
      meter(box, 'CPU', ref.cpu, ref.cpu_req, ref.cpu_lim, fmtCpu, data.metrics);
      meter(box, 'Memory', ref.mem, ref.mem_req, ref.mem_lim, fmtMem, data.metrics);
      if (ref.lim_partial) box.appendChild(el('p', 'c3d-note', 'Only some of its containers carry a limit, so the pod as a whole is not bounded.'));
      n += section(box, 'Services that send to it', (ix.podSvcs[id] || []).map(function (s) {
        return ['svc:' + s, ix.ref['svc:' + s].name, (ix.ref['svc:' + s].ports || []).join(', ')]; }), 'svc');
      var rts = {};
      (ix.podSvcs[id] || []).forEach(function (s) { (ix.svcRoutes[s] || []).forEach(function (r) { rts[r] = 1; }); });
      n += section(box, 'Reached from outside through', Object.keys(rts).map(function (r) {
        var x = ix.ref['route:' + r]; return ['route:' + r, (x.hosts || []).join(', ') || x.name, x.tls ? 'TLS' : '']; }), 'route');
      var outs = (ix.wlOut[ref.wl] || []).map(function (l) { return ['svc:' + l.to, l.to, 'in ' + l.via]; });
      n += section(box, 'Its settings name', outs, 'link');
      var ins = {};
      (ix.podSvcs[id] || []).forEach(function (s) { (ix.svcIn[s] || []).forEach(function (l) { ins[l.from] = l.via; }); });
      var inRows = Object.keys(ins).map(function (w) { return ['wl:' + w, w, 'in ' + ins[w]]; });
      n += section(box, 'Named in the settings of', inRows, 'link');
      if (outs.length || inRows.length) box.appendChild(el('p', 'c3d-note', 'These two lists are read from settings: a Service’s name was found in a pod’s environment, start command or ConfigMap. Nothing here measured traffic, and a host kept in a Secret is not seen.'));
      n += section(box, 'Volumes', (ix.podClaims[id] || []).map(function (cl) {
        var x = ix.ref['claim:' + cl]; return ['claim:' + cl, x.name, x.size + (x.bound ? '' : ' · ' + x.status)]; }), 'claim');
      if (!n) box.appendChild(el('p', 'c3d-note', 'Nothing in the cluster points at this pod, and its settings name no Service.'));
      var acts = el('div', 'c3d-acts'), target = encodeURIComponent(ref.ns + '/' + ref.name);
      [['Logs', '&tab=pods&inspect=logs&target=' + target], ['Describe', '&tab=pods&inspect=describe&target=' + target],
        ['In the pod table', '&tab=pods&ns=' + encodeURIComponent(ref.ns) + '&q=' + encodeURIComponent(ref.name)]].forEach(function (a) {
        var l = el('a', '', a[0]); l.href = base + a[1]; if (walk) { l.target = '_blank'; l.rel = 'noopener'; } acts.appendChild(l); });
      box.appendChild(acts);
    } else if (kind === 'svc' && ref) {
      title(el('div', 'c3d-glyph', 'SVC'), 'Service · ' + ref.ns, ref.name);
      state(ref.pods.length ? ref.pods.length + ' pod' + (ref.pods.length === 1 ? '' : 's') + ' behind it'
        : ref.selects ? 'No pod matches its selector: nothing answers on it' : 'It selects no pods (it points somewhere else)',
      ref.pods.length ? 'ok' : ref.selects ? 'bad' : 'idle');
      kv(box, [['Type', ref.type], ['Ports', (ref.ports || []).join(', ')], ['Outside', (ref.external || []).join(', ')]]);
      section(box, 'Routes to it', (ix.svcRoutes[id] || []).map(function (r) {
        var x = ix.ref['route:' + r]; return ['route:' + r, (x.hosts || []).join(', ') || x.name, x.tls ? 'TLS' : '']; }), 'route');
      section(box, 'Named in the settings of', (ix.svcIn[id] || []).map(function (l) { return ['wl:' + l.from, l.from, 'in ' + l.via]; }), 'link');
      section(box, 'Sends to', ref.pods.map(function (p) { var x = ix.ref['pod:' + p]; return ['pod:' + p, x.name, x.problem || x.phase]; }), 'svc');
    } else if (kind === 'route' && ref) {
      title(el('div', 'c3d-glyph', 'ROUTE'), ref.kind + ' · ' + ref.ns, ref.name);
      state((ref.hosts || []).join(', ') || 'no host name', ref.services.length ? 'ok' : 'warn');
      kv(box, [['TLS', ref.tls ? 'yes' : 'no']]);
      if (!section(box, 'Sends to', ref.services.map(function (s) { return ['svc:' + s, s, '']; }), 'route'))
        box.appendChild(el('p', 'c3d-note', 'It names no Service this cluster has.'));
    } else if (kind === 'claim' && ref) {
      title(el('div', 'c3d-glyph', 'VOL'), 'Volume claim · ' + ref.ns, ref.name);
      state(ref.status + (ref.size ? ' · ' + ref.size : ''), ref.bound ? 'ok' : 'bad');
      kv(box, [['Class', ref.sc || 'the default']]);
      if (!section(box, 'Mounted by', ref.pods.map(function (p) { return ['pod:' + p, ix.ref['pod:' + p].name, '']; }), 'claim'))
        box.appendChild(el('p', 'c3d-note', 'No pod mounts it.'));
    } else if (kind === 'plat') {
      var pl = lay.plats.filter(function (p) { return p.key === id; })[0];
      if (!pl) { box.hidden = true; return; }
      var nd = pl.node;
      title(el('div', 'c3d-glyph', nd ? 'NODE' : pl.limbo ? 'WAIT' : 'NS'), nd ? 'Machine' : pl.limbo ? 'Waiting room' : 'Namespace', pl.limbo ? 'Not on any machine' : pl.key);
      if (nd) {
        state((nd.ready ? 'Ready' : 'Not ready') + (nd.schedulable ? '' : ' · cordoned') + (nd.pressure.length ? ' · ' + nd.pressure.join(', ') : ''),
          !nd.ready ? 'bad' : nd.pressure.length || !nd.schedulable ? 'warn' : 'ok');
        kv(box, [['Roles', nd.roles.join(', ')], ['Version', nd.version], ['Address', nd.ip], ['Age', nd.age],
          ['Pods', nd.pods + (nd.pods_cap ? ' of ' + nd.pods_cap + ' allowed' : '')],
          ['CPU', nd.cpu_pct == null ? fmtCpu(nd.cpu_cap) : nd.cpu_pct + '% of ' + fmtCpu(nd.cpu_cap)],
          ['Memory', nd.mem_pct == null ? fmtMem(nd.mem_cap) : nd.mem_pct + '% of ' + fmtMem(nd.mem_cap)]]);
      } else state(pl.count + ' pod' + (pl.count === 1 ? '' : 's') + (pl.bad ? ' · ' + pl.bad + ' failing' : ''), pl.bad ? 'bad' : 'ok');
      section(box, 'Pods that need somebody', pl.pods.filter(function (p) { return p.tone === 'bad' || p.tone === 'warn'; })
        .map(function (p) { return ['pod:' + p.id, p.name, p.problem || p.phase]; }), 'svc');
      if (nd) { var na = el('div', 'c3d-acts'), nl = el('a', '', 'In the machine table'); nl.href = base + '&tab=nodes'; na.appendChild(nl); box.appendChild(na); }
    } else { box.hidden = true; return; }
    box.hidden = false; box.scrollTop = 0;
  }

  function where(key) {
    if (!key.indexOf('plat:')) {
      var pl = lay.plats.filter(function (p) { return p.key === key.slice(5); })[0];
      return pl ? { x: pl.x + pl.w / 2, y: 0, z: pl.z + pl.d / 2, far: Math.max(pl.w, pl.d) * 1.5 + 6 } : null;
    }
    var it = items[key]; return it ? { x: it.gx, y: it.gy, z: it.gz, far: 16 } : null;
  }
  function fly(key, close) {
    var p = where(key); if (!p) return;
    if (walk) {      // in the world you do not fly the camera to a thing: you are put down beside it
      walk.x = p.x + 1.15; walk.z = p.z + 1.15; walk.y = walk.was = p.y > 1.5 ? p.y - 0.6 : p.y < -1 ? p.y - 0.3 : 0;
      return;
    }
    goal.tx = p.x; goal.ty = p.y; goal.tz = p.z; goal.dist = close ? Math.min(p.far, 7.5) : Math.min(p.far, fit);
  }
  function select(key, go) {
    selKey = key || ''; selRel = selKey && lay ? related(selKey, ix, lay.plats) : null;
    if (data) card();
    if (go && selKey) fly(selKey, false);
  }
  function onlyTone(tone) {
    toneOnly = toneOnly === tone ? '' : tone; hud();
    if (!toneOnly) return;
    var first = (data.pods || []).filter(function (p) { return p.tone === tone; })[0];
    if (first) select('pod:' + first.id, true);
  }
  function search(q) {
    q = (q || '').trim().toLowerCase(); found = null; $('c3dFound').textContent = '';
    if (!q || !data) return;
    found = {}; var n = 0, first = '';
    Object.keys(ix.ref).forEach(function (k) {
      var r = ix.ref[k];
      if ((r.name || '').toLowerCase().indexOf(q) >= 0 || (r.hosts || []).join(' ').toLowerCase().indexOf(q) >= 0) { found[k] = 1; n++; first = first || k; }
    });
    lay.plats.forEach(function (pl) { if (pl.key.toLowerCase().indexOf(q) >= 0) { found['plat:' + pl.key] = 1; n++; first = first || 'plat:' + pl.key; } });
    found._first = first; $('c3dFound').textContent = n + ' found';
  }
  function tour(on) {
    touring = on; $('c3dTour').className = 'c3d-btn' + (on ? ' on' : ''); $('c3dTour').setAttribute('aria-pressed', on ? 'true' : 'false');
    stage.classList.toggle('cine', on);
    if (!on || !data) { if (data) caption(''); return; }
    tourList = data.pods.filter(function (p) { return p.tone === 'bad'; }).concat(data.pods.filter(function (p) { return p.tone === 'warn'; }))
      .map(function (p) { return 'pod:' + p.id; });
    // nothing wrong: a tour of the machines is still a tour
    if (!tourList.length) tourList = lay.plats.map(function (pl) { return 'plat:' + pl.key; });
    tourI = -1; tourAt = 0;
  }

  /* ── drawing ─────────────────────────────────────────────────────── */
  function dimmed(it) {
    if (walk) return false;
    var r = it.ref || {};
    if (toneOnly && r.tone !== toneOnly) return true;
    if (focusNs && r.ns !== focusNs) return true;
    if (found && !found[it.key]) return true;
    return !!(selRel && !selRel[it.key]);
  }
  // Names are the one thing still drawn in 2D, on a clear sheet over the
  // picture: text wants to stay sharp and upright whatever the camera does.
  var placed = [];
  function tag(x, y, text, strong, alpha, must) {
    g.font = (strong ? '700 ' : '500 ') + '11.5px ' + FONT;
    var w = g.measureText(text).width + 14, x0 = x - w / 2, i, q;
    for (i = 0; i < placed.length && !must; i++) {
      q = placed[i];
      if (x0 < q[2] && x0 + w > q[0] && y < q[3] && y + 18 > q[1]) return false;
    }
    placed.push([x0 - 3, y - 2, x0 + w + 3, y + 20]);
    g.globalAlpha = alpha * 0.72; g.fillStyle = 'rgb(6,10,24)';
    g.beginPath();
    if (g.roundRect) g.roundRect(x0, y, w, 18, 9); else g.rect(x0, y, w, 18);
    g.fill();
    g.globalAlpha = alpha; g.fillStyle = strong ? '#ffffff' : '#d5deff';
    g.textAlign = 'center'; g.textBaseline = 'middle'; g.fillText(text, x, y + 9.5);
    return true;
  }

  /* Everything below fills flat arrays the GPU reads once a frame: one row per
     island, pod, mark, light and length of line. The shape of each row is in
     cluster3d-gl.js, beside the shader that reads it. */
  function unit(c) { return [c[0] / 255, c[1] / 255, c[2] / 255]; }
  var BODYF = {}, FAMF = {}, TONEF = {}, EDGEF = {}, kx;
  for (kx in BODY) BODYF[kx] = unit(rgb(BODY[kx]));
  for (kx in FAM) FAMF[kx] = unit(rgb(FAM[kx]));
  for (kx in TONE) TONEF[kx] = unit(TONE[kx]);
  for (kx in EDGE) EDGEF[kx] = unit(EDGE[kx]);
  var ISLE = [0.34, 0.5, 0.95], HOTC = [1.0, 0.55, 0.16], GOLD = [0.9, 0.64, 0.2], VIOLET = [0.52, 0.42, 0.95];
  var FAMI = { db: 0, queue: 1, cache: 2, storage: 3, workflow: 4, observability: 5, network: 6, security: 7, system: 8, delivery: 9 };
  var MOOD = { happy: 0, hot: 1, worried: 2, sleeping: 3, hatching: 4, leaving: 5, crying: 6, dizzy: 7, done: 8 };
  var MARKS = ['🌧️', '💫', '💤', '🔥', '✨', '🩹', '🌐', '🌍', '💾', '👑', '⛔', '🚧', '☁️', '👋', '🆘', '❗'];
  var M = {};
  var CAP = { box: 9000, ball: 2600, soft: 1400, orb: 7000, spr: 6000, glow: 14000, beam: 26000, sh: 4000 };
  var A = { boxes: new Float32Array(CAP.box * 14), balls: new Float32Array(CAP.ball * 14), softs: new Float32Array(CAP.soft * 14), orbs: new Float32Array(CAP.orb * 16), sprites: new Float32Array(CAP.spr * 8),
    glows: new Float32Array(CAP.glow * 8), beams: new Float32Array(CAP.beam * 16), shadows: new Float32Array(CAP.sh * 4),
    isles: new Float32Array(24 * 4), isleCols: new Float32Array(24 * 3) };
  var N = { box: 0, ball: 0, soft: 0, orb: 0, spr: 0, glow: 0, beam: 0, sh: 0 };
  /* A ride, as it is told to an engine that has a made model of each (a hall's): which ride, where it stands, how it leans,
     and a number that turns its wheels. Nine to a ride: x, y, z, yaw, tilt, size, pivot, which, turning. */
  var PROPS = new Float32Array(12 * 9), nProps = 0;
  /* A person, as told to the same engine: who, where, and how every joint stands. Eighteen to a person: x, y, z, yaw,
     tilt, size, which of the eight, then the joints (both legs, both knees, both arms, both elbows, both arms' lift,
     and the nod). The pose is worked out here as it always was; only the drawing of it is the engine's. */
  var FIGS = new Float32Array(48 * 18), nFigs = 0;
  var GRIDY = -9, wl = {}, nIsles = 0, moodNow = 0, pulseAt = -99, ptr = { x: 0, y: 0, at: 0, on: false };
  function hue3(h) {
    function f(n) { var k = (n + h / 30) % 12; return 0.62 - 0.285 * Math.max(-1, Math.min(k - 3, 9 - k, 1)); }
    return [f(0), f(8), f(4)];
  }
  function cube(x, y, z, sx, sy, sz, c, glow, yaw, rim, a, kind) {
    if (N.box >= CAP.box) return; var o = N.box++ * 14, d = A.boxes;
    d[o] = x; d[o + 1] = y; d[o + 2] = z; d[o + 3] = sx; d[o + 4] = sy; d[o + 5] = sz;
    d[o + 6] = c[0]; d[o + 7] = c[1]; d[o + 8] = c[2]; d[o + 9] = glow; d[o + 10] = yaw; d[o + 11] = rim; d[o + 12] = a; d[o + 13] = kind;
  }
  /* A figure that is not a pod is built of painted solids: boxes, balls and
     blocks with their edges rounded off. Each part is given where it sits in
     the figure's own frame (x to its side, y up from its feet, z the way it
     faces) and turns with the figure. A part may also lean (about its own x)
     and tip (about its own z), and the whole figure may lean or flip about its
     middle: that is all a walk, a throw or a backflip is. */
  var BOX = 0, BALL = 1, SOFT = 2;
  function solid(shape, x, y, z, sx, sy, sz, c, glow, yaw, lean, tip) {
    var d, o;
    if (shape === BALL) { if (N.ball >= CAP.ball) return; d = A.balls; o = N.ball++ * 14; }
    else if (shape === SOFT) { if (N.soft >= CAP.soft) return; d = A.softs; o = N.soft++ * 14; }
    else { if (N.box >= CAP.box) return; d = A.boxes; o = N.box++ * 14; }
    d[o] = x; d[o + 1] = y; d[o + 2] = z; d[o + 3] = sx; d[o + 4] = sy; d[o + 5] = sz;
    d[o + 6] = c[0]; d[o + 7] = c[1]; d[o + 8] = c[2]; d[o + 9] = glow; d[o + 10] = yaw; d[o + 11] = lean; d[o + 12] = tip; d[o + 13] = 5;
  }
  function part(f, ox, oy, oz, sx, sy, sz, c, glow, lean, tip, shape) {
    var p = lean || 0, y, k = f.k;
    if (f.tilt) { y = oy - f.piv; oy = f.piv + y * f.ct - oz * f.st; oz = y * f.st + oz * f.ct; p += f.tilt; }
    solid(shape || BOX, f.x + (ox * f.cs + oz * f.sn) * k, f.y + oy * k, f.z + (-ox * f.sn + oz * f.cs) * k, sx * k, sy * k, sz * k, c, glow || 0, f.yaw, p, tip || 0);
  }
  /* k is how big the figure is drawn; piv is the height it flips about */
  function stand(x, y, z, yaw, tilt, k, piv) {
    return { x: x, y: y, z: z, yaw: yaw, cs: Math.cos(yaw), sn: Math.sin(yaw), tilt: tilt || 0, ct: Math.cos(tilt || 0), st: Math.sin(tilt || 0), k: k || 1, piv: piv || 0.7 };
  }
  /* A limb hangs from a joint and swings about it, and bends half way down:
     an elbow, a knee. Every piece of it is given as how far down its half of
     the limb it sits and how far ahead of it, and is turned with that half.
     `ang` swings it forward, `out` lifts it away from the body, `bend` is the
     second joint. A piece is [down, ahead, sx, sy, sz, colour, glow, shape]. */
  function bone(f, px, py, pz, ang, out, list) {
    var c = Math.cos(ang), s = Math.sin(ang), cb = Math.cos(out), sb = Math.sin(out), i, q, y, z;
    for (i = 0; i < list.length; i++) {
      q = list[i]; y = -q[0] * c + q[1] * s; z = q[0] * s + q[1] * c;
      part(f, px - y * sb, py + y * cb, pz + z, q[2], q[3], q[4], q[5], q[6] || 0, -ang, out, q[7] || BOX);
    }
  }
  function limb(f, px, py, pz, ang, out, len, bend, upper, lower) {
    var y = -len * Math.cos(ang);
    bone(f, px, py, pz, ang, out, upper);
    bone(f, px - y * Math.sin(out), py + y * Math.cos(out), pz + len * Math.sin(ang), ang + bend, out, lower);
  }
  function ease(x) { x = clamp(x, 0, 1); return x * x * (3 - 2 * x); }

  /* You: a person, because you are one, and one of the people who really keep
     a cluster running. Who exactly is your choice on the way in (the walk
     opens on a line-up), with what you ride and what you carry. All of it is
     costume and nothing more: no role, ride or weapon can do anything the
     walk could not already do, and each choice is kept in this browser only. */
  var INKC = [0.05, 0.04, 0.05], WHITE = [0.93, 0.94, 0.96], STEEL = [0.56, 0.6, 0.68], TYRE = [0.07, 0.07, 0.09], LAMP = [1.0, 0.86, 0.45], REDC = [0.82, 0.14, 0.16];
  var WOOD = [0.55, 0.36, 0.2], JEANS = [0.13, 0.2, 0.36], NAVY = [0.08, 0.1, 0.2], GREEN = [0.2, 0.85, 0.5], HIVIS = [0.95, 0.72, 0.08];
  var KFIG = 0.74;      // how tall a person stands beside a pod
  var HEROES = [
    { name: 'DevOps', line: 'It works on my cluster.', kit: 'devops', skin: [0.86, 0.66, 0.52], hair: [0.2, 0.13, 0.08], top: [0.1, 0.42, 0.46], arm: [0.1, 0.42, 0.46], legs: JEANS, shoes: WHITE },
    { name: 'DevSecOps', line: 'Trusts nobody. Especially you.', kit: 'sec', skin: [0.72, 0.52, 0.4], hair: [0.05, 0.05, 0.06], top: [0.07, 0.08, 0.1], arm: [0.07, 0.08, 0.1], legs: [0.12, 0.13, 0.15], shoes: TYRE },
    { name: 'NOC', line: 'Has seen things at 3 a.m.', kit: 'noc', skin: [0.9, 0.72, 0.6], hair: [0.36, 0.2, 0.1], top: [0.13, 0.33, 0.7], arm: null, legs: [0.16, 0.17, 0.22], shoes: [0.2, 0.2, 0.24] },
    { name: 'Network engineer', line: 'It is never DNS. It was DNS.', kit: 'net', skin: [0.56, 0.38, 0.28], hair: [0.06, 0.05, 0.05], top: HIVIS, arm: [0.2, 0.22, 0.3], legs: [0.2, 0.22, 0.3], shoes: [0.3, 0.2, 0.12] },
    { name: 'CEO', line: 'Can we have it by Friday?', kit: 'ceo', skin: [0.88, 0.7, 0.58], hair: [0.62, 0.62, 0.66], top: NAVY, arm: NAVY, legs: NAVY, shoes: TYRE },
    { name: 'Project manager', line: 'Just a quick sync.', kit: 'pm', skin: [0.78, 0.56, 0.44], hair: [0.3, 0.14, 0.1], top: [0.62, 0.78, 0.92], arm: [0.62, 0.78, 0.92], legs: [0.16, 0.16, 0.2], shoes: [0.3, 0.16, 0.12] },
    { name: 'QA', line: 'Works as designed? Prove it.', kit: 'qa', skin: [0.92, 0.76, 0.62], hair: [0.75, 0.3, 0.14], top: [0.45, 0.24, 0.7], arm: null, legs: JEANS, shoes: [0.9, 0.3, 0.4] },
    { name: 'DBA', line: 'Who ran that query in production?', kit: 'dba', skin: [0.62, 0.44, 0.32], hair: [0.7, 0.7, 0.72], top: [0.42, 0.27, 0.18], arm: [0.42, 0.27, 0.18], legs: [0.3, 0.28, 0.24], shoes: [0.25, 0.15, 0.1] }
  ];
  /* speed is how many times walking pace; sit is how far the rider is lifted;
     pose 1 stands still on it, pose 2 sits and holds on */
  var RIDES = [
    { name: 'On foot', line: 'Free, healthy, slow.', speed: 1, pose: 0, sit: 0, dist: 4.6 },
    { name: 'Skateboard', line: 'Kickflips are not in the audit log.', speed: 1.5, pose: 1, sit: 0.12, dist: 4.8 },
    { name: 'Bicycle', line: 'Zero emissions, zero downtime.', speed: 1.9, pose: 2, sit: 0.3, dist: 5 },
    { name: 'Scooter', line: 'Beep beep.', speed: 2.4, pose: 2, sit: 0.16, dist: 5.2 },
    { name: 'Motorbike', line: 'For incidents that cannot wait.', speed: 3.1, pose: 2, sit: 0.24, dist: 5.6 },
    { name: 'Go-kart', line: 'The fastest way to a machine.', speed: 3.6, pose: 2, sit: -0.06, dist: 6 }
  ];
  /* Every weapon sends the SAME one action (delete this pod) through the same
     checks; `how` is only the way your character uses it. */
  var WEAPONS = [
    { name: 'Blaster', verb: 'was vaporised', how: 'bolt' },
    { name: 'Knife', verb: 'has been sliced', how: 'slash' },
    { name: 'Shoe', verb: 'took a shoe to the face', how: 'throw', c: [0.55, 0.3, 0.16], size: [0.14, 0.11, 0.3], shape: SOFT },
    { name: 'Hammer', verb: 'got flattened', how: 'drop' },
    { name: 'Frying pan', verb: 'heard a very loud CLANG', how: 'throw', c: [0.25, 0.26, 0.3], size: [0.38, 0.05, 0.38], shape: BALL },
    { name: 'Snowball', verb: 'is now a snowman', how: 'throw', c: [0.95, 0.97, 1.0], size: [0.2, 0.2, 0.2], shape: BALL }
  ];
  var me = { hero: 0, ride: 0, weapon: 0, mute: false }, picking = false, shot = null;
  try {      // storage can be missing or refuse; the walk works the same without it
    var kept = JSON.parse(localStorage.getItem('c3d.me') || '{}');
    [['hero', HEROES], ['ride', RIDES], ['weapon', WEAPONS]].forEach(function (k) { if (kept[k[0]] === (kept[k[0]] | 0) && kept[k[0]] >= 0 && kept[k[0]] < k[1].length) me[k[0]] = kept[k[0]]; });
    me.mute = kept.mute === true;
  } catch (e) { /* nothing kept */ }
  function keep() { try { localStorage.setItem('c3d.me', JSON.stringify(me)); } catch (e) { /* not kept */ } }
  /* What the right hand holds, laid along the forearm from the elbow so that
     it points where the arm points: a blaster aims, a hammer comes over. */
  var HELD = {
    Blaster: [[0.42, 0.05, 0.09, 0.3, 0.12, STEEL, 0, SOFT], [0.31, 0.1, 0.07, 0.1, 0.14, TYRE], [0.58, 0.05, 0.05, 0.05, 0.05, REDC, 0.9, BALL]],
    Knife: [[0.35, 0.03, 0.05, 0.12, 0.05, WOOD], [0.56, 0.03, 0.03, 0.32, 0.08, WHITE, 0.15]],
    Shoe: [[0.4, 0.06, 0.16, 0.13, 0.34, [0.55, 0.3, 0.16], 0, SOFT]],
    Hammer: [[0.6, 0.02, 0.06, 0.64, 0.06, WOOD], [0.95, 0.02, 0.42, 0.28, 0.3, STEEL, 0.05, SOFT]],
    'Frying pan': [[0.47, 0.02, 0.05, 0.32, 0.04, TYRE], [0.82, 0.02, 0.44, 0.44, 0.06, [0.25, 0.26, 0.3], 0, BALL]],
    Snowball: [[0.42, 0.04, 0.22, 0.22, 0.22, [0.95, 0.97, 1.0], 0.4, BALL]],
    Medkit: [[0.43, 0.05, 0.28, 0.22, 0.13, WHITE, 0, SOFT], [0.43, 0.12, 0.14, 0.04, 0.02, GREEN, 0.8], [0.43, 0.12, 0.04, 0.14, 0.02, GREEN, 0.8]]
  };
  /* What each role has in its other hand, from the elbow down. */
  var PROP = {
    devops: [[0.22, 0.1, 0.34, 0.24, 0.03, STEEL, 0, SOFT], [0.22, 0.118, 0.1, 0.1, 0.01, GREEN, 0.7, BALL]],                       // a laptop, and its sticker
    sec: [[0.4, 0.04, 0.12, 0.11, 0.06, LAMP, 0.15, SOFT], [0.33, 0.04, 0.08, 0.07, 0.025, STEEL]],                                  // a padlock
    noc: [[0.36, 0.07, 0.1, 0.13, 0.1, WHITE, 0, BALL], [0.3, 0.07, 0.1, 0.02, 0.1, [0.3, 0.18, 0.1], 0, BALL]],                       // coffee
    net: [[0.38, 0.05, 0.1, 0.18, 0.06, HIVIS, 0, SOFT], [0.33, 0.085, 0.06, 0.05, 0.01, GREEN, 0.9]],                                // a cable tester
    ceo: [[0.38, 0.05, 0.075, 0.15, 0.02, TYRE, 0, SOFT], [0.38, 0.062, 0.06, 0.12, 0.005, [0.5, 0.75, 1.0], 0.7]],                   // a phone
    pm: [[0.3, 0.1, 0.26, 0.34, 0.02, WOOD, 0, SOFT], [0.31, 0.113, 0.22, 0.27, 0.005, WHITE], [0.16, 0.115, 0.1, 0.04, 0.02, STEEL]], // a clipboard
    qa: [[0.4, 0.04, 0.03, 0.16, 0.03, WOOD], [0.58, 0.04, 0.22, 0.22, 0.03, STEEL, 0, BALL], [0.58, 0.045, 0.17, 0.17, 0.035, [0.6, 0.9, 1.0], 0.45, BALL]],      // a magnifying glass
    dba: [[0.35, 0.06, 0.11, 0.12, 0.11, [0.75, 0.3, 0.2], 0, BALL], [0.35, 0.12, 0.03, 0.07, 0.05, [0.75, 0.3, 0.2], 0, BALL]]       // a mug
  };
  var RELEASE = 0.42;      // how far through a throw the hand lets go
  /* How a thing is carried, as [arm, elbow]: a long one rests on the shoulder,
     because an arm hanging straight down would put a hammer through the floor. */
  var CARRY = { Hammer: [1.15, 1.65], 'Frying pan': [1.05, 1.55] }, EASY = [0.2, 0.55];
  /* The blow, as joint angles. `u` runs 0 to 1 and the blow lands at 1; past
     that the pose lets go. A bolt is aimed and kicks; a knife cuts twice; a
     hammer goes up over the head with a jump and comes down; anything thrown
     goes back over the shoulder and is let go. */
  function attack(J, how, u, from) {
    var v = Math.min(u, 1), back = 1 - ease((u - 1) / 0.35), a, e;
    if (how === 'bolt') {
      a = from[0] + (1.5 - from[0]) * ease(v / 0.45) + (v > 0.6 ? 0.4 * Math.max(0, 1 - (v - 0.6) / 0.22) : 0); e = from[1] * (1 - ease(v / 0.4)) + 0.05; J.tilt -= 0.05 * back;
    } else if (how === 'slash') {
      a = v < 0.1 ? from[0] + (2.4 - from[0]) * ease(v / 0.1) : v < 0.4 ? 2.4 - 1.9 * ease((v - 0.1) / 0.3) : v < 0.6 ? 0.5 + 1.9 * ease((v - 0.4) / 0.2) : 2.4 - 1.9 * ease((v - 0.6) / 0.35);
      e = 0.15 + 0.9 * clamp((a - 0.5) / 1.9, 0, 1);      // cocked at the top, straight through the cut
      J.outR = 0.3 * back; J.outL = -0.5 * back; J.tilt += 0.22 * back; J.legL = 0.5 * back; J.legR = -0.4 * back; J.kneeL = -0.5 * back;
    } else if (how === 'drop') {
      a = v < 0.55 ? from[0] + (2.95 - from[0]) * ease(v / 0.5) : 2.95 - 1.95 * ease((v - 0.55) / 0.42); e = v < 0.55 ? from[1] + (0.35 - from[1]) * ease(v / 0.5) : 0.35 - 0.25 * ease((v - 0.55) / 0.4);
      J.armL = a * back; J.elbL = e * back; J.hop += Math.sin(Math.min(1, v / 0.92) * PI) * 0.75 * back;
      J.tilt += (v < 0.55 ? -0.14 * ease(v / 0.5) : -0.14 + 0.46 * ease((v - 0.55) / 0.4)) * back; J.legL = J.legR = 0.35 * Math.sin(Math.min(1, v / 0.92) * PI) * back; J.kneeL = J.kneeR = -0.9 * Math.sin(Math.min(1, v / 0.92) * PI) * back;
    } else {      // back over the shoulder and away
      a = v < 0.32 ? from[0] + (3.3 - from[0]) * ease(v / 0.3) : 3.3 - 2.6 * ease((v - 0.32) / 0.2); e = v < 0.32 ? from[1] + (1.3 - from[1]) * ease(v / 0.3) : 1.3 - 1.2 * ease((v - 0.32) / 0.16);
      J.outL = -0.7 * back; J.legL = 0.4 * back; J.legR = -0.3 * back; J.kneeR = -0.3 * back;
      J.tilt += (v < 0.32 ? -0.14 * ease(v / 0.3) : -0.14 + 0.36 * ease((v - 0.32) / 0.2)) * back;
    }
    J.armR = a * back + (u > 1 ? from[0] * (1 - back) : 0); J.elbR = e * back + (u > 1 ? from[1] * (1 - back) : 0);      // and back to how it is carried
  }
  /* Each role's own move: what it does when it is chosen, and when it has
     won. `u` runs 0 to 1 through it. */
  function emote(J, i, u, t) {
    var s = Math.sin(u * PI), w = Math.sin(u * TAU), late = ease((u - 0.6) / 0.12);
    if (i === 0) {             // DevOps: opens the laptop, types fast, then a fist in the air: it deployed
      J.armL = 0.55; J.elbL = 1.25; J.armR = 0.6 + late * 2.3; J.elbR = (1.2 + Math.sin(t * 24) * 0.12) * (1 - late) + 0.2 * late; J.hop += late * Math.sin(clamp((u - 0.6) / 0.4, 0, 1) * PI) * 0.4; J.nod = 0.25 * (1 - late);
    } else if (i === 1) {      // DevSecOps: looks over each shoulder, then locks it down behind a shield
      J.spin = Math.sin(clamp(u / 0.55, 0, 1) * TAU) * 0.8 * (1 - late); J.armR = 2.1 * (1 - late) + 1.15 * late; J.elbR = 1.7 * (1 - late) + 1.5 * late; J.armL = 1.15 * late + 0.3; J.elbL = 1.5 * late + 0.9; J.shield = late * (1 - ease((u - 0.92) / 0.08));
    } else if (i === 2) {      // NOC: a hand to the headset, a nod, then both arms up: all green
      J.armR = 1.95 * (1 - late) + 2.95 * late; J.elbR = 2.2 * (1 - late) + 0.2 * late; J.armL = 0.4 + 2.55 * late; J.elbL = 0.9 * (1 - late) + 0.2 * late; J.nod = Math.max(0, Math.sin(u * TAU * 3)) * 0.25 * (1 - late); J.hop += late * Math.abs(Math.sin(u * TAU * 3)) * 0.15; J.ok = late;
    } else if (i === 3) {      // Network engineer: swings a loop of cable round over the head
      J.armR = 2.75 + Math.sin(u * TAU * 3) * 0.2; J.elbR = 0.35; J.outR = Math.cos(u * TAU * 3) * 0.35; J.sway = Math.sin(u * TAU * 3) * 0.05; J.loop = Math.min(1, u * 4) * (1 - ease((u - 0.9) / 0.1)); J.legL = 0.2; J.legR = -0.2;
    } else if (i === 4) {      // CEO: straightens the tie, then points at the future
      J.armR = 1.0 * (1 - late) + 1.55 * late; J.elbR = 2.0 * (1 - late) + 0.05 * late; J.tilt -= 0.1 * late; J.outL = -0.9 * late; J.armL = 0.3 + 0.5 * late; J.elbL = 0.9 - 0.6 * late; J.nod = -0.15 * late; J.hop += (1 - late) * Math.abs(Math.sin(u * TAU * 2.5)) * 0.03;
    } else if (i === 5) {      // Project manager: checks the watch, taps a foot, then a thumb up
      J.armR = 1.15 * (1 - late) + 1.3 * late; J.elbR = 1.75 * (1 - late) + 0.5 * late; J.outR = 0.95 * late; J.nod = 0.3 * (1 - late); J.legR = Math.max(0, Math.sin(u * TAU * 5)) * 0.25 * (1 - late); J.kneeR = -Math.max(0, Math.sin(u * TAU * 5)) * 0.4 * (1 - late); J.hop += late * s * 0.12;
    } else if (i === 6) {      // QA: bends to look through the glass, sweeps it, then jumps: found one
      J.tilt += 0.4 * (1 - late); J.armL = 1.45 * (1 - late) + 2.9 * late; J.elbL = 0.35; J.outL = -Math.sin(u * TAU * 2) * 0.35 * (1 - late); J.nod = 0.2 * (1 - late); J.armR = 0.4 + 2.5 * late; J.elbR = 0.6 - 0.4 * late;
      J.hop += late * Math.sin(clamp((u - 0.6) / 0.4, 0, 1) * PI) * 0.55; J.kneeL = J.kneeR = -late * Math.sin(clamp((u - 0.6) / 0.4, 0, 1) * PI) * 0.8; J.bug = late;
    } else {                   // DBA: a sip from the mug, then tables rise over an open hand
      J.armL = 0.95 * (1 - late) + 0.4 * late; J.elbL = 2.05 * (1 - late) + 0.9 * late; J.nod = -0.2 * (1 - late); J.armR = 0.3 + 1.0 * late; J.elbR = 0.6 + 0.5 * late; J.outR = 0.25 * late; J.discs = late * (1 - ease((u - 0.93) / 0.07));
    }
  }
  /* o: { hero, pose, step, moving, run, hold, ready, act: {how, name, u}, emote, eu } */
  function joints(o, t) {
    var J = { legL: 0, legR: 0, kneeL: 0, kneeR: 0, armL: 0.12, armR: 0.05, elbL: 1.15, elbR: 0.3, outL: 0, outR: 0, tilt: 0, hop: 0, spin: 0, sway: 0, nod: 0, hold: o.hold || '' }, p, k, c;
    if (o.pose === 2) {      // seated: knees up and feet down, hands on the bars
      J.legL = J.legR = 1.4; J.kneeL = J.kneeR = -1.25; J.armL = J.armR = 1.0; J.elbL = J.elbR = 0.35; J.noProp = 1; return J;
    }
    if (o.pose === 1) { J.outL = -0.55; J.outR = 0.55; J.armL = 0.1; J.elbL = J.elbR = 0.3; J.legL = 0.16; J.legR = -0.16; J.kneeL = J.kneeR = -0.25; J.noProp = 1; return J; }      // on a board, arms out
    if (o.moving && !calm) {
      p = o.step * 1.6; k = o.run ? 1 : 0.7;
      J.legL = Math.sin(p) * 0.75 * k; J.legR = -Math.sin(p) * 0.75 * k;
      J.kneeL = -(0.12 + Math.max(0, Math.cos(p)) * 1.0 * k); J.kneeR = -(0.12 + Math.max(0, -Math.cos(p)) * 1.0 * k);      // the knee folds as its leg comes through
      J.armR = -Math.sin(p) * 0.65 * k; J.elbR = o.run ? 1.3 : 0.5; J.armL = 0.12 + Math.sin(p) * 0.2 * k;
      J.hop = Math.abs(Math.sin(p)) * 0.05; J.tilt = o.run ? 0.16 : 0.05;
    } else if (!calm) { J.armR = 0.05 + Math.sin(t * 1.6 + o.hero) * 0.04; J.hop = Math.sin(t * 2.2 + o.hero) * 0.012; J.nod = Math.sin(t * 0.9 + o.hero * 2) * 0.04; }
    if (J.hold && !o.act) { c = CARRY[J.hold] || EASY; J.armR = c[0] + (o.ready ? 0.45 : 0) + (c === EASY ? J.armR * 0.3 : 0); J.elbR = c[1]; }      // what you carry: ahead of you, or on the shoulder; higher when you mean it
    if (o.act) attack(J, o.act.how, o.act.u, CARRY[o.act.name] || EASY);
    if (o.emote != null && !calm) emote(J, o.emote, o.eu, t);
    if (o.dance != null && !calm) groove(J, o.dance);
    return J;
  }
  /* A dance, as joint angles. `b` counts beats from the first; four are one
     figure, and the figures come round in turn: a side step with the arms
     swinging across, both hands up, a turn on the spot with the arms wide,
     and a hand to the sky, one and then the other. */
  function groove(J, b) {
    var bar = Math.floor(b / 4) % 4, s = Math.sin(b * PI), up = Math.abs(s), k = ease((s + 1) / 2);
    J.hop += up * 0.1; J.kneeL = J.kneeR = -0.22 - up * 0.3; J.nod = Math.sin(b * TAU) * 0.08; J.noProp = 1;
    if (bar === 0) {
      J.sway = s * 0.16; J.armL = 0.9 + s * 0.6; J.armR = 0.9 - s * 0.6; J.elbL = J.elbR = 1.3; J.legL = Math.max(0, s) * 0.3; J.legR = Math.max(0, -s) * 0.3;
    } else if (bar === 1) {
      J.armL = J.armR = 2.75 + Math.sin(b * TAU) * 0.2; J.elbL = J.elbR = 0.25 + up * 0.3; J.outL = -0.25; J.outR = 0.25; J.hop += up * 0.12;
    } else if (bar === 2) {
      J.spin = ease((b % 4) / 4) * TAU; J.outL = -1.15; J.outR = 1.15; J.armL = J.armR = 0.3; J.elbL = J.elbR = 0.2; J.legL = 0.15; J.legR = -0.15;
    } else {
      J.armR = 0.5 + 2.4 * k; J.armL = 2.9 - 2.4 * k; J.elbL = J.elbR = 0.2; J.outR = 0.35 * k; J.outL = -0.35 * (1 - k); J.tilt += s * 0.08; J.sway = s * 0.08;
    }
  }
  /* A person: a head with a face, a neck, a chest and waist, and four limbs
     that bend. Rounded throughout, and dressed for the job. */
  function person(x, y, z, yaw, t, o) {
    var L = HEROES[o.hero], J = joints(o, t), ya = yaw + J.spin, f = stand(x + J.sway * Math.cos(ya), y + J.hop, z - J.sway * Math.sin(ya), ya, J.tilt, KFIG, 1.0), side, k, a;
    var fore = L.arm || L.skin, thigh = [[0.2, 0, 0.2, 0.47, 0.22, L.legs, 0, BALL]], shin = [[0.2, 0, 0.165, 0.45, 0.185, L.legs, 0, BALL], [0.41, 0.055, 0.14, 0.1, 0.29, L.shoes, L.shoes === WHITE ? 0.12 : 0, SOFT]];
    var upper = [[0, 0, 0.19, 0.19, 0.19, L.arm || L.top, 0, BALL], [0.15, 0, 0.155, 0.37, 0.165, L.arm || L.top, 0, BALL]], lower = [[0.14, 0, 0.135, 0.33, 0.145, fore, 0, BALL], [0.31, 0, 0.115, 0.125, 0.115, L.skin, 0, BALL]];
    if (HALL) {
      // The engine draws the body. What is in each hand is still hung from this arithmetic (a limb with nothing on it
      // but the thing held), so it sits in the hand the engine draws: its figure has these joints, at these lengths.
      if (nFigs < 48) { FIGS.set([f.x, f.y, f.z, ya, J.tilt, f.k, o.hero, J.legL, J.legR, J.kneeL, J.kneeR, J.armL, J.armR, J.elbL, J.elbR, J.outL, J.outR, J.nod], nFigs * 18); nFigs++; }
      if (!(J.noProp || o.act)) limb(f, -0.27, 1.42, 0, J.armL, J.outL, 0.3, J.elbL, [], PROP[L.kit]);
      if (J.hold && HELD[J.hold]) limb(f, 0.27, 1.42, 0, J.armR, J.outR, 0.3, J.elbR, [], HELD[J.hold]);
    } else {
    limb(f, -0.1, 0.86, 0, J.legL, 0, 0.4, J.kneeL, thigh, shin); limb(f, 0.1, 0.86, 0, J.legR, 0, 0.4, J.kneeR, thigh, shin);
    limb(f, -0.27, 1.42, 0, J.armL, J.outL, 0.3, J.elbL, upper, J.noProp || o.act ? lower : lower.concat(PROP[L.kit]));
    limb(f, 0.27, 1.42, 0, J.armR, J.outR, 0.3, J.elbR, upper, J.hold && HELD[J.hold] ? lower.concat(HELD[J.hold]) : lower);
    part(f, 0, 0.9, 0, 0.36, 0.22, 0.25, L.legs, 0, 0, 0, SOFT);                                   // hips
    part(f, 0, 1.09, 0, 0.36, 0.3, 0.25, L.top, 0, 0, 0, SOFT);                                    // waist
    part(f, 0, 1.3, 0, 0.45, 0.36, 0.29, L.top, 0, 0, 0, SOFT);                                    // chest
    part(f, 0, 1.5, 0, 0.13, 0.14, 0.13, L.skin, 0, 0, 0, BALL);                                   // neck
    dress(f, L, t, J);
    head(stand(f.x, f.y, f.z, ya, J.tilt + J.nod, KFIG, J.nod ? 1.5 : 1.0), L, J);
    }
    // what a move adds
    if (J.shield) { part(f, 0, 1.22, 0.4, 0.5 * J.shield, 0.6 * J.shield, 0.05, [0.06, 0.4, 0.22], 0.06, 0, 0, SOFT); part(f, 0, 1.22, 0.432, 0.4 * J.shield, 0.5 * J.shield, 0.02, [0.1, 0.62, 0.34], 0.1, 0, 0, SOFT); part(f, 0, 1.24, 0.45, 0.12 * J.shield, 0.16 * J.shield, 0.02, WHITE, 0.15, 0, 0, SOFT); }
    if (J.ok) for (k = 0; k < 5; k++) solid(BALL, x + (k - 2) * 0.24 * f.cs, y + J.hop + 1.62 + Math.sin(t * 5 + k) * 0.05, z - (k - 2) * 0.24 * f.sn, 0.09 * J.ok, 0.09 * J.ok, 0.09 * J.ok, TONEF.ok, 0.5, 0, 0, 0);      // five green lights
    if (J.loop) for (k = 0; k < 12; k++) { a = t * 7 + k * TAU / 12; solid(BALL, x + Math.cos(a) * 0.7 * J.loop, y + J.hop + 1.72 + Math.sin(a * 2) * 0.05, z + Math.sin(a) * 0.7 * J.loop, 0.07, 0.07, 0.07, [0.2, 0.5, 1.0], 0.6, 0, 0, 0); }
    if (J.bug) { solid(BALL, x + f.sn * 0.55, y + J.hop + 1.5 + J.bug * 0.25, z + f.cs * 0.55, 0.13, 0.1, 0.16, REDC, 0.5, ya, 0, 0); glo(x + f.sn * 0.55, y + J.hop + 1.75, z + f.cs * 0.55, 0.6, REDC, 1.4 * J.bug); }
    if (J.discs) for (k = 0; k < 3; k++) solid(BALL, x + (0.27 * f.cs + 0.42 * f.sn) * KFIG, y + J.hop + (1.25 + k * 0.13 * J.discs) * KFIG + 0.12, z + (-0.27 * f.sn + 0.42 * f.cs) * KFIG, 0.26 * J.discs, 0.07, 0.26 * J.discs, PATH, 0.7, t * 1.5, 0, 0);
  }
  /* The head: it nods on the neck, so it stands in its own frame. A face is
     what makes a figure somebody: eyes with a light in them, brows, a nose, a
     mouth and ears, then hair and whatever the job puts on a head. */
  function head(f, L, J) {
    var side, kit = L.kit, h = L.hair;
    part(f, 0, 1.7, 0, 0.34, 0.39, 0.36, L.skin, 0, 0, 0, BALL);
    for (side = -1; side <= 1; side += 2) {
      part(f, side * 0.078, 1.72, 0.152, 0.055, 0.08, 0.05, INKC, 0, 0, 0, BALL);                  // an eye
      part(f, side * 0.088, 1.742, 0.176, 0.02, 0.02, 0.012, WHITE, 0.8, 0, 0, BALL);              // the light in it
      part(f, side * 0.078, 1.795, 0.158, 0.075, 0.016, 0.02, kit === 'ceo' || kit === 'dba' ? [0.45, 0.45, 0.48] : h, 0, 0, -side * 0.12);      // a brow
      part(f, side * 0.172, 1.7, 0, 0.05, 0.1, 0.075, L.skin, 0, 0, 0, BALL);                      // an ear
    }
    part(f, 0, 1.665, 0.182, 0.05, 0.06, 0.055, [L.skin[0] * 0.92, L.skin[1] * 0.88, L.skin[2] * 0.86], 0, 0, 0, BALL);      // the nose
    part(f, 0, 1.598, 0.158, 0.1, 0.022, 0.03, [0.42, 0.15, 0.15], 0, 0, 0, SOFT);                 // the mouth
    // hair, by who it is
    if (kit === 'sec') {      // the hood is up
      part(f, 0, 1.72, -0.035, 0.43, 0.47, 0.42, L.top, 0, 0, 0, BALL); part(f, 0, 1.52, -0.1, 0.4, 0.2, 0.26, L.top, 0, 0, 0, SOFT);
    } else if (kit === 'dba') {      // bald on top, grey at the sides, and a beard
      for (side = -1; side <= 1; side += 2) part(f, side * 0.15, 1.72, -0.05, 0.08, 0.2, 0.26, h, 0, 0, 0, BALL);
      part(f, 0, 1.69, -0.15, 0.3, 0.26, 0.1, h, 0, 0, 0, BALL);
      part(f, 0, 1.565, 0.1, 0.28, 0.2, 0.2, h, 0, 0, 0, BALL); part(f, 0, 1.625, 0.172, 0.14, 0.03, 0.03, h, 0, 0, 0, SOFT);
    } else {
      part(f, 0, 1.815, -0.025, 0.365, 0.2, 0.37, h, 0, 0, 0, BALL); part(f, 0, 1.72, -0.13, 0.35, 0.3, 0.14, h, 0, 0, 0, BALL);      // a cap of hair, and the back of it
      if (kit === 'devops') { part(f, 0.07, 1.9, 0.05, 0.16, 0.1, 0.16, h, 0, 0, 0, BALL); part(f, -0.09, 1.89, 0.0, 0.15, 0.1, 0.16, h, 0, 0, 0, BALL); part(f, 0, 1.585, 0.12, 0.26, 0.11, 0.14, [h[0] * 1.2, h[1] * 1.2, h[2] * 1.2], 0, 0, 0, BALL); }      // unruly, and a short beard
      else if (kit === 'ceo') part(f, 0, 1.855, 0.06, 0.34, 0.1, 0.24, h, 0, -0.25, 0, BALL);      // swept back
      else if (kit === 'pm') { part(f, 0, 1.9, -0.13, 0.17, 0.17, 0.17, h, 0, 0, 0, BALL); part(f, 0, 1.84, 0.1, 0.33, 0.09, 0.14, h, 0, 0, 0, BALL); }      // a bun, and a fringe
      else if (kit === 'qa') { for (side = -1; side <= 1; side += 2) part(f, side * 0.165, 1.66, -0.02, 0.09, 0.32, 0.3, h, 0, 0, 0, BALL); part(f, 0, 1.845, 0.11, 0.34, 0.09, 0.13, h, 0, 0, 0, BALL); }      // a bob
      else if (kit === 'net') { part(f, 0, 1.85, 0, 0.385, 0.17, 0.39, [0.14, 0.2, 0.42], 0, 0, 0, BALL); part(f, 0, 1.815, 0.2, 0.3, 0.035, 0.2, [0.14, 0.2, 0.42], 0, 0, 0, SOFT); part(f, 0, 1.87, 0.17, 0.09, 0.07, 0.02, WHITE); }      // a cap with a peak
      else if (kit === 'noc') part(f, 0.05, 1.87, 0.08, 0.26, 0.09, 0.16, h, 0, 0, 0.2, BALL);      // a side parting
    }
    // what the job puts on a head
    if (kit === 'sec' || kit === 'qa' || kit === 'dba') {      // glasses
      for (side = -1; side <= 1; side += 2) { part(f, side * 0.078, 1.72, 0.188, 0.105, 0.085, 0.012, kit === 'sec' ? GREEN : INKC, kit === 'sec' ? 0.35 : 0, 0, 0, kit === 'qa' ? BALL : SOFT); part(f, side * 0.078, 1.72, 0.192, 0.08, 0.06, 0.012, kit === 'sec' ? [0.1, 0.3, 0.2] : [0.75, 0.85, 0.95], kit === 'sec' ? 0.5 : 0.12, 0, 0, kit === 'qa' ? BALL : SOFT); }
      part(f, 0, 1.725, 0.19, 0.06, 0.014, 0.012, INKC);
    }
    if (kit === 'noc') {      // a headset, and its microphone
      part(f, 0, 1.895, 0, 0.37, 0.035, 0.06, TYRE, 0, 0, 0, SOFT);
      for (side = -1; side <= 1; side += 2) part(f, side * 0.19, 1.71, 0, 0.06, 0.14, 0.13, TYRE, 0, 0, 0, BALL);
      part(f, 0.16, 1.63, 0.11, 0.02, 0.02, 0.2, TYRE, 0, -0.5, 0); part(f, 0.11, 1.585, 0.19, 0.05, 0.04, 0.04, TYRE, 0, 0, 0, BALL);
    }
  }
  /* What each role wears over the plain body. */
  function dress(f, L, t, J) {
    var kit = L.kit, side, k;
    if (kit === 'devops') {
      part(f, 0, 1.47, -0.1, 0.36, 0.14, 0.2, L.top, 0, 0, 0, SOFT);                                 // the hood, down
      part(f, 0, 1.18, 0.135, 0.26, 0.12, 0.03, [L.top[0] * 0.8, L.top[1] * 0.8, L.top[2] * 0.8], 0, 0, 0, SOFT);      // its pocket
      for (side = -1; side <= 1; side += 2) { part(f, side * 0.05, 1.36, 0.15, 0.015, 0.16, 0.015, WHITE, 0.3); part(f, side * 0.13, 1.5, 0.02, 0.09, 0.1, 0.11, TYRE, 0, 0, 0, BALL); }      // drawstrings, and headphones round the neck
      part(f, 0, 1.5, -0.1, 0.28, 0.035, 0.04, TYRE, 0, 0, 0, SOFT);
    } else if (kit === 'sec') {
      part(f, 0.11, 1.33, 0.148, 0.11, 0.13, 0.02, GREEN, 0.55, 0, 0, SOFT); part(f, 0.11, 1.335, 0.16, 0.05, 0.06, 0.01, [0.03, 0.12, 0.07]);      // a shield on the chest
      for (side = -1; side <= 1; side += 2) part(f, side * 0.13, 0.82, 0.12, 0.1, 0.12, 0.05, [0.1, 0.11, 0.13], 0, 0, 0, SOFT);       // pockets
    } else if (kit === 'noc') {
      part(f, 0, 1.47, 0.02, 0.22, 0.05, 0.22, WHITE, 0, 0, 0, SOFT);                                 // the collar
      part(f, 0, 1.3, 0.15, 0.012, 0.3, 0.012, REDC); part(f, 0, 1.13, 0.155, 0.1, 0.13, 0.012, WHITE); part(f, 0, 1.15, 0.163, 0.06, 0.04, 0.005, L.top);      // a lanyard and its badge
    } else if (kit === 'net') {
      for (k = 0; k < 2; k++) part(f, 0, 1.14 + k * 0.17, 0, 0.47, 0.035, 0.305, WHITE, 0.25, 0, 0, SOFT);      // the stripes that shine
      part(f, 0, 1.3, 0.15, 0.1, 0.36, 0.01, [0.2, 0.22, 0.3]);                                      // the vest is open
      part(f, 0, 0.96, 0, 0.39, 0.06, 0.27, WOOD, 0, 0, 0, SOFT); part(f, 0.15, 0.9, 0.1, 0.1, 0.13, 0.06, WOOD, 0, 0, 0, SOFT);       // a belt and its pouch
      for (k = 0; k < 10; k++) part(f, -0.3 + Math.cos(k * TAU / 10) * 0.015, 1.36 + Math.sin(k * TAU / 10) * 0.13, Math.cos(k * TAU / 10) * 0.13, 0.05, 0.05, 0.05, [0.15, 0.4, 0.95], 0.15, 0, 0, BALL);      // a coil of cable on the shoulder
    } else if (kit === 'ceo') {
      part(f, 0, 1.33, 0.146, 0.13, 0.3, 0.012, WHITE); part(f, 0, 1.31, 0.156, 0.045, 0.27, 0.012, REDC); part(f, 0, 1.455, 0.15, 0.06, 0.05, 0.02, REDC, 0, 0, 0, SOFT);      // shirt, tie and its knot
      for (side = -1; side <= 1; side += 2) part(f, side * 0.095, 1.34, 0.152, 0.07, 0.26, 0.012, [0.11, 0.14, 0.27], 0, 0, -side * 0.28);      // lapels
      part(f, -0.14, 1.36, 0.152, 0.06, 0.03, 0.01, WHITE);                                          // a pocket square
    } else if (kit === 'pm') {
      part(f, 0, 1.47, 0.02, 0.22, 0.05, 0.22, WHITE, 0, 0, 0, SOFT);
      part(f, 0, 1.3, 0.15, 0.012, 0.3, 0.012, [0.2, 0.6, 0.4]); part(f, 0, 1.13, 0.155, 0.1, 0.13, 0.012, WHITE);                   // a lanyard and its badge
      part(f, 0.27, 1.2, 0.02, 0.07, 0.035, 0.16, TYRE, 0, 0, 0, SOFT);                               // a watch... worn high, where it can be seen
    } else if (kit === 'qa') {
      part(f, 0, 1.32, 0.148, 0.13, 0.1, 0.03, GREEN, 0.35, 0, 0, BALL);                              // a bug on the shirt
      for (side = -1; side <= 1; side += 2) for (k = -1; k <= 1; k++) part(f, side * 0.08, 1.32 + k * 0.03, 0.15, 0.05, 0.01, 0.01, INKC, 0, 0, side * (0.3 + k * 0.3));
    } else {
      part(f, 0, 1.3, 0.148, 0.16, 0.36, 0.012, [0.9, 0.86, 0.74]);                                   // the shirt under the cardigan
      for (k = 0; k < 3; k++) part(f, 0.1, 1.38 - k * 0.11, 0.156, 0.03, 0.03, 0.012, WOOD, 0, 0, 0, BALL);                         // its buttons
      for (k = 0; k < 3; k++) part(f, -0.12, 1.36 - k * 0.035, 0.155, 0.1, 0.022, 0.012, PATH, 0.5, 0, 0, BALL);                    // a database on the pocket
    }
  }
  /* What you ride, built of the same boxes, in the rider's own frame. */
  function rideDraw(f, i, t, moving) {
    var side, c, k;
    if (HALL) {      // the engine draws its own model of this ride; only its lamp and its streak are left to draw here
      if (nProps < 12) { PROPS.set([f.x, f.y, f.z, f.yaw, f.tilt, f.k, f.piv, i, moving && !calm ? t : 0], nProps * 9); nProps++; }
    } else if (i === 1) {
      part(f, 0, 0.1, 0, 0.24, 0.04, 0.8, [0.75, 0.5, 0.25]);
      for (side = -1; side <= 1; side += 2) for (k = -1; k <= 1; k += 2) part(f, side * 0.1, 0.04, k * 0.28, 0.06, 0.07, 0.1, TYRE);
    } else if (i === 2) {
      part(f, 0, 0.22, 0.44, 0.05, 0.44, 0.44, TYRE); part(f, 0, 0.22, -0.44, 0.05, 0.44, 0.44, TYRE);
      part(f, 0, 0.22, 0.44, 0.07, 0.1, 0.1, STEEL); part(f, 0, 0.22, -0.44, 0.07, 0.1, 0.1, STEEL);
      part(f, 0, 0.42, 0, 0.05, 0.06, 0.84, REDC); part(f, 0, 0.5, -0.08, 0.05, 0.2, 0.05, REDC); part(f, 0, 0.6, -0.08, 0.16, 0.05, 0.24, TYRE);
      part(f, 0, 0.56, 0.4, 0.05, 0.42, 0.05, STEEL); part(f, 0, 0.78, 0.4, 0.42, 0.04, 0.04, TYRE);
    } else if (i === 3) {
      c = [0.16, 0.7, 0.66];
      part(f, 0, 0.14, 0.5, 0.08, 0.28, 0.28, TYRE); part(f, 0, 0.14, -0.42, 0.08, 0.28, 0.28, TYRE);
      part(f, 0, 0.28, -0.14, 0.3, 0.22, 0.66, c); part(f, 0, 0.16, 0.22, 0.26, 0.05, 0.4, STEEL); part(f, 0, 0.44, -0.12, 0.26, 0.08, 0.44, TYRE);
      part(f, 0, 0.5, 0.44, 0.3, 0.5, 0.06, c); part(f, 0, 0.8, 0.42, 0.44, 0.04, 0.04, TYRE); part(f, 0, 0.62, 0.48, 0.1, 0.1, 0.03, LAMP, 1);
    } else if (i === 4) {
      part(f, 0, 0.24, 0.64, 0.1, 0.48, 0.48, TYRE); part(f, 0, 0.24, -0.58, 0.12, 0.48, 0.48, TYRE);
      part(f, 0, 0.3, 0.02, 0.24, 0.22, 0.44, STEEL); part(f, 0, 0.5, 0.32, 0.26, 0.2, 0.44, REDC); part(f, 0, 0.52, -0.2, 0.24, 0.08, 0.5, TYRE);
      part(f, 0, 0.5, 0.56, 0.06, 0.52, 0.06, STEEL); part(f, 0, 0.8, 0.5, 0.5, 0.04, 0.04, TYRE); part(f, 0, 0.66, 0.62, 0.12, 0.12, 0.04, LAMP, 1);
      part(f, 0.17, 0.26, -0.5, 0.07, 0.07, 0.42, STEEL); part(f, 0, 0.5, -0.5, 0.12, 0.06, 0.03, REDC, 0.9);
    } else if (i === 5) {
      c = [0.95, 0.72, 0.1];
      for (side = -1; side <= 1; side += 2) {
        for (k = -1; k <= 1; k += 2) part(f, side * 0.47, 0.14, k * 0.52, 0.14, 0.28, 0.28, TYRE);
        part(f, side * 0.36, 0.26, -0.1, 0.12, 0.16, 0.7, REDC); part(f, side * 0.18, 0.27, 0.8, 0.1, 0.07, 0.03, LAMP, 1);
        part(f, side * 0.2, 0.3, -0.76, 0.1, 0.06, 0.03, REDC, 0.9);
      }
      part(f, 0, 0.16, 0, 0.8, 0.1, 1.5, c); part(f, 0, 0.24, 0.6, 0.5, 0.12, 0.4, c); part(f, 0, 0.48, -0.38, 0.44, 0.5, 0.08, TYRE);
      part(f, 0, 0.5, 0.34, 0.26, 0.05, 0.05, TYRE); part(f, 0, 0.38, 0.38, 0.04, 0.2, 0.04, STEEL); part(f, 0, 0.6, -0.72, 0.84, 0.05, 0.2, REDC);
    }
    if (i > 2 && !calm) glo(f.x + f.sn * 1.4, f.y + 0.4, f.z + f.cs * 1.4, 1.3, LAMP, 0.5);       // its lamp lights the way
    if (moving && i > 1 && !calm) for (k = 0; k < 3; k++) {      // and it leaves a streak when it goes
      c = (t * 4 + k / 3) % 1;
      glo(f.x - f.sn * (0.8 + c * 1.6), f.y + 0.2, f.z - f.cs * (0.8 + c * 1.6), 0.5 * (1 - c), i > 3 ? HOTC : PATH, 0.8 * (1 - c));
    }
  }
  /* Claude, as the doctor: the orange block creature of Claude Code, with two
     tall eyes, an arm each side and four short legs. It is this view's own
     model of that look, made of the same boxes as everything else here. */
  var CLAUDEC = [0.86, 0.46, 0.33];
  /* Claude as the doctor: Claude Code's orange block creature, as it has always
     been drawn here. It was swapped for a starburst on 22 November 2026 and the
     user asked for this one back the same day: tests/test_scene.py holds it. */
  function claude(x, y, z, yaw, t, sad, going) {
    var f = stand(x, y + (calm ? 0 : Math.sin(t * 2.4) * 0.025), z, yaw), blink = !calm && (t * 0.31) % 1 > 0.965, i, up;
    for (i = 0; i < 4; i++) {
      up = going && !calm ? Math.max(0, Math.sin(t * 11 + i * PI)) * 0.07 : 0;
      part(f, -0.3 + i * 0.2, 0.1 + up, 0, 0.1, 0.2, 0.34, CLAUDEC);
    }
    part(f, 0, 0.5, 0, 0.9, 0.6, 0.6, CLAUDEC);
    part(f, -0.5, 0.47, 0, 0.12, 0.15, 0.3, CLAUDEC); part(f, 0.5, 0.47, 0, 0.12, 0.15, 0.3, CLAUDEC);
    // its eyes are tall; they shut for a blink and go flat when it could not heal somebody
    part(f, -0.17, sad ? 0.52 : 0.58, 0.305, sad ? 0.14 : 0.075, blink || sad ? 0.03 : 0.2, 0.02, INKC);
    part(f, 0.17, sad ? 0.52 : 0.58, 0.305, sad ? 0.14 : 0.075, blink || sad ? 0.03 : 0.2, 0.02, INKC);
  }
  function orb(x, y, z, rad, c, a, yaw, pit, mood, seed, mark, fill, squash, hl) {
    if (N.orb >= CAP.orb) return; var o = N.orb++ * 16, d = A.orbs;
    d[o] = x; d[o + 1] = y; d[o + 2] = z; d[o + 3] = rad; d[o + 4] = c[0]; d[o + 5] = c[1]; d[o + 6] = c[2]; d[o + 7] = a;
    d[o + 8] = yaw; d[o + 9] = pit; d[o + 10] = mood; d[o + 11] = seed; d[o + 12] = mark; d[o + 13] = fill; d[o + 14] = squash; d[o + 15] = hl;
  }
  function spr(x, y, z, size, mark, a, rot) {
    if (N.spr >= CAP.spr || mark == null) return; var o = N.spr++ * 8, d = A.sprites;
    d[o] = x; d[o + 1] = y; d[o + 2] = z; d[o + 3] = size; d[o + 4] = mark; d[o + 5] = a; d[o + 6] = rot; d[o + 7] = 0;
  }
  function glo(x, y, z, size, c, a) {
    if (N.glow >= CAP.glow) return; var o = N.glow++ * 8, d = A.glows;
    d[o] = x; d[o + 1] = y; d[o + 2] = z; d[o + 3] = size; d[o + 4] = c[0]; d[o + 5] = c[1]; d[o + 6] = c[2];
    d[o + 7] = a * (walk ? 0.38 : 1);      // on foot every light is close, so each is turned down
  }
  function beam(ax, ay, az, bx, by, bz, c, a, width, u0, u1, speed, dash, phase) {
    if (N.beam >= CAP.beam) return; var o = N.beam++ * 16, d = A.beams;
    d[o] = ax; d[o + 1] = ay; d[o + 2] = az; d[o + 3] = bx; d[o + 4] = by; d[o + 5] = bz;
    d[o + 6] = c[0]; d[o + 7] = c[1]; d[o + 8] = c[2]; d[o + 9] = a; d[o + 10] = width; d[o + 11] = u0; d[o + 12] = u1; d[o + 13] = speed;
    d[o + 14] = dash; d[o + 15] = phase;
  }
  function shad(x, z, rad, a) {
    if (N.sh >= CAP.sh) return; var o = N.sh++ * 4, d = A.shadows; d[o] = x; d[o + 1] = z; d[o + 2] = rad; d[o + 3] = a;
  }
  function back(u) { var c = u - 1; return 1 + 2.7 * c * c * c + 1.7 * c * c; }

  /* A machine's core: a rack of servers. It was one dark column with two bars
     of light beside it, which said "pillar" and not "computer". The lamps on
     each server flicker faster the busier the machine is and take its state's
     colour; the two faces that look into the hall each carry a meter of ten
     lamps, CPU on one and memory on the other; and a beacon on top says ready,
     under pressure or not ready from across the cluster. Every figure is the
     node's own: nothing is lit for show. */
  var RACKC = [0.065, 0.078, 0.12], UNITC = [0.12, 0.14, 0.2], DARKC = [0.03, 0.035, 0.05];
  function rack(x, z, nd, lit, dim, t, seed) {
    var tall = 3.0, wide = 0.96, half = wide / 2, load = nd && nd.cpu_pct != null ? clamp(nd.cpu_pct / 100, 0, 1) : 0.2, u, k, y, on, c, f, m;
    var tone = !nd ? TONEF.info : !nd.ready ? TONEF.bad : nd.pressure.length || !nd.schedulable ? TONEF.warn : TONEF.ok;
    function dimmed(q) { return [q[0] * dim, q[1] * dim, q[2] * dim]; }
    solid(SOFT, x, 0.11, z, wide + 0.34, 0.22, wide + 0.34, dimmed(UNITC), 0, 0, 0, 0);                 // its plinth
    solid(SOFT, x, tall / 2 + 0.2, z, wide, tall, wide, dimmed(RACKC), lit ? 0.12 : 0, 0, 0, 0);       // the cabinet
    solid(SOFT, x, tall + 0.24, z, wide + 0.1, 0.1, wide + 0.1, dimmed(UNITC), 0, 0, 0, 0);            // and its top
    for (u = 0; u < 7; u++) {      // the servers in it: a front panel and its lamps, on both faces that look into the hall
      y = 0.52 + u * 0.38;
      cube(x + half + 0.004, y, z - 0.07, 0.02, 0.3, wide * 0.68, dimmed(UNITC), 0, 0, 0, 0, 5);
      cube(x - 0.07, y, z + half + 0.004, wide * 0.68, 0.3, 0.02, dimmed(UNITC), 0, 0, 0, 0, 5);
      cube(x + half + 0.012, y - 0.08, z - 0.07, 0.012, 0.03, wide * 0.5, dimmed(DARKC), 0, 0, 0, 0, 5);      // a drive bay
      cube(x - 0.07, y - 0.08, z + half + 0.012, wide * 0.5, 0.03, 0.012, dimmed(DARKC), 0, 0, 0, 0, 5);
      for (k = 0; k < 3; k++) {
        // a lamp is on most of the time and flickers with work; a machine that is not ready blinks all of them together
        on = calm ? 1 : !nd || nd.ready ? (Math.floor(t * (2 + load * 9) + u * 1.7 + k * 2.3 + seed) % 5 ? 1 : 0) : (Math.floor(t * 2) % 2);
        c = on ? dimmed(k === 2 && nd && nd.ready ? PATH : tone) : dimmed(DARKC);
        cube(x + half + 0.016, y + 0.07, z - 0.33 + k * 0.085, 0.014, 0.045, 0.045, c, on ? 0.9 : 0, 0, 0, 0, 5);
        cube(x - 0.33 + k * 0.085, y + 0.07, z + half + 0.016, 0.045, 0.045, 0.014, c, on ? 0.9 : 0, 0, 0, 0, 5);
      }
    }
    if (nd) [[nd.cpu_pct, 1], [nd.mem_pct, 0]].forEach(function (g) {      // ten lamps up the edge of a face: CPU on one, memory on the other
      if (g[0] == null) return;
      f = clamp(g[0] / 100, 0, 1); m = f >= 0.9 ? TONEF.bad : f >= 0.7 ? TONEF.warn : TONEF.ok;
      for (k = 0; k < 10; k++) {
        on = (k + 0.5) / 10 <= Math.max(f, 0.05);
        if (g[1]) cube(x + half + 0.016, 0.5 + k * 0.265, z + 0.36, 0.014, 0.2, 0.1, on ? dimmed(m) : dimmed(DARKC), on ? 0.8 : 0, 0, 0, 0, 5);
        else cube(x + 0.36, 0.5 + k * 0.265, z + half + 0.016, 0.1, 0.2, 0.014, on ? dimmed(m) : dimmed(DARKC), on ? 0.8 : 0, 0, 0, 0, 5);
      }
    });
    // the beacon: its colour is the machine's state, and it throbs when something is wrong
    f = tone === TONEF.ok || calm ? 1 : 0.55 + 0.45 * Math.sin(t * (tone === TONEF.bad ? 7 : 3));
    cube(x, tall + 0.42, z, 0.05, 0.3, 0.05, dimmed(UNITC), 0, 0, 0, 0, 5);
    solid(BALL, x, tall + 0.64, z, 0.24, 0.24, 0.24, dimmed(tone), 0.9 * f, 0, 0, 0);
    glo(x, tall + 0.64, z, lit ? 2.4 : 1.5, tone, (lit ? 0.7 : 0.4) * f * dim);
  }
  /* A volume: storage, drawn as what everybody draws for storage, a stack of
     discs. It was a plain ball, the same shape as a pod. The stack is as big
     as the claim (a wider one for more gigabytes, on a log scale so a terabyte
     does not hide the rest), each disc has a lit rim, and the lamp on its
     front is green when the claim is bound and blinks red when it is not. */
  function gigs(text) {
    var m = /^([0-9.]+)\s*([KMGTP]?)i?/.exec(String(text || '')), k = { K: 1e-6, M: 1e-3, G: 1, T: 1e3, P: 1e6 };
    return m ? parseFloat(m[1]) * (m[2] ? k[m[2]] : 1e-9) : 0;
  }
  function volume(x, y, z, ref, c, seen, strong, t, seed) {
    var s = clamp(0.8 + Math.log(1 + gigs(ref.size)) / Math.LN10 * 0.22, 0.8, 1.5), k, on = ref.bound || calm ? 1 : Math.floor(t * 3) % 2;
    var body = [c[0] * 0.8 * seen, c[1] * 0.8 * seen, c[2] * 0.8 * seen], rim = [c[0] * seen, c[1] * seen, c[2] * seen];
    for (k = 0; k < 3; k++) {
      solid(BALL, x, y + (k - 1) * 0.2 * s, z, 0.6 * s, 0.2 * s, 0.6 * s, body, strong ? 0.3 : 0.12, 0, 0, 0);            // a disc
      solid(BALL, x, y + (k - 1) * 0.2 * s + 0.045 * s, z, 0.64 * s, 0.035 * s, 0.64 * s, rim, strong ? 0.9 : 0.45, 0, 0, 0);      // and its lit rim
    }
    solid(BALL, x + fx * -0.31 * s, y - 0.2 * s, z + fz * -0.31 * s, 0.07 * s, 0.07 * s, 0.07 * s, on ? (ref.bound ? TONEF.ok : TONEF.bad) : DARKC, on ? 1 : 0, 0, 0, 0);      // the lamp, on the side you see
  }
  function world(t, dt, k) {
    var key, i, look = null;
    // What the pods are looking at: the place the pointer is over, on the floor
    // they stand on. With no pointer about, they look at whoever is watching.
    if (ptr.on && Date.now() - ptr.at < 6000) {
      var qx = ptr.x - W / 2, qy = H / 2 - ptr.y;
      var dx = fx * F + rx * qx + ux * qy, dy = fy * F + uy * qy, dz = fz * F + rz * qx + uz * qy, tt = (0.6 - ey) / dy;
      if (tt > 0 && isFinite(tt)) look = [ex + dx * tt, 0.6, ez + dz * tt];
    }
    if (walk) look = [walk.x, walk.y + 0.7, walk.z];      // somebody is walking among them: they watch that
    if (!look) look = [ex, ey, ez];

    // the machines: each an island, and on it a hall (a post at every corner
    // and a frame overhead), so that on foot a machine is a room you are in
    nIsles = 0;
    lay.plats.forEach(function (pl, n) {
      var nd = pl.node;
      var c = pl.limbo ? TONEF.info : nd ? (!nd.ready ? TONEF.bad : nd.pressure.length || !nd.schedulable ? TONEF.warn : ISLE) : ISLE;
      var lit = selKey === 'plat:' + pl.key || hoverKey === 'plat:' + pl.key || (walk && walk.near === 'plat:' + pl.key);
      var off = found && !found['plat:' + pl.key] && !pl.pods.some(function (p) { return found['pod:' + p.id]; });
      var load = nd && nd.cpu_pct != null ? clamp(nd.cpu_pct / 100, 0, 1) : 0.3, dimI = off ? 0.3 : 1;
      var cx = pl.x + pl.w / 2, cz = pl.z + pl.d / 2, eng = Math.min(pl.w, pl.d), x1 = pl.x + pl.w, z1 = pl.z + pl.d, HH = 3.1;
      var frame = [c[0] * dimI, c[1] * dimI, c[2] * dimI];
      cube(cx, -TH / 2, cz, pl.w, TH, pl.d, c, load, 0, ((lit ? 1.4 : 0.6) * dimI + (pl.bad && !calm ? 0.2 * Math.sin(t * 4) : 0)) * (walk ? 0.6 : 1), 1, 0);
      if (!HALL) {      // in a hall a bay is open, with its rack behind it: no posts and no frame to look through
        [[x1, pl.z], [x1, z1], [pl.x, z1]].forEach(function (q) { cube(q[0], HH / 2, q[1], 0.16, HH, 0.16, frame, 0.1, 0, 0, 1, 4); });
        cube(cx, HH, pl.z, pl.w, 0.1, 0.1, frame, 0.3, 0, 0, 1, 4); cube(cx, HH, z1, pl.w, 0.1, 0.1, frame, 0.3, 0, 0, 1, 4);
        cube(pl.x, HH, cz, 0.1, 0.1, pl.d, frame, 0.3, 0, 0, 1, 4); cube(x1, HH, cz, 0.1, 0.1, pl.d, frame, 0.3, 0, 0, 1, 4);
      }
      // its core stands in the first corner: a rack of servers, with what the
      // machine is using lit up its two faces
      rack(pl.x + 0.1, pl.z + 0.1, nd, lit, dimI, t, n);
      pl.blocks.forEach(function (b) {      // a plinth under each namespace's rows
        var bc = hue3(hash(b.key || 'none') % 360), k2 = ((focusNs && groupBy === 'node' && b.key !== focusNs) || off) ? 0.25 : 1;
        cube(b.x + b.w / 2, 0.03, b.z + b.d / 2, b.w - 0.14, 0.06, b.d - 0.14, [bc[0] * k2, bc[1] * k2, bc[2] * k2], 0.2, 0, 0, 1, 4);
      });
      glo(cx, -TH - 0.55, cz, eng * 0.5, c, (0.3 + load * 0.4) * dimI);
      beam(cx, -TH, cz, cx, GRIDY, cz, c, (0.07 + load * 0.1) * dimI, eng * 0.13, 0, 1, 0.2 + load * 0.9, 3, n * 0.37);
      if (nIsles < 24) {
        A.isles[nIsles * 4] = cx; A.isles[nIsles * 4 + 1] = cz; A.isles[nIsles * 4 + 2] = Math.max(pl.w, pl.d) * 0.7;
        for (i = 0; i < 3; i++) A.isleCols[nIsles * 3 + i] = c[i] * (0.35 + load * 0.4) * dimI;
        nIsles++;
      }
    });

    list.length = 0; wl = {};
    for (key in items) {
      var it = items[key];
      if (it.dead && t - it.dead > 2.4) { delete items[key]; continue; }
      it.x += (it.gx - it.x) * k; it.y += (it.gy - it.y) * k; it.z += (it.gz - it.z) * k;
      var ax = it.x, ay = it.y, az = it.z, u = (t - it.born) / 0.9, ref = it.ref, squash = 1;
      it.hid = u < 0;
      if (it.hid) continue;
      var isPod = it.kind === 'pod', mood = isPod ? (it.dead ? 'leaving' : ref.mood) : '';
      if (isPod) {
        if (u < 1 && !calm) ay += (1 - bounce(u)) * 7;
        // a dance: its partner in full, and the rest of its workload joining in from where they stand
        var dnc = dance && !it.dead && !calm ? (key === dance.key ? 1 : ref.wl === dance.wl ? 0.4 : 0) : 0, dbt = dnc ? danceBeat(t) : 0;
        if (it.dead) ay += (t - it.dead) * 1.6;
        else if (dnc) {
          var dup = Math.abs(Math.sin(dbt * PI)); ay += dup * 0.46 * dnc; squash = 0.9 + dup * 0.16;
          if (dnc === 1) { var dsw = Math.sin(dbt * PI / 2) * 0.2, dto = Math.atan2(walk.x - ax, walk.z - az); ax += Math.cos(dto) * dsw; az -= Math.sin(dto) * dsw; }
        } else if (!calm) {
          if (ref.tone === 'bad') ax += Math.sin(t * 31 + it.seed * 40) * 0.03;
          else if (mood === 'sleeping' || mood === 'done') squash = 1 + Math.sin(t * 0.9 + it.seed * 9) * 0.035;
          else if (mood === 'leaving') ay += 0.25 + Math.sin(t * 1.4 + it.seed * 9) * 0.14;
          else {
            var work = ref.cpu != null && (ref.cpu_lim || ref.cpu_req) ? clamp(ref.cpu / (ref.cpu_lim || ref.cpu_req), 0.05, 1.3) : 0.3;
            var hop = Math.abs(Math.sin(t * (1.0 + work * 2.8) + it.seed * 20)); ay += hop * (0.08 + work * 0.1); squash = 0.94 + hop * 0.1;
          }
        }
      } else if (!calm) ay += Math.sin(t * 0.8 + it.seed * 11) * 0.09;
      it.ax = ax; it.ay = ay; it.az = az;
      var size = isPod ? R : it.kind === 'svc' ? 0.24 + Math.min(0.2, ref.pods.length * 0.025) : it.kind === 'route' ? 0.5 : 0.4;
      var strong = (key === selKey || key === hoverKey || (walk && key === walk.near)) && !(dance && key === dance.key);      // a partner is not a target
      it.fade = it.dead ? 1 - (t - it.dead) / 2.4 : Math.min(1, u * 3);
      it.dim = dimmed(it);
      var v = view(ax, ay, az); it.sz = v[2]; it.pr = 0;
      if (v[2] >= NEAR) {
        var sc = F / v[2]; it.sx = W / 2 + v[0] * sc; it.sy = H / 2 - v[1] * sc; it.pr = sc * size;
        if (it.sx > -90 && it.sx < W + 90 && it.sy > -90 && it.sy < H + 90) list.push(it);
      }
      var a = it.fade, seen = it.dim ? 0.2 : 1;
      var cyaw = Math.atan2(ex - ax, ez - az), cpit = Math.atan2(ey - ay, Math.hypot(ex - ax, ez - az));
      if (isPod) {
        if (!it.dead) {
          var w = wl[ref.wl] || (wl[ref.wl] = { ax: 0, ay: 0, az: 0, n: 0 }); w.ax += ax; w.ay += ay + R; w.az += az; w.n++;
          if (ref.workload && /^(Deployment|StatefulSet|DaemonSet)$/.test(ref.kind)) { w.kind = ref.kind; w.name = ref.workload; }
        }
        var rad = R * (u < 1 && !calm ? Math.max(0.05, back(u)) : 1) * (strong ? 1.12 : 1);
        // where it is looking, and how quickly it turns its head (each its own pace)
        var lx = look[0] - ax, ly = look[1] - ay, lz = look[2] - az;
        var wantYaw = Math.atan2(lx, lz), wantPit = clamp(Math.atan2(ly, Math.hypot(lx, lz)), -0.5, 0.75);
        if (it.fyaw == null) { it.fyaw = cyaw; it.fpit = cpit; }
        if (mood === 'sleeping' || mood === 'done') { wantYaw = it.fyaw; wantPit = -0.22; }
        else if (mood === 'crying') wantPit = Math.min(wantPit, 0.1) - 0.2;
        else if (mood === 'dizzy') wantYaw += Math.sin(t * 2.3 + it.seed * 9) * 0.9;
        // dancing, it looks at its partner, sways its head, and turns when its partner turns
        if (dnc === 1) { wantYaw = Math.atan2(walk.x - ax, walk.z - az) + (Math.floor(dbt / 4) % 4 === 2 ? ease((dbt % 4) / 4) * TAU : Math.sin(dbt * PI) * 0.6); wantPit = 0.12; }
        var rate = calm ? 1 : dnc === 1 ? Math.min(1, dt * 14) : 1 - Math.exp(-dt * (2.5 + it.seed * 5));
        it.fyaw += Math.atan2(Math.sin(wantYaw - it.fyaw), Math.cos(wantYaw - it.fyaw)) * rate;
        it.fpit += (wantPit - it.fpit) * rate;
        var tech = ref.tech && data.techs[ref.tech], tone = ref.tone, mi = MOOD[dnc === 1 ? 'happy' : mood] + (it.dim ? 16 : 0);
        // the one colour on it is its state: the light of its eyes and the seam round its middle
        var sc = mood === 'hot' ? HOTC : mood === 'sleeping' || mood === 'done' ? TONEF.idle : TONEF[tone], lite = [sc[0] * seen, sc[1] * seen, sc[2] * seen];
        var soft = a * (mood === 'leaving' ? 0.55 : mood === 'done' ? 0.8 : 1) * (walk ? clamp((v[2] - 0.5) / 1.3, 0.1, 1) : 1);
        // the bubble is its memory limit, filled to what it uses. Drawn only
        // where it says something: on the pod in hand, and on one getting tight
        var fill = -1;
        if (!it.dead && !it.dim && tone !== 'idle' && ref.mem != null && ref.mem_lim) {
          var mf = clamp(ref.mem / ref.mem_lim, 0, 1), cf = ref.cpu != null && ref.cpu_lim ? ref.cpu / ref.cpu_lim : 0, top = Math.max(mf, cf);
          if (strong || top >= 0.7) fill = (top >= 0.9 ? 2 : top >= 0.7 ? 1 : 0) + mf * 0.999;
        }
        orb(ax, ay, az, rad, lite, soft, it.fyaw, it.fpit, mi, it.seed, tech ? (FAMI[tech.family] != null ? FAMI[tech.family] : 8) : -1, fill, squash, strong ? 1 : 0);
        if (!it.dead) {
          shad(ax, az, rad * 1.1, 0.5 * clamp(1 - (ay - R) / 5, 0, 1) * it.fade * (it.dim ? 0.3 : 1));
          cube(it.gx, 0.075, it.gz, 1.06, 0.03, 1.06, lite, tone === 'bad' ? 1.5 : 0.1, 0, 0, 1, 4);      // its place on the plinth
        }
        if ((tone === 'bad' || tone === 'warn') && !it.dim) {
          var pulse = tone === 'bad' && !calm ? 1 + 0.2 * Math.sin(t * 6 + it.seed * 9) : 1;
          glo(ax + fx * rad * 1.3, ay + fy * rad * 1.3, az + fz * rad * 1.3, rad * (tone === 'bad' ? 3.2 : 2.3) * pulse, sc, it.fade * (tone === 'bad' ? 0.7 : 0.3));
        }
        if (mood === 'hot' && !calm && !it.dim) for (var hq = 0; hq < 3; hq++) {
          var hf = (t * 0.8 + it.seed + hq / 3) % 1;
          glo(ax + Math.sin(hf * 9 + hq) * 0.12, ay + rad + hf * 1.3, az, rad * 0.45 * (1 - hf), HOTC, (1 - hf) * (walk ? 2 : 0.8));
        }
        if (it.flash && t - it.flash < 1 && !calm) glo(ax + fx * rad * 1.3, ay + fy * rad * 1.3, az + fz * rad * 1.3, rad * (2 + (t - it.flash) * 7), sc, (1 - (t - it.flash)) * 0.8);
      } else if (it.kind === 'svc') {
        var broken = !ref.pods.length && ref.selects, sc3 = broken ? TONEF.bad : ref.published ? GOLD : EDGEF.svc;
        cube(ax, ay, az, size, size, size, [sc3[0] * seen, sc3[1] * seen, sc3[2] * seen], strong ? 1 : 0.15, calm ? 0.6 : t * 0.7 + it.seed * 6, 0, 1, 2);
        glo(ax, ay, az, size * (strong ? 3.6 : 2.4), sc3, 0.4 * a * seen);
      } else {
        var oc = it.kind === 'route' ? GOLD : ref.bound ? VIOLET : TONEF.bad;
        if (it.kind === 'claim') volume(ax, ay, az, ref, oc, seen, strong, t, it.seed);
        else orb(ax, ay, az, size * 0.8, [oc[0] * seen, oc[1] * seen, oc[2] * seen], a, 0, 0, 9, it.seed, -1, -1, 1, strong ? 1 : 0);
        glo(ax + fx * size, ay + fy * size, az + fz * size, size * 2.6, oc, (it.kind === 'claim' ? 0.22 : 0.4) * a * seen);
      }
    }
    for (key in wl) { var m = wl[key]; m.ax /= m.n; m.ay /= m.n; m.az /= m.n; }

    // the lines, each with light travelling the way it points
    var hot = {};
    [selRel, hoverRel].forEach(function (s) { if (s) for (var q in s) hot[q] = 1; });
    var heavy = lay.edges.length > 1600;
    lay.edges.forEach(function (e, n) {
      var p = e.kind === 'link' ? wl[e.a.slice(3)] : items[e.a], q = items[e.b];
      if (!p || !q || p.hid || q.hid) return;
      var lit = hot[e.a] && hot[e.b];
      if (lit) { if (lines === 'off' && !selKey) return; }
      else if (walk ? !(e.kind === 'svc' && q.ref && q.ref.node === walk.isle) : (lines !== 'all' || (heavy && (e.kind === 'svc' || e.kind === 'claim')) || p.dim || q.dim)) return;
      var c = EDGEF[e.kind], arc = e.kind === 'link' || e.kind === 'route';
      var alpha = (lit ? 0.95 : arc ? 0.3 : 0.17) * (walk && !lit ? 0.45 : 1), width = lit ? 0.07 : 0.032, speed = calm ? 0 : lit ? 0.9 : 0.3;
      var len = Math.hypot(q.ax - p.ax, q.ay - p.ay, q.az - p.az), dash = calm ? 0 : Math.max(1, len / (lit ? 2.4 : 5));
      if (!arc) { beam(p.ax, p.ay, p.az, q.ax, q.ay, q.az, c, alpha, width, 0, 1, speed, dash, n * 0.37); return; }
      var mx = (p.ax + q.ax) / 2, my = Math.max(p.ay, q.ay) + 1.2 + len * 0.16, mz = (p.az + q.az) / 2, px = p.ax, py = p.ay, pz = p.az;
      for (var j = 1; j <= 12; j++) {
        var s = j / 12, w0 = (1 - s) * (1 - s), w1 = 2 * (1 - s) * s, w2 = s * s;
        var nx = w0 * p.ax + w1 * mx + w2 * q.ax, ny = w0 * p.ay + w1 * my + w2 * q.ay, nz = w0 * p.az + w1 * mz + w2 * q.az;
        beam(px, py, pz, nx, ny, nz, c, alpha, width, (j - 1) / 12, s, speed, dash, n * 0.37); px = nx; py = ny; pz = nz;
      }
    });
    life(t);
    if (walk) walkDraw(t);
    list.sort(function (a2, b2) { return b2.sz - a2.sz; });
  }

  function platTags() {
    lay.plats.forEach(function (pl) {
      // under whichever edge is nearest the reader, where there is a gap
      var mids = [[pl.x + pl.w / 2, pl.z], [pl.x + pl.w / 2, pl.z + pl.d], [pl.x, pl.z + pl.d / 2], [pl.x + pl.w, pl.z + pl.d / 2]], best = null;
      mids.forEach(function (m) { var v = view(m[0], -TH, m[1]); if (v[2] < NEAR) return; var p = scr(v); if (!best || p[1] > best[1]) best = [p[0], p[1], v[2]]; });
      if (!best || best[0] < -80 || best[0] > W + 80 || best[1] > H + 20) return;
      var k = F / best[2]; if (k * pl.w < 46) return;      // too small on screen to carry a name
      var nd = pl.node, name = pl.limbo ? 'not on any machine' : pl.key;
      var cp = nd && (nd.roles || []).some(function (r) { return r === 'control-plane' || r === 'master'; });
      var text = name + (cp ? ' · control plane' : '') + (nd && !nd.ready ? ' · NOT READY' : '') + (nd && !nd.schedulable ? ' · cordoned' : '') + ' · ' + pl.count + ' pods' + (pl.bad ? ' · ' + pl.bad + ' failing' : '')
        + (nd && nd.cpu_pct != null ? ' · cpu ' + nd.cpu_pct + '%' : '') + (nd && nd.mem_pct != null ? ' · mem ' + nd.mem_pct + '%' : '');
      tag(best[0], best[1] + 10, text, selKey === 'plat:' + pl.key || !!pl.bad, found && !found['plat:' + pl.key] ? 0.3 : 0.95);
      if (k * S >= 30 && labels) pl.blocks.forEach(function (b) {
        var v = view(b.x + 0.2, 0.05, b.z + b.d - 0.25); if (v[2] < NEAR) return; var p = scr(v);
        g.globalAlpha = 0.75; g.font = '600 10px ' + FONT; g.textAlign = 'left'; g.textBaseline = 'middle';
        g.fillStyle = 'hsl(' + hash(b.key || 'none') % 360 + ',80%,80%)'; g.fillText(b.key || 'no machine yet', p[0], p[1]);
      });
    });
  }
  function names() {
    // what is selected or pointed at first, then what is failing, then the
    // nearest, and each only where no other name already is
    placed.length = 0;
    var want = [];
    for (var n = list.length - 1; n >= 0; n--) {
      var o = list[n], strong = o.key === selKey || o.key === hoverKey, ref = o.ref;
      if (o.dead || (!strong && (o.dim || !labels))) continue;
      if (strong || (o.kind === 'pod' ? (o.pr >= (walk ? 46 : 22) || (ref.tone === 'bad' && o.pr >= 7)) : o.pr >= (walk ? 40 : 20)))
        want.push([strong ? 0 : ref.tone === 'bad' ? 1 : 2, o]);
    }
    want.sort(function (a, b) { return a[0] - b[0]; });      // stable: nearest stays first within a rank
    for (var i = 0, room = walk ? 12 : 46; i < want.length && room > 0; i++) {
      var w = want[i][1], r = w.ref, top = !want[i][0];
      var text = w.kind === 'pod' ? (top || !r.workload || r.kind === 'StatefulSet' ? r.name : r.workload)
        : w.kind === 'route' ? ((r.hosts || [])[0] || r.name) : r.name;
      if (text.length > 34) text = text.slice(0, 16) + '…' + text.slice(-15);
      if (tag(w.sx, w.sy + w.pr * (w.kind === 'pod' ? 1.62 : 1.4) + 4, text, top || r.tone === 'bad', w.fade, top)) room--;
    }
    platTags();
    var now = performance.now() / 1000;
    if (!walk && note && now - note.at < note.keep) tag(W / 2, 14, note.text, true, Math.min(1, (note.keep - (now - note.at)) * 2), true);
    if (walk && !dance) chatter.forEach(function (c) {
      var o = items[c.key], age = now - c.at; if (age < 0 || !o || o.ax == null || o.dead) return;
      var v = view(o.ax, o.ay + (o.kind === 'pod' ? 0.7 : 0.5), o.az); if (v[2] < NEAR) return;
      var q = scr(v); whisper(q[0], q[1] - 6, c.text, o.ref.tone, Math.min(1, age * 4) * Math.min(1, (CHAT - age) * 2));
    });
    // the examination: what the doctor says over the doctor, what the pod answers over the pod
    var ds = doc.say, ps = doc.pod, dp, pit, pv, pp = null, side = 0, mid = 0, docShown = false;
    if (ds && doc.sv && doc.sv[2] >= NEAR && now - doc.at < 90 && !unseen(scr(doc.sv))) {
      dp = scr(doc.sv); pit = ps && items['pod:' + ps.n.pod]; docShown = true;
      pv = pit && pit.ax != null && now - ps.at < hold(ps.n) + 12 ? view(pit.ax, pit.ay + 0.75, pit.az) : null;
      // however close the two stand on screen, their words meet at the middle and never cross
      if (pv && pv[2] >= NEAR && !unseen(scr(pv))) { pp = scr(pv); side = dp[0] >= pp[0] ? 1 : -1; mid = clamp((dp[0] + pp[0]) / 2, W * 0.3, W * 0.7); }
      bubble(dp[0], dp[1] - 16, ds.n.text, ds.n.who + '  ·  the doctor' + (SAYS[ds.n.state] ? '  ·  ' + SAYS[ds.n.state] : ''), { side: side, mid: mid, at: ds.at, doctor: ds.n.who });
      if (pp) bubble(pp[0], pp[1] - 10, ps.n.text, pit.ref.name, { side: -side, mid: mid, at: ps.at, tone: pit.ref.tone });
    }
    var youOn = doc.you && now - doc.you.at < hold(doc.you.n) + 6;
    if (youOn) bubble(W / 2, H - 150, doc.you.n.text, 'You  ·  to the doctor', { at: doc.you.at, you: true });
    subtitle(now, youOn, docShown, !!pp);
    if (walk && !picking && !fin && !dance) walkHud();
    if (walk) finDraw(now);
    if (walk && dance) danceDraw(now);
  }
  /* Whoever is speaking where you cannot see them is still heard, as a
     subtitle that says where they are. Words were drawn only over the speaker,
     so a doctor answering your question from a pod behind you, or across the
     cluster, gave an answer nobody saw: "he does not answer me". */
  /* Off the stage, or where its bubble would open under the cluster's card at
     the top left: a line said there could not be read. */
  function unseen(p) {
    if (p[0] < 24 || p[0] > W - 24 || p[1] < 40 || p[1] > H - 40) return true;
    var c = document.querySelector('.c3d-top'), r = c && c.getBoundingClientRect(), sb = stage.getBoundingClientRect();
    return !!(r && r.width) && p[0] < r.right - sb.left + 140 && p[1] - 70 < r.bottom - sb.top;
  }
  function subtitle(now, youOn, docShown, podShown) {
    var cur = doc.cur, n = cur && cur.n, it;
    if (!n || n.voice === 'person' || now - cur.at > hold(n) + 6) return;
    // the line the picture already shows over its speaker is not said twice
    if (n.voice === 'pod' ? podShown : docShown) return;
    it = n.pod && items['pod:' + n.pod];
    var name = it ? it.ref.name : n.pod ? n.pod.split('/').pop() : '';
    var who = n.voice === 'pod' ? (name || 'a pod') + '  ·  out of sight'
      : n.who + '  ·  the doctor' + (name ? '  ·  at ' + name : '  ·  out of sight');
    g.font = '700 11px ' + FONT;
    if (g.measureText(who).width > W - 90) who = name ? 'at ' + name : n.who;      // a narrow stage keeps where, not who
    // above your own line while it shows, above "press T to answer", and above a pod's talk window
    var y = H - 150 - (youOn ? Math.ceil(doc.you.n.text.length / 38) * 18 + 56 : 0);
    if (doc.asked && $('c3dSay').hidden) y = Math.min(y, H - 206);
    if (talk) y = Math.min(y, $('c3dTalk').getBoundingClientRect().top - stage.getBoundingClientRect().top - 30);
    bubble(W / 2, y, n.text, who, { at: cur.at, doctor: n.voice === 'pod' ? '' : n.who, tone: it && it.ref.tone, tail: false });
  }
  function caption(key) {
    var c = $('c3dCaption'), r = key && ix.ref[key], pl;
    if (!key) c.textContent = '';
    else if (r && !key.indexOf('pod:')) c.textContent = r.name + '   ·   ' + (r.problem || 'healthy') + (r.restarts ? '   ·   ' + r.restarts + ' restart' + (r.restarts === 1 ? '' : 's') : '') + '   ·   ' + r.ns;
    else { pl = lay.plats.filter(function (p) { return 'plat:' + p.key === key; })[0]; c.textContent = pl ? (pl.limbo ? 'not on any machine' : pl.key) + '   ·   ' + pl.count + ' pods' : ''; }
  }

  /* ── life, and the power over it ─────────────────────────────────────
     On foot you carry one of three things: a hand (E talks), a blaster (kills
     the pod in front of you) and a medkit (restarts the workload it belongs
     to). The last two are the same two actions the conversation offers, sent
     through the same guarded route. They are ARMED once, by typing the word
     the portal asks for before any delete (and the cluster's name where it
     serves production), and stay armed only until the walk ends: a typed word
     before every shot is not a game, and no word at all is not a safeguard.

     What follows a death is drawn, because it is the point of the thing:
     the owner of the dead pod starts another, and light runs from where the
     one fell to the one that replaces it. */
  var TOOLS = ['Hand', 'Blaster', 'Medkit'], MEDKIT = { name: 'Medkit', verb: 'got its medicine', how: 'bolt', c: [0.3, 1.0, 0.6] }, tool = 0, armed = null, shotAt = -9, note = null, feed = [], hitAt = -9, AC = null;
  var graves = [], heals = [], sparks = [], CTRL = [0.95, 0.9, 0.7];
  function toast(text, kind) {
    note = { text: text, at: performance.now() / 1000, keep: clamp(2.5 + text.length / 22, 5, 12), kind: kind || '' };
    feed.push(note); if (feed.length > 4) feed.shift();
  }
  /* A few sounds, made here from a tone each: nothing is fetched or shipped
     for them. M turns them off, and that is kept with the rest of your choices. */
  var SFX = { kick: [150, 46, 0.16, 0.2, 'sine'], tick: [660, 520, 0.05, 0.035, 'square'], whoosh: [240, 80, 0.55, 0.06, 'sawtooth'], hit: [150, 36, 0.5, 0.32, 'sine'], heal: [440, 880, 0.4, 0.09, 'sine'] };
  function sfx(kind) {
    if (me.mute) return;
    try {
      AC = AC || new (window.AudioContext || window.webkitAudioContext)();
      var f = SFX[kind], t0 = AC.currentTime, o = AC.createOscillator(), v = AC.createGain();
      o.type = f[4]; o.frequency.setValueAtTime(f[0], t0); o.frequency.exponentialRampToValueAtTime(f[1], t0 + f[2]);
      v.gain.setValueAtTime(f[3], t0); v.gain.exponentialRampToValueAtTime(0.0001, t0 + f[2]);
      o.connect(v); v.connect(AC.destination); o.start(t0); o.stop(t0 + f[2] + 0.03);
    } catch (e) { /* a browser with no sound plays the same game */ }
  }
  function burst(it, c) {
    for (var i = 0; i < 16; i++) {
      var a = Math.random() * TAU, up = Math.random();
      sparks.push({ x: it.ax, y: it.ay, z: it.az, vx: Math.cos(a) * (0.6 + up), vy: 0.8 + up * 1.6, vz: Math.sin(a) * (0.6 + up), c: c, at: performance.now() / 1000 });
    }
  }
  function healed(it, now) {
    for (var i = graves.length - 1; i >= 0; i--) {
      if (now - graves[i].at > 120) { graves.splice(i, 1); continue; }
      if (graves[i].wl !== it.ref.wl) continue;
      heals.push({ key: it.key, x: graves[i].x, y: graves[i].y, z: graves[i].z, at: now });
      // a pod killed for good that comes back was put back by what manages it, and that is said
      toast(graves[i].end ? (it.ref.kind || 'Its owner') + ' ' + (it.ref.workload || it.ref.name) + ' is back to its old size: what manages it (Git, or an autoscaler) started a pod where you killed one'
        : (it.ref.kind || 'Its owner') + ' ' + (it.ref.workload || it.ref.name) + ' healed itself: a new pod is starting where one died');
      graves.splice(i, 1);
      return;
    }
  }
  function send(action, r, typed) {
    return fetch('/clusters/3d/act.json', { method: 'POST', credentials: 'same-origin', headers: { Accept: 'application/json' },
      body: new URLSearchParams({ project: QS.get('project'), cluster: QS.get('cluster'), action: action, namespace: r.ns,
        name: action === 'restart' ? r.workload : r.name, kind: action === 'restart' ? r.kind.toLowerCase() : 'pod', confirm: typed }) })
      .then(function (res) { return res.json(); });
  }
  function arm(then) {
    if (locked()) document.exitPointerLock();
    keys = {};
    var words = 'pods on ' + stage.getAttribute('data-name') + ': one real pod for every shot, until you leave the walk';
    (window.confirmDelete ? window.confirmDelete(words) : Promise.resolve(window.confirm('Arm? Every shot deletes a real pod.'))).then(function (yes) {
      if (!yes || !walk) return;
      armed = { typed: data.can.prod ? (window.prompt('This cluster serves production. Type its name to arm:') || '') : '' };
      toast('Armed. Every shot is real, and every shot is in the audit log'); grab();
      if (then) then();
    });
  }
  function useTool() {
    var k = walk.near, r = k && !k.indexOf('pod:') && ix.ref[k], it = r && items[k], now = performance.now() / 1000, kill = tool === 1;
    if (!r || !it) { toast('Nothing in reach: walk up to a pod'); return; }
    if (!data.can || !data.can.act) { toast('The ' + (kill ? WEAPONS[me.weapon].name : TOOLS[tool]).toLowerCase() + ' is locked: ' + ((data.can || {}).why || 'not allowed')); return; }
    if (!kill && !/^(Deployment|StatefulSet|DaemonSet)$/.test(r.kind)) { toast('Nothing owns ' + r.name + ', so there is nothing to restart'); return; }
    if (!armed) { arm(useTool); return; }
    if (now - shotAt < 0.7) return;
    shotAt = now;
    send(kill ? 'delete-pod' : 'restart', r, armed.typed).then(function (d) {
      if (!d.ok) { toast('Refused: ' + d.message); return; }
      if (game) game.acts++;
      finish(it, r, kill ? WEAPONS[me.weapon] : MEDKIT, kill ? 'kill' : 'restart');
    }).catch(function () { toast('The portal did not answer'); });
  }
  /* A weapon on its way to a pod, and what follows when it lands. Nothing here
     runs until the portal has said the action went through: a refusal is a
     miss, however good the throw would have looked. */
  function strike(it, w, slow) {
    var now = performance.now() / 1000, d = Math.hypot(it.ax - walk.x, it.az - walk.z) || 1, hand = w.how === 'slash' || w.how === 'drop';
    shot = { w: w, it: it, at: now, dur: (w.how === 'bolt' ? 0.5 : w.how === 'slash' ? 0.62 : w.how === 'drop' ? 0.72 : 0.74) * (slow || 1) };
    walk.face = Math.atan2(it.ax - walk.x, it.az - walk.z);
    if (walk.riding) { walk.riding = false; walk.remount = true; }      // nobody swings a hammer sitting down
    // a hand weapon has to reach: you close the distance while it is raised
    if (hand && d > 1.4) walk.dash = { x0: walk.x, z0: walk.z, x1: it.ax - (it.ax - walk.x) / d * 1.3, z1: it.az - (it.az - walk.z) / d * 1.3, at: now, dur: shot.dur * 0.38 };
    walk.act = { how: w.how, w: w, at: now, dur: shot.dur };
    return shot;
  }
  /* Where your right hand is when the arm is at `ang` and `reach` long: a bolt
     and a throw leave from there, not from the middle of you. */
  function handAt(ang, reach) {
    var cs = Math.cos(walk.face), sn = Math.sin(walk.face), oz = reach * KFIG * Math.sin(ang);
    return [walk.x + 0.27 * KFIG * cs + oz * sn, walk.y + (1.42 - reach * Math.cos(ang)) * KFIG, walk.z - 0.27 * KFIG * sn + oz * cs];
  }
  function land(it, r, w, kind) {
    var at = performance.now() / 1000;
    hitAt = at; verdict = { kind: kind, r: r, w: w, at: at }; sfx(kind === 'restart' ? 'heal' : 'hit');
    if (fin && !calm) { walk.move = { at: at + 0.35, dur: 1.5 }; walk.face = goal.yaw; }      // and you take your bow, to the camera
    if (kind !== 'restart') {      // 'kill' comes back as another pod; 'end' was killed for good
      burst(it, w.c || TONEF.bad); burst(it, TONEF.bad); it.dead = at; graves.push({ wl: r.wl, x: it.ax, y: it.ay, z: it.az, at: at, end: kind === 'end' });
      toast(r.name + ' ' + w.verb + '. ' + (kind === 'end' ? killed(r) : r.workload ? r.kind + ' ' + r.workload + ' will start another' : 'Nothing owns it: it will not come back'), 'kill');
    } else {
      (ix.wlPods[r.wl] || []).forEach(function (id) { var o = items['pod:' + id]; if (o && o.ax != null) { o.flash = at; burst(o, TONEF.ok); } });
      toast('Medicine given: every pod of ' + r.workload + ' will be replaced, one after another', 'heal');
    }
    poll(true);
  }

  /* ── the finisher ────────────────────────────────────────────────────
     A pod taken out, or a workload restarted, gets its moment the way a
     fighting game ends a round: the screen closes to a letterbox, the camera
     leaves you for the pod, the blow lands slowly, and a verdict is stamped
     across the picture. The sequence and its words are this view's own.

     It starts only AFTER the portal has answered that the action went
     through, so it never celebrates something that did not happen. A second
     one asked for while one plays, and anybody who asked for less motion, gets
     the blow and the verdict without the camera. Space, Enter or Esc skips. */
  var fin = null, verdict = null, FIN = { kill: ['ANY LAST LOGS?', 'EVICTED'], end: ['NO COMING BACK THIS TIME.', 'GONE FOR GOOD'], restart: ['HOLD STILL.', 'ROLLING RESTART'] };
  function finish(it, r, w, kind) {
    var s;
    if (talk) talkClose();
    if (calm || fin || it.ax == null) {
      s = strike(it, w);
      setTimeout(function () { land(it, r, w, kind); }, s.dur * 1000);
      return;
    }
    // where the pod stands now: a pod that has fallen rises and fades, and the camera stays with the scene
    fin = { it: it, r: r, w: w, kind: kind, at: performance.now() / 1000, yaw: goal.yaw, pitch: goal.pitch, shot: null, hit: 0, x: it.ax, y: it.ay, z: it.az };
    keys = {}; stage.classList.add('fin'); sfx('whoosh');
  }
  function finStep(t) {
    var f = fin;
    if (f.it.ax == null) { finEnd(); return; }
    if (!f.shot && t - f.at > 0.95) f.shot = strike(f.it, f.w, 2.2);      // the blow, slowed
    if (f.shot && !f.hit && t > f.shot.at + f.shot.dur) { f.hit = t; land(f.it, f.r, f.w, f.kind); }
    if (f.hit && t - f.hit > 2.1) finEnd();
  }
  function finEnd() {
    var f = fin;
    if (!f) return;
    fin = null; stage.classList.remove('fin');
    if (!f.hit) land(f.it, f.r, f.w, f.kind);      // skipped: what happened is still shown
    goal.yaw = f.yaw; goal.pitch = f.pitch;
  }
  /* Big letters that land: over-sized for a moment, then settled. */
  function slam(text, y, size, top, foot, age, tilt, alpha, framed) {
    var k = calm || age > 0.2 ? 1 : 1 + (1 - age / 0.2) * 1.5, wide;
    g.save(); g.translate(W / 2, y); g.rotate(tilt); g.scale(k, k); g.globalAlpha = Math.max(0, Math.min(1, age / 0.1) * alpha);
    g.font = 'italic 900 ' + size + 'px ' + FONT; g.textAlign = 'center'; g.textBaseline = 'middle';
    var grad = g.createLinearGradient(0, -size / 2, 0, size / 2); grad.addColorStop(0, top); grad.addColorStop(1, foot);
    g.lineJoin = 'round'; g.lineWidth = Math.max(4, size / 9); g.strokeStyle = 'rgba(0,0,0,.9)'; g.strokeText(text, 0, 0);
    g.shadowColor = foot; g.shadowBlur = size / 2; g.fillStyle = grad; g.fillText(text, 0, 0); g.shadowBlur = 0;
    if (framed) {      // a stamp has an edge
      wide = g.measureText(text).width;
      g.lineWidth = Math.max(3, size / 14); g.strokeStyle = foot; g.strokeRect(-wide / 2 - size * 0.3, -size * 0.66, wide + size * 0.6, size * 1.32);
    }
    g.restore(); g.globalAlpha = 1;
  }
  function finDraw(now) {
    var f = fin, v = verdict, age, bar, size = Math.round(clamp(W * 0.07, 34, 96)), kill;
    if (f) {
      age = now - f.at; bar = (calm ? 1 : Math.min(1, age / 0.25)) * H * 0.11;
      g.globalAlpha = 1; g.fillStyle = '#000'; g.fillRect(0, 0, W, bar); g.fillRect(0, H - bar, W, bar);
      if (!f.hit && age > 0.12) {
        slam(FIN[f.kind][0], H * 0.24, Math.round(size * 0.62), '#ffffff', '#aeb8cf', age - 0.12, 0, 1, false);
        ink((HEROES[me.hero].name + ' · ' + f.w.name).toUpperCase() + '      VS      ' + (f.kind === 'restart' ? f.r.kind + ' ' + f.r.workload : f.r.name).toUpperCase(), W / 2, H * 0.24 + size * 0.55, 12, HUDC.amber, 'center', 800, 2);
      }
      if (f.hit && now - f.hit < 0.16 && !calm) { g.globalAlpha = (1 - (now - f.hit) / 0.16) * 0.8; g.fillStyle = '#fff'; g.fillRect(0, 0, W, H); g.globalAlpha = 1; }
      ink('SPACE   SKIP', W - 22, H - bar / 2, 10, HUDC.dim, 'right', 700, 2);
    }
    if (v && now - v.at < 2.3) {
      age = now - v.at; kill = v.kind !== 'restart';
      slam(FIN[v.kind][1], H * 0.26, size, kill ? '#ffe08a' : '#eafff3', kill ? '#ff3b4e' : '#3ddc97', age, -0.06, Math.min(1, (2.3 - age) * 3), true);
      g.globalAlpha = Math.min(1, age * 4) * Math.min(1, (2.3 - age) * 3);
      ink((kill ? v.r.name + ' ' + v.w.verb : 'every pod of ' + v.r.workload + ' is being replaced').toUpperCase(), W / 2, H * 0.26 + size * 1.05, 13, HUDC.ink, 'center', 800, 1.5);
      ink((!kill ? 'one after another' : v.kind === 'end' ? killed(v.r) : v.r.workload ? v.r.kind + ' ' + v.r.workload + ' is starting another' : 'nothing owns it: it will not come back').toUpperCase(),
        W / 2, H * 0.26 + size * 1.05 + 22, 11, HUDC.dim, 'center', 700, 1.5);
      g.globalAlpha = 1;
    }
  }
  /* ── a dance ─────────────────────────────────────────────────────────
     "Dance with me" in a pod's conversation, or B with a pod in reach. You
     and the pod dance for a dozen seconds: your figure through four figures,
     the pod jumping and turning with you, the rest of its workload joining in
     from where they stand, lights going round and a tune made here from a few
     tones. It is the one thing in this view that does nothing at all: no
     request is sent, nothing is audited, and it needs no permission. Space,
     Enter, Esc or B stops it; less motion gets the tune and the caption
     without the moves or the camera. */
  var dance = null, BPM = 124, DANCE = 13.2, DISCO = [[1.0, 0.3, 0.62], [0.3, 0.8, 1.0], [1.0, 0.85, 0.3], [0.62, 0.42, 1.0], [0.3, 1.0, 0.6]];
  var TUNE = [0, 7, 12, 10, 7, 5, 7, 3, 5, 12, 15, 12, 10, 7, 5, 3], BASS = [110, 110, 87.31, 98];
  function danceBeat(t) { return Math.max(0, (t - dance.at - 0.4) * BPM / 60); }
  function beep(freq, len, gain, type, after) {
    if (me.mute) return;
    try {
      AC = AC || new (window.AudioContext || window.webkitAudioContext)();
      var t0 = AC.currentTime + (after || 0), o = AC.createOscillator(), v = AC.createGain();
      o.type = type; o.frequency.setValueAtTime(freq, t0);
      v.gain.setValueAtTime(0.0001, t0); v.gain.exponentialRampToValueAtTime(gain, t0 + 0.012); v.gain.exponentialRampToValueAtTime(0.0001, t0 + len);
      o.connect(v); v.connect(AC.destination); o.start(t0); o.stop(t0 + len + 0.03);
    } catch (e) { /* a browser with no sound dances in silence */ }
  }
  function danceLine(r) {
    if (r.tone === 'bad') return 'I am falling over, and I can still dance. Thank you for asking.';
    if (r.mood === 'sleeping') return 'No machine has room for me, but there is room for this.';
    if (r.mood === 'done') return 'My job is finished. This is how it should end.';
    if (r.tone === 'warn') return 'I am not at my best, and I will dance anyway.';
    return 'Nobody ever asks the pods to dance. Yes!';
  }
  function danceStart(key) {
    var it = items[key], r = ix.ref[key], now = performance.now() / 1000, d, k;
    if (!walk || fin || dance || picking || !r || !it || it.dead || it.ax == null) return;
    if (talk) talkClose();
    select('', false);      // its card and its ring step back too: this is not an inspection
    dance = { key: key, name: r.name, wl: r.wl, line: danceLine(r), at: now, beat: -1, yaw: goal.yaw, pitch: goal.pitch, remount: walk.riding };
    walk.riding = false; walk.move = null; keys = {};      // nobody dances sitting down
    // where a partner stands: close, and not on its toes
    d = Math.hypot(walk.x - it.gx, walk.z - it.gz);
    if (d > 0.01 && (d < 1.5 || d > 2.1)) { k = 1.8 / d; walk.dash = { x0: walk.x, z0: walk.z, x1: it.gx + (walk.x - it.gx) * k, z1: it.gz + (walk.z - it.gz) * k, at: now, dur: 0.35 }; }
    stage.classList.add('dancing'); sfx('whoosh');
  }
  function danceEnd(early) {
    var d = dance, it, now = performance.now() / 1000;
    if (!d) return;
    dance = null; stage.classList.remove('dancing');
    if (!walk) return;
    goal.yaw = d.yaw; goal.pitch = d.pitch;
    if (d.remount) walk.riding = true;
    it = items[d.key];
    if (!early && it && it.ax != null) { it.flash = now; burst(it, GOLD); burst({ ax: walk.x, ay: walk.y + 1, az: walk.z }, PATH); sfx('heal'); walk.move = { at: now, dur: 1.5 }; }
    toast(early ? 'The dance with ' + d.name + ' stopped.' : 'You danced with ' + d.name + '. Nothing in the cluster changed, and that is fine.');
  }
  function danceStep(t) {
    var d = dance, it = items[d.key], n, i, a, cx, cz;
    if (!walk || !it || it.dead || it.ax == null) { danceEnd(true); return; }
    if (t - d.at > DANCE) { danceEnd(false); return; }
    n = Math.floor(danceBeat(t));
    if (t - d.at > 0.4 && n > d.beat) {      // on the beat: a kick, the bass, two notes of the tune, and a tick between
      d.beat = n; sfx('kick');
      beep(BASS[Math.floor(n / 4) % 4], 0.24, 0.09, 'triangle');
      beep(220 * Math.pow(2, TUNE[n * 2 % TUNE.length] / 12), 0.2, 0.05, 'square');
      beep(220 * Math.pow(2, TUNE[(n * 2 + 1) % TUNE.length] / 12), 0.18, 0.05, 'square', 30 / BPM);
      beep(5200, 0.03, 0.02, 'square', 30 / BPM);
      if (!calm && n % 4 === 0) burst({ ax: (walk.x + it.ax) / 2, ay: walk.y + 2.4, az: (walk.z + it.az) / 2 }, DISCO[Math.floor(n / 4) % DISCO.length]);
    }
    if (calm) return;
    cx = (walk.x + it.gx) / 2; cz = (walk.z + it.gz) / 2;
    for (i = 0; i < 6; i++) {      // lights on the floor, going round the two of them
      a = t * 1.3 + i * TAU / 6;
      glo(cx + Math.cos(a) * 2.3, walk.y + 0.12, cz + Math.sin(a) * 2.3, 0.85, DISCO[(i + Math.max(0, n)) % DISCO.length], 0.9);
    }
    for (i = 0; i < 2; i++) {      // and one from above on each
      a = t * 0.9 + i * PI;
      beam(i ? it.ax : walk.x, (i ? it.ay : walk.y + 1) + 0.3, i ? it.az : walk.z, cx + Math.cos(a) * 2.6, walk.y + 11, cz + Math.sin(a) * 2.6, DISCO[(i * 2 + Math.max(0, n)) % DISCO.length], 0.3, 0.3, 0, 1, 0, 0, 0);
    }
  }
  function danceDraw(now) {
    var d = dance, age = now - d.at, it = items[d.key], bar = (calm ? 1 : Math.min(1, age / 0.25)) * H * 0.07, v, q, i, u;
    g.globalAlpha = 1; g.fillStyle = '#000'; g.fillRect(0, 0, W, bar); g.fillRect(0, H - bar, W, bar);
    ink(('Dancing with ' + d.name).toUpperCase(), W / 2, bar / 2, 12, HUDC.amber, 'center', 800, 2);
    ink('NOTHING IN THE CLUSTER CHANGES', 22, H - bar / 2, 10, HUDC.dim, 'left', 700, 2);
    ink('SPACE   STOPS', W - 22, H - bar / 2, 10, HUDC.dim, 'right', 700, 2);
    v = it && it.ax != null && view(it.ax, it.ay + 0.75, it.az);
    if (!v || v[2] < NEAR) return;
    q = scr(v);
    if (age < 4.5) { bubble(q[0], q[1] - 10, d.line, d.name, { at: d.at, tone: it.ref.tone }); return; }
    if (calm) return;
    g.font = '700 22px ' + FONT; g.textAlign = 'center'; g.textBaseline = 'middle'; g.fillStyle = '#fff';
    for (i = 0; i < 3; i++) {      // notes, rising off it
      u = (now * 0.45 + i / 3) % 1;
      g.globalAlpha = Math.min(1, u * 5) * (1 - u); g.fillText(i % 2 ? '\u266B' : '\u266A', q[0] + Math.sin(u * 7 + i * 2.1) * 26, q[1] - 14 - u * 80);
    }
    g.globalAlpha = 1;
  }
  function strikeDraw(t) {
    var s = shot, w = s.w, it = s.it, u = (t - s.at) / s.dur, bx = it.ax, by = it.ay, bz = it.az, h, v;
    if (w.how === 'bolt') {      // aimed first, then the bolt, from the muzzle
      if (u > 0.6 && u < 1.05) { h = handAt(1.5, 0.9); v = (u - 0.6) / 0.45; beam(h[0], h[1], h[2], bx, by, bz, w.c || [1.0, 0.35, 0.3], 2.6 * (1 - v), 0.1, 0, 1, 0, 0, 0); glo(h[0], h[1], h[2], 0.8, w.c || REDC, 1.6 * (1 - v)); }
    } else if (w.how === 'slash') [[0.1, 0.4, -1], [0.6, 0.95, 1]].forEach(function (c) {      // each cut leaves its line
      v = (u - c[0]) / (c[1] - c[0]);
      if (v > 0 && v < 1.3) beam(bx - c[2] * 0.65, by + 0.65, bz, bx - c[2] * 0.65 + c[2] * 1.3 * Math.min(1, v), by + 0.65 - 1.3 * Math.min(1, v), bz, YOU, 2.4 * (1 - v * 0.7), 0.05, 0, 1, 0, 0, 0);
    });
    else if (w.how === 'throw' && u > RELEASE && u < 1) {      // let go at the top of the swing, turning over as it flies
      h = handAt(2.0, 0.62); v = (u - RELEASE) / (1 - RELEASE);
      solid(w.shape || BOX, h[0] + (bx - h[0]) * v, h[1] + (by - h[1]) * v + Math.sin(v * PI) * 0.7, h[2] + (bz - h[2]) * v, w.size[0], w.size[1], w.size[2], w.c, w.name === 'Snowball' ? 0.5 : 0, walk.face, calm ? 0 : -v * 9, 0);
    }
    // a hammer is in your hands the whole way: nothing comes out of the sky
  }
  function life(t) {
    var i, s, a, wid, m, to;
    for (i = heals.length - 1; i >= 0; i--) {
      s = heals[i]; a = (t - s.at) / 3.2; to = items[s.key];
      if (a > 1 || !to || to.ax == null) { if (a > 1 || !to) heals.splice(i, 1); continue; }
      beam(s.x, s.y + 0.3, s.z, to.ax, to.ay, to.az, TONEF.ok, (1 - a) * 1.3, 0.06, 0, 1, 1.6, 2, 0);
      glo(to.ax, to.ay, to.az, 1.4 + a * 2.2, TONEF.ok, (1 - a) * (walk ? 2.2 : 0.9));
    }
    for (i = sparks.length - 1; i >= 0; i--) {
      s = sparks[i]; a = (t - s.at) / 0.9;
      if (a > 1) { sparks.splice(i, 1); continue; }
      glo(s.x + s.vx * a, s.y + s.vy * a - a * a * 1.4, s.z + s.vz * a, 0.3 * (1 - a), s.c, (1 - a) * (walk ? 2.4 : 1));
    }
    if (fin) finStep(t);
    if (dance) danceStep(t);
    if (shot && shot.it.ax != null && t - shot.at < shot.dur + 0.12) strikeDraw(t);
    doctorDraw(t);
    if (walk) {
      chatterStep(t);
      chatter.forEach(function (c) {      // an answer runs back along a thread to whoever it answers
        var a = c.from && items[c.from], b = items[c.key], age = t - c.at;
        if (a && b && a.ax != null && b.ax != null && age > 0 && age < 2.2 && !calm) beam(b.ax, b.ay + 0.3, b.az, a.ax, a.ay + 0.3, a.az, EDGEF.link, 0.7 * (1 - age / 2.2), 0.03, 0, 1, 1.8, 4, 0);
      });
    }
    if (game && game.won && t - game.won < 7 && !calm && Math.random() < 0.3) {      // fireworks, over the hall you are in
      burst({ ax: walk.x + (Math.random() - 0.5) * 14, ay: 3 + Math.random() * 4, az: walk.z + (Math.random() - 0.5) * 14 }, [TONEF.ok, PATH, GOLD][Math.floor(Math.random() * 3)]);
    }
    if (!walk) return;
    // whatever owns pods hovers over the ones it keeps alive, with a thread to each
    for (wid in wl) {
      m = wl[wid];
      if (!m.kind || Math.hypot(m.ax - walk.x, m.az - walk.z) > 15) continue;
      var cy = m.ay + 1.55 + (calm ? 0 : Math.sin(t * 1.2 + m.ax) * 0.08);
      orb(m.ax, cy, m.az, 0.22, CTRL, 1, 0, 0, 9, 0.3, -1, -1, 1, 0);
      (ix.wlPods[wid] || []).forEach(function (id) {
        var o = items['pod:' + id];
        if (o && !o.dead && !o.hid && o.ax != null) beam(m.ax, cy, m.az, o.ax, o.ay + 0.5, o.az, CTRL, 0.22, 0.016, 0, 1, 0.5, 2, 0);
      });
    }
  }

  /* ── the mission, and the doctor ─────────────────────────────────────
     The walk has a goal: every pod healthy. It is won when the CLUSTER says
     so (nothing failing and nothing needing a look in the data just read),
     never when the player has pressed enough buttons.

     H calls for a doctor. The call is a line the portal's MCP server hands to
     whatever model the person has connected (`doctor_calls`); that model
     examines and treats with its own tools and says what it is doing
     (`doctor_note`), and each note is drawn here as a doctor standing beside
     the pod it is about. Nothing in this file treats anything by itself. */
  var game = null, DOCC = [1.0, 0.5, 0.3], docTimer = 0;
  var doc = { on: false, last: 0, notes: [], calls: [], queue: [], cur: null, say: null, pod: null, you: null, mine: {}, hands: null, x: 0, y: 0.5, z: 0, at: -99,
    log: [], logged: 0, me: '', drawn: '' };
  var SAYS = { arrived: 'has arrived', asking: 'asks', examining: 'examining', treating: 'treating', healed: 'healed it', failed: 'could not heal it', done: 'is leaving' };
  function win() {
    var now = performance.now() / 1000, secs = Math.round(now - game.start);
    game.won = now;
    game.line = 'in ' + Math.floor(secs / 60) + ':' + ('0' + secs % 60).slice(-2) + (game.acts ? ' · ' + game.acts + ' action' + (game.acts === 1 ? '' : 's') + ' of yours' : '')
      + (doc.notes.length ? ' · with the doctor' : '');
  }
  function sendNode(action, pl) {
    return function () {
      if (!window.confirm(action === 'cordon' ? 'Cordon ' + pl.key + '? No new pod will be placed on it.' : 'Uncordon ' + pl.key + '? Pods may be placed on it again.')) return;
      var typed = data.can.prod ? (window.prompt('This cluster serves production. Type its name to go ahead:') || '') : '';
      talkShow('Doing it…');
      fetch('/clusters/3d/act.json', { method: 'POST', credentials: 'same-origin', headers: { Accept: 'application/json' },
        body: new URLSearchParams({ project: QS.get('project'), cluster: QS.get('cluster'), action: action, node: pl.key, confirm: typed }) })
        .then(function (res) { return res.json(); })
        .then(function (d) {
          if (d.ok && game) game.acts++;
          if (talk) talkShow(d.ok ? (action === 'cordon' ? 'Done. Nothing new will land on me.' : 'Done. Pods waiting for a machine may come to me now.') : 'It was refused: ' + d.message);
          poll(true);
        }).catch(function () { if (talk) talkShow('I could not reach the portal.'); });
    };
  }
  function doctorPoll() {
    clearTimeout(docTimer);
    if (!doc.on) return;
    getJson('/clusters/3d/doctor.json', { since: doc.last }).then(function (d) {
      var fresh = d.notes || [], newest = fresh.length ? fresh[fresh.length - 1].at : 0;
      // the chat keeps everything said, an ended visit included: it is the record, where the picture is the moment
      fresh.forEach(function (n) { if (n.n > doc.logged) { doc.log.push(n); doc.logged = n.n; } });
      doc.log = doc.log.slice(-60);
      // Walking in on a visit already UNDER WAY: watch its last quarter of an
      // hour. A visit that has ENDED is not replayed: everything up to the
      // doctor's last "done" is history, and without an open call or a line in
      // the last two minutes there is nobody here. Replaying a finished visit
      // put the doctor in the picture of somebody who had not called it.
      if (!doc.last) {
        var end = -1, wall = Date.now() / 1000;
        fresh.forEach(function (n, i) { if (n.voice !== 'person' && n.state === 'done' && !n.pod) end = i; });
        fresh = fresh.slice(end + 1);
        if (!(d.calls || []).length && !fresh.some(function (n) { return wall - n.at < 120; })) fresh = [];
        fresh = fresh.filter(function (n) { return newest - n.at < 900; }).slice(-18);
      }
      fresh.forEach(function (n) {
        if (n.voice === 'person') {      // somebody else in this view said it: yours was shown the moment you sent it
          if (!doc.mine[n.n] && doc.last) toast(n.who + ' to the doctor: ' + n.text);
          return;
        }
        doc.notes.push(n); doc.queue.push(n);
      });
      doc.notes = doc.notes.slice(-40); doc.calls = d.calls || []; doc.last = d.last || doc.last;
      chatDraw();
    }).catch(function () { /* the next round asks again */ }).then(function () { docTimer = setTimeout(doctorPoll, 2500); });
  }
  /* What calling (or speaking) brought. The portal sends Claude itself when
     the person has a Claude account connected; otherwise the call waits for an
     AI client connected over MCP, and the line says how to need neither. */
  function arrival(d, h) {
    var limits = h.may_change ? '' : ' It may examine, but not operate: ' + h.why + '.';
    if (d.doctor === 'portal') return (d.arrival === 'here' ? 'Claude is already here.' : 'Claude is on the way.') + limits;
    if (h.clients) return 'The call is waiting for your connected AI client. To have Claude come by itself, ' + d.how + '.' + limits;
    return 'Nobody can answer yet: ' + d.how + '.';
  }
  function callDoctor(key) {
    var r = key && !key.indexOf('pod:') ? ix.ref[key] : null;
    function tell(text) { toast(text); if (talk) talkShow(text); }
    fetch('/clusters/3d/doctor.json', { method: 'POST', credentials: 'same-origin', headers: { Accept: 'application/json' },
      body: new URLSearchParams({ project: QS.get('project'), cluster: QS.get('cluster'), pod: r ? r.ns + '/' + r.name : '', problem: r ? (r.problem || r.phase) : '' }) })
      .then(function (res) { return res.json(); })
      .then(function (d) {
        if (!d.ok) { tell('The call was refused: ' + d.message); return; }
        var h = d.hands || { clients: 1, may_change: true, why: '' }; doc.via = d.doctor || doc.via; doc.how = d.how || '';
        doc.on = true; doc.hands = h; doctorPoll();
        // said now, not after the wait: a doctor that may only look is still worth calling, and worth knowing about
        tell(arrival(d, h));
      }).catch(function () { tell('The portal did not answer'); });
  }
  /* T: say something to whoever is being the doctor. The line goes to the
     portal as words (it changes nothing), the connected client hears it over
     MCP and answers with a note, which is drawn like every other. */
  function sayOpen() {
    if (!walk || talk) return;
    if (locked()) document.exitPointerLock();
    // If the doctor is waiting on an answer, its question is shown over the
    // field with whatever answers it offered: a key each, while nothing is typed.
    var q = doc.asked, ask = $('c3dSayAsk'), box = $('c3dSayOpts');
    ask.hidden = !q; ask.textContent = q ? q.who + ' asks you: ' + q.text : '';
    clear(box); box.hidden = !(q && (q.choices || []).length);
    (q && q.choices || []).forEach(function (text, i) {
      var b = el('button', 'c3d-opt'); b.type = 'button';
      b.appendChild(el('kbd', '', String(i + 1))); b.appendChild(el('span', '', text));
      b.addEventListener('click', function () { sayClose(true); saySend(text); });
      box.appendChild(b);
    });
    $('c3dSayText').placeholder = q ? 'Or type your answer…   Enter sends · Esc closes' : 'Say something to the doctor…   Enter sends · Esc closes';
    keys = {}; $('c3dSay').hidden = false; stage.classList.add('saying'); $('c3dSayText').value = ''; $('c3dSayText').focus();
  }
  function sayClose(again) {
    if ($('c3dSay').hidden) return;
    $('c3dSay').hidden = true; stage.classList.remove('saying'); cv.focus({ preventScroll: true });
    if (again && walk) grab();
  }
  function saySend(text) {
    var r = walk && walk.near && !walk.near.indexOf('pod:') ? ix.ref[walk.near] : null;
    fetch('/clusters/3d/doctor.json', { method: 'POST', credentials: 'same-origin', headers: { Accept: 'application/json' },
      body: new URLSearchParams({ project: QS.get('project'), cluster: QS.get('cluster'), say: text, pod: r ? r.ns + '/' + r.name : '' }) })
      .then(function (res) { return res.json(); })
      .then(function (d) {
        if (!d.ok) { toast('That was not sent: ' + d.message); return; }
        var h = d.hands || { clients: 1, may_change: true, why: '' }; doc.via = d.doctor || doc.via; doc.how = d.how || '';
        doc.on = true; doc.hands = h; doc.mine[d.note.n] = 1; doc.me = d.note.who; doc.you = { n: d.note, at: performance.now() / 1000 }; doc.asked = null; doctorPoll();
        // a goodbye answered to a doctor that has just left calls nobody back
        if (d.parting) { doc.asked = null; return; }
        if (d.arrival === 'started') toast('Claude is on the way.');
        else if (d.doctor !== 'portal' && !docHere()) toast(arrival(d, h));
      }).catch(function () { toast('The portal did not answer'); });
  }
  /* The conversation with the doctor, kept on screen like the chat of a game.
     A bubble is gone in seconds, so an answer you looked away from was an
     answer you never got, and nothing showed what had been said before. It
     takes no clicks (T is how you speak) and is redrawn only when it changes. */
  function chatDraw() {
    var box = $('c3dChat'), rows = doc.log.slice(-9), last = rows[rows.length - 1], here = docHere();
    var waiting = doc.calls.length && (!last || last.voice === 'person');
    var sig = walk && !picking ? (last ? last.n : 0) + '|' + doc.calls.length + '|' + here + '|' + doc.me + '|' + doc.via : '';
    if (sig === doc.drawn) return;
    doc.drawn = sig; clear(box); box.hidden = !sig || (!rows.length && !doc.calls.length);
    if (box.hidden) return;
    box.appendChild(el('div', 'c3d-chat-head', 'Chat   ·   T talks to ' + (here ? docName() : 'the doctor')));
    rows.forEach(function (n) {
      var mine = n.voice === 'person' && (doc.mine[n.n] || n.who === doc.me);
      var row = el('div', 'c3d-chat-row ' + (n.voice === 'person' ? (mine ? 'me' : 'them') : n.voice === 'pod' ? 'pod' : 'doc'));
      row.appendChild(el('b', '', n.voice === 'person' ? (mine ? 'You' : n.who.split('@')[0]) : n.voice === 'pod' ? ((n.pod || '').split('/').pop() || 'a pod') : isClaude(n.who) ? 'Claude' : n.who));
      row.appendChild(el('span', '', n.text));
      box.appendChild(row);
    });
    // a call the portal itself answers is a doctor thinking; one that waits for an
    // AI client somewhere else may wait for ever, and saying "thinking" hid that
    if (waiting) box.appendChild(el('div', 'c3d-chat-row wait', doc.via === 'mcp'
      ? 'Waiting for an AI client connected over MCP to answer.' + (doc.how ? ' To have Claude come by itself, ' + doc.how + '.' : '')
      : 'The doctor is thinking…'));
  }
  /* The visit is played one line at a time, however the lines arrived: a
     question stays up long enough to be read before its answer appears. A
     question put to a pod that whoever is the doctor does not answer for it is
     answered by the pod itself, from its own row (plea()). */
  function hold(n) { return clamp(1.8 + n.text.length / 20, 2.6, 9); }
  function docStep(now) {
    var cur = doc.cur, next = doc.queue[0], n, it;
    if (cur && now - cur.at < hold(cur.n)) return;
    if (cur && cur.n.state === 'asking' && cur.n.pod && !cur.answered) {
      if (next && next.voice === 'pod' && next.pod === cur.n.pod) cur.answered = true;
      else if (next || now - cur.at > hold(cur.n) + 3) {
        cur.answered = true;
        if (ix.ref['pod:' + cur.n.pod]) doc.queue.unshift({ voice: 'pod', pod: cur.n.pod, state: '', who: '', text: plea('pod:' + cur.n.pod, ix, data.techs || {}) });
      }
    }
    if (!doc.queue.length) return;
    n = doc.queue.shift(); it = n.pod && items['pod:' + n.pod];
    doc.cur = { n: n, at: now }; doc.at = now;
    if (n.voice === 'pod') { doc.pod = doc.cur; if (it) it.flash = now; return; }
    if (doc.say && doc.say.n.pod !== n.pod) doc.pod = null;      // it has moved on to somebody else
    doc.say = doc.cur;
    // A question with no pod is put to YOU. The field opens for the answer,
    // unless the visit has already moved past it or you are busy talking.
    doc.asked = n.state === 'asking' && !n.pod && !doc.queue.length ? n : null;
    if (doc.asked && walk && !talk && $('c3dSay').hidden) sayOpen();
    if (it && it.ax != null) { if (n.state === 'healed') burst(it, TONEF.ok); else if (n.state === 'failed') burst(it, TONEF.bad); }
    if (n.state === 'treating' || n.state === 'healed') poll(true);
  }
  /* A goodbye is a goodbye. Once the doctor's `done` has been up long enough
     to read, it goes back up the way it came and is gone. It used to stand
     beside you for a minute and a half after saying it was leaving, and
     followed you while it stood: "I told him bye, but he is stuck here with
     me". */
  var LEAVE = 1.5;
  function docLeaving(now) {
    var s = doc.say, n = s && s.n;
    return n && n.state === 'done' && !n.pod && !doc.queue.length ? now - s.at - hold(n) : -1;
  }
  function doctorDraw(t) {
    var now = performance.now() / 1000;
    if (data) docStep(now);
    var n = doc.say && doc.say.n, bye = docLeaving(now);
    if (n && bye > (calm ? 0 : LEAVE)) {
      if (doc.placed && walk) toast(docName() + ' has left.  H or T calls the doctor back.');
      doc.sv = null; doc.placed = false; return;
    }
    if (!n || now - doc.at > 90) { doc.sv = null; doc.placed = false; return; }      // it has not been heard from for a while: it has gone
    var it = n.pod && items['pod:' + n.pod], tx, tz, ty = 0.5, here = it && it.ax != null;
    if (here) { tx = it.ax + 0.95; tz = it.az + 0.35; ty = it.gy; } else if (walk && bye < 0) { tx = walk.x + 1.2; tz = walk.z - 0.6; } else { tx = doc.x; tz = doc.z; }      // saying goodbye, it stops following you
    if (!doc.placed) { doc.x = tx; doc.z = tz; doc.y = ty + (calm ? 0 : 9); doc.placed = true; }      // it comes down out of the sky
    doc.x += (tx - doc.x) * 0.07; doc.z += (tz - doc.z) * 0.07;
    if (bye > 0) doc.y = ty + 11 * Math.pow(bye / LEAVE, 2); else doc.y += (ty - doc.y) * 0.07;
    // it looks at whoever it is speaking to: its patient, or you
    var bob = calm ? 0 : Math.abs(Math.sin(t * 2.2)) * 0.07, dy = doc.y + bob, going = Math.hypot(tx - doc.x, tz - doc.z) > 0.25;
    var face = here ? Math.atan2(it.ax - doc.x, it.az - doc.z) : walk ? Math.atan2(walk.x - doc.x, walk.z - doc.z) : 0;
    if (isClaude(n.who)) claude(doc.x, doc.y - 0.47, doc.z, face, t, n.state === 'failed', going);
    else {
      orb(doc.x, dy, doc.z, 0.47, DOCC, 1, face, 0, n.state === 'failed' ? 2 : 0, 0.61, 2, -1, 1, 0);
      spr(doc.x, dy + 0.86, doc.z, 0.3, M.cross, 1, 0);
    }
    glo(doc.x + fx * 0.6, dy + fy * 0.6, doc.z + fz * 0.6, 1.5, DOCC, walk ? 1.6 : 0.6);
    shad(doc.x, doc.z, 0.52, 0.5 * clamp(1 - (doc.y - ty) / 5, 0, 1));
    if (doc.y - ty > 0.4) beam(doc.x, doc.y, doc.z, doc.x, doc.y + 16, doc.z, DOCC, 0.55, 0.18, 0, 1, 0.8, 3, 0);
    if (here && !calm) {
      if (n.state === 'treating' || n.state === 'examining') beam(doc.x, dy + 0.2, doc.z, it.ax, it.ay, it.az, n.state === 'treating' ? TONEF.ok : DOCC, 0.9, 0.05, 0, 1, 1.4, 3, 0);
      // a question runs to the pod, and its answer runs back
      else if (doc.cur === doc.pod && doc.pod.n.pod === n.pod) beam(it.ax, it.ay + 0.3, it.az, doc.x, dy + 0.3, doc.z, TONEF[it.ref.tone] || DOCC, 0.6, 0.025, 0, 1, 1.8, 6, 0);
      else if (n.state === 'asking') beam(doc.x, dy + 0.3, doc.z, it.ax, it.ay + 0.3, it.az, DOCC, 0.6, 0.025, 0, 1, 1.8, 6, 0);
    }
    doc.sv = view(doc.x, dy + 1.25, doc.z);
  }

  /* ── souls ───────────────────────────────────────────────────────────
     On foot, what is near you mutters: one fact each, off its own row
     (murmurs()), so the place sounds alive without one invented word. A line
     that names another Service is answered by a pod standing behind it. */
  var chatter = [], chatAt = 0, chatN = 0, CHAT = 4.4;
  function chatterStep(t) {
    var i, o, d, key, lines, line, back, pool = [], busy = {};
    for (i = chatter.length - 1; i >= 0; i--) if (t - chatter[i].at > CHAT) chatter.splice(i, 1);
    if (t < chatAt || chatter.length >= 2 || talk) return;
    chatAt = t + 1.3 + Math.random() * 1.7;
    chatter.forEach(function (c) { busy[c.key] = 1; });
    if (doc.say && doc.say.n.pod && t - doc.at < 90) busy['pod:' + doc.say.n.pod] = 1;      // it is being examined: let it speak there
    for (i = 0; i < list.length; i++) {
      o = list[i]; if (o.dead || o.dim || o.ax == null || busy[o.key] || o.pr < 9) continue;
      d = Math.hypot(o.ax - walk.x, o.az - walk.z);
      if (d > 9 || d < 0.9 || o.sx < 60 || o.sx > W - 60 || o.sy < 110 || o.sy > H - 150) continue;      // only who you can see
      pool.push(o.key); if (o.kind === 'pod' && o.ref.tone === 'bad') pool.push(o.key, o.key);      // the ones in trouble speak up more
    }
    if (!pool.length) return;
    key = pool[Math.floor(Math.random() * pool.length)];
    lines = murmurs(key, ix, data.techs || {}); line = lines[(chatN++ + hash(key)) % (lines.length || 1)];
    if (!line) return;
    chatter.push({ key: key, text: line.text, at: t });
    back = line.to && ((ix.ref['svc:' + line.to] || {}).pods || []).filter(function (id) {
      var q = items['pod:' + id]; return q && 'pod:' + id !== key && !q.dead && !q.hid && q.ax != null && Math.hypot(q.ax - walk.x, q.az - walk.z) < 14;
    })[0];
    if (back) chatter.push({ key: 'pod:' + back, from: key, text: (ix.ref[key].workload || ix.ref[key].name) + ' names me in its settings.', at: t + 1.4 });
  }
  function whisper(x, y, text, tone, a) {
    var lines = [], cur = '', wide = 0;
    text.split(' ').forEach(function (w) { if ((cur + ' ' + w).trim().length > 32) { lines.push(cur); cur = w; } else cur = (cur + ' ' + w).trim(); });
    if (cur) lines.push(cur);
    g.font = 'italic 500 12px ' + FONT; lines.forEach(function (l) { wide = Math.max(wide, g.measureText(l).width); });
    var w = wide + 20, h = lines.length * 15 + 11, x0 = clamp(x - w / 2, 8, W - w - 8), y0 = Math.max(8, y - h - 12), c = TONE[tone] || TONE.ok;
    g.globalAlpha = a * 0.86; g.fillStyle = 'rgb(9,14,32)'; g.beginPath();
    if (g.roundRect) g.roundRect(x0, y0, w, h, 10); else g.rect(x0, y0, w, h);
    g.fill(); g.lineWidth = 1; g.strokeStyle = rgba(c, 0.55); g.stroke();
    g.beginPath(); g.arc(x, y0 + h + 4, 2.4, 0, TAU); g.arc(x, y0 + h + 9, 1.4, 0, TAU); g.fill();      // a thought, not a speech
    g.globalAlpha = a; g.fillStyle = '#e6ecff'; g.textAlign = 'left'; g.textBaseline = 'alphabetic';
    lines.forEach(function (l, i) { g.fillText(l, x0 + 10, y0 + 18 + i * 15); });
    g.globalAlpha = 1;
  }

  /* ── walking ─────────────────────────────────────────────────────────
     The same world from the floor: you are a small figure on the islands, the
     camera follows behind (or sits in your eyes, scrolled all the way in), and
     the keys move you. Nothing here reads the cluster or changes it: walking
     up to a pod and pressing E opens the same card a click does.

     The mouse is captured only while the browser allows it. Where it does not
     (an embedded pane, a refused prompt) dragging still looks around, so the
     mode never depends on the lock. */
  var walk = null, keys = {}, HINT = $('c3dHint').textContent;
  var YOU = [0.93, 0.97, 1.0], PATH = [0.35, 0.85, 1.0];
  function islandAt(x, z) {
    for (var i = 0; i < lay.plats.length; i++) { var p = lay.plats[i]; if (x >= p.x && x <= p.x + p.w && z >= p.z && z <= p.z + p.d) return p; }
    return null;
  }
  function needy() { return (data.pods || []).filter(function (p) { return p.tone === 'bad' || p.tone === 'warn'; }); }
  function locked() { return document.pointerLockElement === cv; }
  function grab() {
    function refused() { if (walk) walk.nolock = true; }
    try { var asked = cv.requestPointerLock(); if (asked && asked.catch) asked.catch(refused); } catch (e) { refused(); }
  }
  function enterWalk() {
    if (!data || walk) return;
    if (touring) tour(false);
    var at = (selKey && where(selKey)) || null, pl = lay.plats.filter(function (p) { return p.count; })[0] || lay.plats[0];
    if (!at) at = { x: pl.x + pl.w / 2 - 1.1, z: pl.z + pl.d - 1.9 };
    walk = { x: at.x + 1.1, y: 0, z: at.z + 1.1, was: 0, face: 0, dist: 4.6, seen: {}, isle: undefined, banner: null, say: null, near: '', trail: [], step: 0, riding: false };
    focusNs = ''; toneOnly = ''; found = null; $('c3dSearch').value = ''; $('c3dFound').textContent = ''; select('', false); hud();
    game = { start: performance.now() / 1000, acts: 0, sick0: needy().length, won: 0, line: '' };
    doc.on = true; doctorPoll();
    stage.classList.add('walk'); $('c3dWalk').textContent = 'Leave walk'; $('c3dWalk').setAttribute('aria-pressed', 'true');
    $('c3dHint').textContent = 'W A S D move · Shift faster · V ride · Space up, C down · E talk · 1 2 3 hand, weapon, medkit · G next weapon · F use · H doctor · T chat · P character · B dance, or your move · Esc leaves';
    $('c3dHint').className = 'c3d-hint';
    goal.pitch = 0.4; goal.dist = walk.dist;
    cv.focus({ preventScroll: true }); pickOpen(true);
  }
  /* The way in: who you are and what you ride. You turn on the spot while you
     choose, so the choice is looked at rather than read. Arrow keys or a
     click; Enter starts. P opens it again. */
  var pk = null;
  function pickOpen(first) {
    if (!walk || talk || fin) return;
    sayClose(false);
    // The line-up stands on a stage of its own, high over where you will land:
    // down among the pods there is no room for eight figures side by side.
    pickAt(walk.x, 12, walk.z, first, { quit: leaveWalk, done: function (was) {
      if (was) { walk.y = pk.y - 0.4; walk.was = walk.y; }      // you come down from the stage into the cluster
      walk.riding = me.ride > 0; walk.dist = RIDES[me.ride].dist;
      toast(HEROES[me.hero].name + (me.ride ? ' on a ' + RIDES[me.ride].name.toLowerCase() : '') + ' enters the cluster. T talks to the doctor, H calls it');
      chatDraw(); grab(); cv.focus({ preventScroll: true });
    } });
    chatDraw();
  }
  /* The chooser itself belongs to nobody's walk: it is given a place to stand
     its stage and whoever opened it (`host`), and tells them when a choice is
     made (`done`) or the whole thing is walked away from (`quit`). A cluster
     opens it, and so does the city, so that you choose who you are the same
     way wherever you come in. */
  function pickAt(x, y, z, first, host) {
    if (locked()) document.exitPointerLock();
    pk = { x: x, y: y, z: z, turn: me.hero * TAU / HEROES.length, since: performance.now() / 1000, pitch: goal.pitch, first: !!first, host: host };
    picking = true; keys = {}; $('c3dPick').hidden = false; stage.classList.add('picking'); pickDraw();
  }
  /* Where the camera looks while you choose: at the line-up, on whoever is
     chosen, as the ring comes round to them. */
  function pickAim(dt) {
    pk.turn += turn(me.hero * TAU / HEROES.length - pk.turn) * Math.min(1, dt * 7);
    goal.tx = pk.x; goal.tz = pk.z; goal.dist = 5.6; goal.pitch = 0.1;
    // the panel covers the foot of the stage: aim lower by half its height, and the figures stand clear above it
    goal.ty = pk.y + 0.95 - $('c3dPick').offsetHeight / 2 * goal.dist / F;
  }
  /* Everybody you could be stands on a ring that turns to bring the one you
     chose to the front, into the light, where it does its own move. Seeing
     them is the point: a row of names told you nothing about a wizard. */
  function pickScene(t) {
    var n = HEROES.length, R = 3.0, yaw = goal.yaw, cx = pk.x - Math.sin(yaw) * R, cz = pk.z - Math.cos(yaw) * R, i, a, near, r, x, z, u;
    solid(BALL, cx, pk.y - 0.12, cz, R * 2 + 4.2, 0.2, R * 2 + 4.2, [0.035, 0.045, 0.085], 0, yaw, 0, 0);
    solid(BALL, cx, pk.y - 0.05, cz, R * 2 + 1.6, 0.1, R * 2 + 1.6, [0.06, 0.08, 0.15], 0, yaw, 0, 0);
    for (i = 0; i < n; i++) {
      a = i * TAU / n - pk.turn; near = Math.pow(Math.max(0, Math.cos(a)), 6); r = R + near * 0.75;      // whoever is chosen steps out to you
      x = cx + r * Math.sin(a + yaw); z = cz + r * Math.cos(a + yaw);
      solid(BALL, x, pk.y, z, 1.15, 0.1, 1.15, i === me.hero ? PATH : [0.1, 0.13, 0.22], i === me.hero ? 0.55 : 0, a + yaw, 0, 0);
      u = i === me.hero ? ((t - pk.since) % 3.3) / 2.3 : 2;      // its move, then a breath, then again
      person(x, pk.y + 0.04, z, a + yaw, t, { hero: i, pose: 0, step: 0, moving: false, hold: '', emote: u <= 1 ? i : null, eu: u });
      shad(x, z, 0.4, 0.3);
      if (i === me.hero) {
        beam(x, pk.y + 0.1, z, x, pk.y + 10, z, PATH, 0.3, 0.55, 0, 1, 0.5, 2, 0);
        glo(x, pk.y + 1.0, z, 2.8, PATH, 0.55);
        // what it will ride stands beside it, turning to be looked at
        if (me.ride) rideDraw(stand(x + Math.cos(yaw) * 1.9, pk.y + 0.04, z - Math.sin(yaw) * 1.9, t * 0.7), me.ride, t, false);
      }
    }
  }
  function pickClose() {
    if (!picking) return;
    picking = false; keep(); $('c3dPick').hidden = true; stage.classList.remove('picking');
    goal.pitch = pk.pitch; pk.host.done(pk.first);
  }
  function pickKey(k) {
    if (k === 'ArrowLeft' || k === 'a') { me.hero = (me.hero + HEROES.length - 1) % HEROES.length; pk.since = performance.now() / 1000; }
    else if (k === 'ArrowRight' || k === 'd') { me.hero = (me.hero + 1) % HEROES.length; pk.since = performance.now() / 1000; }
    else if (k === 'ArrowUp' || k === 'w') me.ride = (me.ride + RIDES.length - 1) % RIDES.length;
    else if (k === 'ArrowDown' || k === 's') me.ride = (me.ride + 1) % RIDES.length;
    else if (k === 'Enter' || k === ' ') { pickClose(); return; }
    else if (k === 'Escape') { pk.host.quit(); return; }
    else if (k === 'm') { me.mute = !me.mute; keep(); }
    else return;
    sfx('tick'); pickDraw();
  }
  function pickDraw() {
    var box = $('c3dPick'), foot = el('div', 'c3d-pick-foot'), go = el('button', 'c3d-btn c3d-go', 'Start');
    function row(list, at, set) {
      var wrap = el('div', 'c3d-pick-row');
      list.forEach(function (o, i) {
        var b = el('button', 'c3d-opt' + (i === at ? ' on' : '')); b.type = 'button';
        b.appendChild(el('span', '', o.name)); if (o.speed > 1) b.appendChild(el('em', '', '×' + o.speed));
        b.title = o.line; b.setAttribute('aria-pressed', i === at ? 'true' : 'false');
        b.addEventListener('click', function () { set(i); pickDraw(); });
        wrap.appendChild(b);
      });
      box.appendChild(el('div', 'c3d-pick-title', list[at].name + '   ·   ' + list[at].line)); box.appendChild(wrap);
    }
    clear(box);
    box.appendChild(el('div', 'c3d-pick-head', 'Choose your engineer, and your ride'));
    row(HEROES, me.hero, function (i) { me.hero = i; pk.since = performance.now() / 1000; });
    row(RIDES, me.ride, function (i) { me.ride = i; });
    go.type = 'button'; go.addEventListener('click', pickClose);
    foot.appendChild(el('span', '', '←  →  character   ·   ↑  ↓  ride   ·   M  sound ' + (me.mute ? 'off' : 'on') + '   ·   Enter starts')); foot.appendChild(go);
    box.appendChild(foot);
  }
  function mount() {
    if (!me.ride) { toast('You came on foot. P chooses a ride'); return; }
    walk.riding = !walk.riding; walk.dist = walk.riding ? RIDES[me.ride].dist : 4.6;
    toast(walk.riding ? 'On the ' + RIDES[me.ride].name.toLowerCase() + '. Shift goes faster' : 'On foot again. V gets back on');
  }
  function leaveWalk() {
    if (!walk) return;
    talkClose(); sayClose(false); danceEnd(true); walk = null; keys = {}; armed = null; tool = 0; game = null; chatter.length = 0; doc.on = doc.calls.length > 0;
    if (picking && pk) goal.pitch = pk.pitch;
    picking = false; $('c3dPick').hidden = true; fin = null; verdict = null; feed.length = 0; stage.classList.remove('picking', 'fin'); chatDraw();
    stage.classList.remove('walk'); $('c3dWalk').textContent = 'Walk'; $('c3dWalk').setAttribute('aria-pressed', 'false');
    if (locked()) document.exitPointerLock();
    $('c3dHint').textContent = HINT; select('', false); home(false);
    if (fromCity) toStreet();
  }
  /* Back out of the door you came in by. */
  function toStreet() { location.href = '/clusters/city?at=' + encodeURIComponent(QS.get('cluster') || ''); }
  /* The doctor is in the picture: it has spoken in the last minute and a half
     and is drawn. While it is, talking to it is offered on screen. */
  function docHere() { var now = performance.now() / 1000; return !!(doc.say && doc.placed && now - doc.at < 90 && docLeaving(now) <= 0); }
  function docName() { return doc.say && isClaude(doc.say.n.who) ? 'Claude' : 'the doctor'; }
  function interact() {
    if (!walk || !walk.near || talk) return;
    var k = walk.near, r = ix.ref[k], now = performance.now() / 1000;
    if (k.indexOf('plat:')) {
      if (!r) return;
      select(k, false);
      if (!k.indexOf('pod:') && (r.tone === 'bad' || r.tone === 'warn')) walk.seen[k] = 1;
      if (items[k]) items[k].flash = now;
    }
    talkOpen(k);
  }
  function walkStep(t, dt) {
    var mx = (keys.d || keys.ArrowRight ? 1 : 0) - (keys.a || keys.ArrowLeft ? 1 : 0), mz = (keys.w || keys.ArrowUp ? 1 : 0) - (keys.s || keys.ArrowDown ? 1 : 0);
    // the chooser is open: you turn on the spot to be looked at, and go nowhere
    if (picking) { walk.moving = false; pickAim(dt); return; }
    if (walk.dash) {      // closing on a pod with a hand weapon
      var du = (t - walk.dash.at) / walk.dash.dur, de = ease(du);
      walk.x = walk.dash.x0 + (walk.dash.x1 - walk.dash.x0) * de; walk.z = walk.dash.z0 + (walk.dash.z1 - walk.dash.z0) * de; walk.step += dt * 11;
      if (du >= 1) walk.dash = null;
    }
    if (fin) {
      // The camera leaves your shoulder for the side: you and the pod face to
      // face across the picture, the way a fighting game frames its two. From
      // behind you, your own head was most of the shot.
      var fa = t - fin.at, sh = fin.hit && t - fin.hit < 0.35 ? 0.16 : 0, into = ease(fa / 0.45);
      var side = Math.atan2(walk.x - fin.x, walk.z - fin.z) + PI / 2, sep = Math.hypot(walk.x - fin.x, walk.z - fin.z);
      if (Math.abs(turn(side - fin.yaw)) > PI / 2) side -= PI;      // whichever side is the shorter way round
      walk.moving = false; if (!walk.move) walk.face = Math.atan2(fin.x - walk.x, fin.z - walk.z);
      goal.tx = (walk.x + fin.x) / 2 + (Math.random() - 0.5) * sh; goal.ty = fin.y + 0.2 + (Math.random() - 0.5) * sh; goal.tz = (walk.z + fin.z) / 2;
      goal.dist = clamp(sep * 0.9 + 3, 3.6, 7.5); goal.yaw = fin.yaw + turn(side - fin.yaw) * into + fa * 0.05; goal.pitch = fin.pitch + (0.16 - fin.pitch) * into;
      return;
    }
    if (dance) {
      var pal = items[dance.key], since = t - dance.at;
      if (pal && pal.ax != null) {
        walk.moving = false; walk.v = 0; walk.face = Math.atan2(pal.gx - walk.x, pal.gz - walk.z);
        goal.tx = (walk.x + pal.gx) / 2; goal.ty = walk.y + 1.0; goal.tz = (walk.z + pal.gz) / 2;
        goal.dist = clamp(Math.hypot(walk.x - pal.gx, walk.z - pal.gz) * 0.9 + 3.8, 4.4, 7.5);
        goal.yaw = dance.yaw + (calm ? 0 : since * 0.42); goal.pitch = dance.pitch + (0.2 - dance.pitch) * ease(since / 0.6);
      }
      return;
    }
    var sy = Math.sin(goal.yaw), cy = Math.cos(goal.yaw), len = Math.hypot(mx, mz) || 1;
    // a ride is a pace, and Shift pushes it: on foot it is a run
    var sp = 4.6 * (walk.riding ? RIDES[me.ride].speed * (keys.Shift ? 1.5 : 1) : keys.Shift ? 1.96 : 1);
    var vx = (cy * mx - sy * mz) / len * sp, vz = (-sy * mx - cy * mz) / len * sp;
    walk.x += vx * dt; walk.z += vz * dt;
    walk.moving = !!(mx || mz); walk.v = walk.moving ? sp : 0;
    if (walk.moving) { walk.face = Math.atan2(vx, vz); walk.step += dt * sp; }
    var lim = Math.max(lay.w, lay.d) / 2 + 14; walk.x = clamp(walk.x, -lim, lim); walk.z = clamp(walk.z, -lim, lim);
    var up = keys[' '] ? 1 : 0, dn = keys.c ? 1 : 0, pl = islandAt(walk.x, walk.z);
    if (up || dn) walk.y += (up - dn) * 5.5 * dt; else walk.y += (0 - walk.y) * Math.min(1, dt * 1.8);
    walk.y = clamp(walk.y, -7, 12);
    if (pl) {      // an island is solid: you stand on it from above and stop under it from below
      if (walk.was >= 0 && walk.y < 0) walk.y = 0;
      else if (walk.was <= -(TH + 1.1) && walk.y > -(TH + 1.1)) walk.y = -(TH + 1.1);
    }
    walk.was = walk.y;
    // pods are solid too, and the nearest thing within reach is the one E talks to
    var best = '', bd = 2.6, key, it, dx, dz, dy, d, reach;
    for (key in items) {
      it = items[key]; if (it.dead || it.hid || it.ax == null) continue;
      dx = walk.x - it.ax; dz = walk.z - it.az; dy = walk.y + 0.45 - it.ay; d = Math.hypot(dx, dz);
      if (it.kind === 'pod' && Math.abs(dy) < 0.85 && d < 0.95 && d > 1e-4) { walk.x += dx / d * (0.95 - d); walk.z += dz / d * (0.95 - d); }
      reach = Math.hypot(d, dy); if (reach < bd) { bd = reach; best = key; }
    }
    lay.plats.forEach(function (q) {      // and a machine's core can be talked to as well
      var cd = Math.hypot(walk.x - q.x - 0.1, walk.z - q.z - 0.1);
      if (q.node && Math.abs(walk.y) < 2 && cd < 2 && cd < bd) { bd = cd; best = 'plat:' + q.key; }
    });
    walk.near = best;
    // the doctor standing beside you is somebody E talks to as well, before any pod further off
    walk.doc = docHere() && Math.hypot(walk.x - doc.x, walk.z - doc.z) < Math.min(2.6, bd + 0.4);
    if (talk) {      // walking away ends the conversation
      var who = items[talk.key], wp = who ? [who.ax, who.az] : (function (q) { return q ? [q.x, q.z] : null; })(lay.plats.filter(function (q) { return 'plat:' + q.key === talk.key; })[0]);
      if (!wp || Math.hypot(walk.x - wp[0], walk.z - wp[1]) > 6) { talkClose(); select('', false); }
    }
    var said = walk.say && items[walk.say.key];
    if (walk.say && (t - walk.say.at > 9 || !said || Math.hypot(walk.x - said.ax, walk.z - said.az) > 5)) { if (selKey === walk.say.key) select('', false); walk.say = null; }
    // the name of the island you have just stepped onto, like the name of a level
    var name = pl ? pl.key : null;
    if (name !== walk.isle) { walk.isle = name; if (pl) walk.banner = { pl: pl, at: t }; }
    // off the islands a path of light forms under your feet
    if (!pl && Math.abs(walk.y) < 0.3) {
      var tail = walk.trail[walk.trail.length - 1];
      if (!tail || Math.hypot(tail.x - walk.x, tail.z - walk.z) > 0.8) walk.trail.push({ x: walk.x, z: walk.z, at: t });
    }
    while (walk.trail.length && t - walk.trail[0].at > 4) walk.trail.shift();
    goal.tx = walk.x; goal.ty = walk.y + 1.2; goal.tz = walk.z; goal.dist = walk.dist;
  }
  function walkDraw(t) {
    var cy2 = walk.y + 0.44 + (calm ? 0 : Math.abs(Math.sin(walk.step * 1.6)) * 0.09);
    if (picking) { pickScene(t); return; }
    if (cam.dist > 1.1) {      // scrolled all the way in, you are looking out of its eyes
      var on = walk.riding ? me.ride : 0, act = walk.act && { how: walk.act.how, name: walk.act.w.name, u: (t - walk.act.at) / walk.act.dur }, mv = walk.move && (t - walk.move.at) / walk.move.dur;
      if (act && act.u > 1.35) { walk.act = act = null; if (walk.remount) { walk.riding = true; walk.remount = false; } }
      if (mv > 1) walk.move = mv = null;
      // what is in your hand: the weapon you carry, gone from it once thrown
      var hold = act ? (act.how === 'throw' && act.u > RELEASE ? '' : walk.act.w.name) : fin && !fin.hit ? fin.w.name : on ? '' : tool === 1 ? WEAPONS[me.weapon].name : tool === 2 ? 'Medkit' : '';
      if (on) rideDraw(stand(walk.x, walk.y, walk.z, walk.face), on, t, walk.moving);
      person(walk.x, walk.y + RIDES[on].sit - (RIDES[on].pose === 2 ? 0.18 : 0), walk.z, walk.face, t, { hero: me.hero, pose: RIDES[on].pose, step: walk.step, moving: walk.moving || !!walk.dash, run: !!keys.Shift || !!walk.dash,
        hold: dance ? '' : hold, ready: !!fin, act: act, emote: mv != null && mv >= 0 ? me.hero : null, eu: mv, dance: dance ? danceBeat(t) : null });
      if ((keys[' '] || walk.y > 2.5) && !calm) for (var j = 0; j < 4; j++) {      // rising, or coming down from above: light under your feet
        var fl = (t * 3 + j / 4) % 1;
        glo(walk.x, walk.y - 0.1 - fl * 0.9, walk.z, 0.5 * (1 - fl), HOTC, 1 - fl);
      }
      glo(walk.x + fx * 0.6, cy2 + fy * 0.6, walk.z + fz * 0.6, 1.5, PATH, 0.4);
      shad(walk.x, walk.z, on ? 0.8 : 0.4, 0.5 * clamp(1 - walk.y / 5, 0, 1));
    }
    glo(walk.x, walk.y + 0.05, walk.z, 1.9, PATH, 0.16);
    walk.trail.forEach(function (s) { cube(s.x, -0.03, s.z, 1.1, 0.04, 1.1, PATH, 0, 0, 0, 1 - (t - s.at) / 4, 1); });
    if (!islandAt(walk.x, walk.z) && Math.abs(walk.y) < 0.3) cube(walk.x, -0.03, walk.z, 1.5, 0.04, 1.5, PATH, 0, 0, 0, 1.4, 1);
    // a column of light over every pod that needs somebody and has not been visited
    needy().forEach(function (p, n) {
      var it = items['pod:' + p.id]; if (!it || walk.seen['pod:' + p.id] || it.ax == null) return;
      beam(it.ax, it.ay + 1.2, it.az, it.ax, it.ay + 16, it.az, p.tone === 'bad' ? TONEF.bad : TONEF.warn, 0.5, 0.16, 0, 1, 0.8, 3, n * 0.3);
    });
  }
  function bubble(x, y, text, who, o) {
    o = o || {};
    var lines = [], cur = '', wide = 0, lead = o.doctor ? 20 : 0, left = o.at != null && !calm ? Math.floor((performance.now() / 1000 - o.at) * 46) : 1e9;
    text.split(' ').forEach(function (w) { if ((cur + ' ' + w).trim().length > 38) { lines.push(cur); cur = w; } else cur = (cur + ' ' + w).trim(); });
    if (cur) lines.push(cur);
    g.font = '600 13px ' + FONT; lines.forEach(function (l) { wide = Math.max(wide, g.measureText(l).width); });
    g.font = '700 11px ' + FONT; wide = Math.max(wide, g.measureText(who).width + lead);
    // two speakers stand close: each one's words open away from the other
    var w = wide + 28, h = lines.length * 18 + 34, y0 = Math.max(8, y - h - 10);
    var x0 = clamp(o.side > 0 ? Math.max(x - 26, o.mid + 5) : o.side < 0 ? Math.min(x + 26, o.mid - 5) - w : x - w / 2, 8, W - w - 8), tx = clamp(x, x0 + 16, x0 + w - 16);
    g.globalAlpha = 0.96; g.fillStyle = o.doctor ? '#fff4ea' : o.you ? '#e9fbff' : o.tone === 'bad' ? '#fff1f2' : '#f4f7ff'; g.beginPath();
    if (g.roundRect) g.roundRect(x0, y0, w, h, 12); else g.rect(x0, y0, w, h);
    g.fill();
    if (o.tail !== false) { g.beginPath(); g.moveTo(tx - 8, y0 + h - 1); g.lineTo(tx + 8, y0 + h - 1); g.lineTo(tx, y0 + h + 9); g.closePath(); g.fill(); }
    g.textAlign = 'left'; g.textBaseline = 'alphabetic'; g.globalAlpha = 1;
    if (o.doctor) { g.save(); (isClaude(o.doctor) ? critter : cross)(g, x0 + 21, y0 + 15, 8); g.restore(); }
    g.font = '700 11px ' + FONT; g.fillStyle = o.doctor ? '#b0502a' : o.you ? '#1c7a94' : o.tone === 'bad' ? '#b3303f' : '#5a6a9a'; g.fillText(who, x0 + 14 + lead, y0 + 19);
    g.font = '600 13px ' + FONT; g.fillStyle = '#131a33';
    lines.forEach(function (l, i) { if (left > 0) g.fillText(l.slice(0, left), x0 + 14, y0 + 38 + i * 18); left -= l.length + 1; });
  }
  function minimap() {
    var size = 168, x0 = 16, y0 = H - size - 84, s = (size - 16) / (Math.max(lay.w, lay.d) + 12), cx = x0 + size / 2, cy = y0 + size / 2, key;
    plate(x0, y0, size, size, null, 0.9); g.globalAlpha = 1; g.lineWidth = 1;
    ink('MAP', x0 + 10, y0 + 11, 8.5, HUDC.dim, 'left', 800, 1.6);
    lay.plats.forEach(function (pl) { g.strokeStyle = pl.key === walk.isle ? '#ffffff' : 'rgba(120,160,255,.7)'; g.strokeRect(cx + pl.x * s, cy + pl.z * s, pl.w * s, pl.d * s); });
    for (key in items) {
      var it = items[key]; if (it.kind !== 'pod' || it.dead || it.hid) continue;
      var tone = it.ref.tone, r = (tone === 'bad' || tone === 'warn') && !walk.seen[key] ? 3.2 : 1.6;
      g.fillStyle = tone === 'bad' ? '#ff4d5e' : tone === 'warn' ? '#ffb020' : tone === 'idle' ? '#6b7690' : '#39d98a';
      g.fillRect(cx + it.x * s - r / 2, cy + it.z * s - r / 2, r, r);
    }
    g.save(); g.translate(clamp(cx + walk.x * s, x0 + 6, x0 + size - 6), clamp(cy + walk.z * s, y0 + 6, y0 + size - 6));
    g.rotate(Math.atan2(-Math.cos(goal.yaw), -Math.sin(goal.yaw)));      // you, pointing the way you are looking
    g.fillStyle = '#fff'; g.beginPath(); g.moveTo(7, 0); g.lineTo(-5, 4.5); g.lineTo(-5, -4.5); g.closePath(); g.fill(); g.restore();
  }
  /* ── the head-up display ─────────────────────────────────────────────
     Drawn the way a shooter draws its own: a compass with what needs you
     marked on it, the objective, a feed of what just happened, what you carry
     and whether it is live, and a reticle that knows what it is on. The look
     is this view's own, and every figure on it is read from the same data as
     the rest of the page: it tells you nothing the tabs would not. */
  var HUDC = { ink: '#f2f5f7', dim: 'rgba(242,245,247,.62)', amber: '#ffc857', red: '#ff4d5e', ok: '#3ddc97', glass: 'rgba(8,10,14,.62)' };
  function plate(x, y, w, h, accent, a) {
    var c = 8;
    g.globalAlpha = a == null ? 1 : a; g.beginPath();
    g.moveTo(x, y); g.lineTo(x + w - c, y); g.lineTo(x + w, y + c); g.lineTo(x + w, y + h); g.lineTo(x + c, y + h); g.lineTo(x, y + h - c); g.closePath();
    g.fillStyle = HUDC.glass; g.fill();
    if (accent) { g.fillStyle = accent; g.fillRect(x, y, 3, h - c); }
  }
  function ink(text, x, y, size, color, align, weight, gap) {
    g.font = (weight || 800) + ' ' + size + 'px ' + FONT; if ('letterSpacing' in g) g.letterSpacing = (gap || 0) + 'px';
    g.textAlign = align || 'left'; g.textBaseline = 'middle'; g.fillStyle = color; g.fillText(text, x, y);
    var wide = g.measureText(text).width; if ('letterSpacing' in g) g.letterSpacing = '0px';
    return wide;
  }
  function turn(a) { return Math.atan2(Math.sin(a), Math.cos(a)); }
  /* North is the far side of the scene. What still needs you sits on the strip
     at its bearing: red for failing, amber for a look, pale once visited. */
  function compass(all, cx, w) {
    var x0 = cx - w / 2, y = 10, half = 1.15, head = Math.atan2(fx, -fz), i, d, x, name;
    function at(bearing) { return cx + clamp(turn(bearing - head) / half, -1, 1) * (w / 2 - 6); }
    plate(x0 - 12, y, w + 24, 30, null, 0.92);
    for (i = 0; i < 24; i++) {      // a tick every 15 degrees, a letter every 45
      d = turn(i * PI / 12 - head); if (Math.abs(d) > half) continue;
      x = cx + d / half * (w / 2 - 6); name = i % 3 ? '' : ['N', 'NE', 'E', 'SE', 'S', 'SW', 'W', 'NW'][i / 3];
      g.globalAlpha = name ? 0.9 : 0.45; g.fillStyle = HUDC.ink; g.fillRect(x - 0.5, y + (name ? 19 : 22), 1, name ? 8 : 5);
      if (name) ink(name, x, y + 10, name.length === 1 ? 12 : 9, name === 'N' ? HUDC.amber : HUDC.ink, 'center', 800);
    }
    all.map(function (p) { var it = items['pod:' + p.id]; return it && it.ax != null ? [Math.hypot(it.ax - walk.x, it.az - walk.z), p, it] : null; })
      .filter(Boolean).sort(function (m, n) { return m[0] - n[0]; }).slice(0, 10).forEach(function (m) {
        x = at(Math.atan2(m[2].ax - walk.x, -(m[2].az - walk.z)));
        g.globalAlpha = walk.seen['pod:' + m[1].id] ? 0.4 : 1; g.fillStyle = m[1].tone === 'bad' ? HUDC.red : HUDC.amber;
        g.beginPath(); g.moveTo(x, y + 22); g.lineTo(x + 4, y + 26); g.lineTo(x, y + 30); g.lineTo(x - 4, y + 26); g.closePath(); g.fill();
      });
    if (docHere()) { x = at(Math.atan2(doc.x - walk.x, -(doc.z - walk.z))); g.globalAlpha = 1; g.fillStyle = '#e2794c'; g.fillRect(x - 3.5, y + 23, 7, 7); }
    g.globalAlpha = 1; g.fillStyle = HUDC.amber; g.beginPath(); g.moveTo(cx - 5, y - 2); g.lineTo(cx + 5, y - 2); g.lineTo(cx, y + 4); g.closePath(); g.fill();
  }
  function walkHud() {
    var t = performance.now() / 1000, all = needy(), done = all.filter(function (p) { return walk.seen['pod:' + p.id]; }).length;
    var won = game && game.won, i, row, wide, x, y, live = !!(tool && armed), near = walk.near && ix.ref[walk.near], pod = near && !walk.near.indexOf('pod:') && items[walk.near];
    // The top of the display has one centre line. On a narrow stage the cluster's
    // card reaches the middle, so the line moves to the middle of what is left.
    var top = document.querySelector('.c3d-top'), edge = top ? top.getBoundingClientRect().right - stage.getBoundingClientRect().left + 14 : 0;
    var cw = Math.min(520, W * 0.44, W - edge - 40), cx = Math.max(W / 2, edge + cw / 2 + 12);
    compass(all, cx, cw);
    // the objective, under the compass
    row = won ? 'CLUSTER HEALTHY' : !all.length ? 'NOTHING HERE NEEDS YOU' : all.length + ' POD' + (all.length === 1 ? ' NEEDS' : 'S NEED') + ' HELP   ·   ' + done + ' EXAMINED'
      + (doc.calls.length ? '   ·   DOCTOR CALLED' + (doc.hands && !doc.hands.may_change ? ' (MAY EXAMINE, NOT OPERATE)' : '') : '');
    var title = W - edge > 560 ? 'HEAL THE CLUSTER' : '';      // a narrow stage keeps the count
    g.font = '800 11px ' + FONT; wide = Math.min(W - edge - 16, g.measureText('OBJECTIVE   ' + title + '   ' + row).width + 64);
    x = clamp(cx - wide / 2, edge, W - wide - 8);
    plate(x, 46, wide, 22, won || !all.length ? HUDC.ok : HUDC.amber, 0.92); g.globalAlpha = 1;
    g.save(); g.beginPath(); g.rect(x, 46, wide - 8, 22); g.clip(); x += 14;
    x += ink('OBJECTIVE', x, 57.5, 9, HUDC.amber, 'left', 800, 1.5) + 12;
    if (title) x += ink(title, x, 57.5, 11, HUDC.ink, 'left', 800, 0.8) + 14;
    ink(row, x, 57.5, 11, won || !all.length ? HUDC.ok : HUDC.dim, 'left', 700, 0.8); g.restore();
    // what just happened, newest last, each fading out on its own
    for (i = 0, y = 76; i < feed.length; i++) {
      if (t - feed[i].at > feed[i].keep) continue;
      g.font = '700 11.5px ' + FONT; wide = Math.min(W - edge - 16, g.measureText(feed[i].text).width + 34);
      x = clamp(cx - wide / 2, edge, W - wide - 8);
      plate(x, y, wide, 22, feed[i].kind === 'kill' ? HUDC.red : feed[i].kind === 'heal' ? HUDC.ok : null, Math.min(1, (feed[i].keep - (t - feed[i].at)) * 2) * 0.95);
      g.save(); g.beginPath(); g.rect(x, y, wide - 8, 22); g.clip();
      ink(feed[i].text, x + 14, y + 11.5, 11.5, HUDC.ink, 'left', 700); g.restore();
      y += 26;
    }
    g.globalAlpha = 1;
    if (game && game.won) {
      g.globalAlpha = Math.min(1, (t - game.won) * 1.5); g.textAlign = 'center'; g.textBaseline = 'middle';
      g.fillStyle = '#eafff3'; g.font = '800 ' + Math.round(clamp(W * 0.05, 30, 72)) + 'px ' + FONT; g.shadowColor = 'rgba(61,220,151,.95)'; g.shadowBlur = 34;
      g.fillText('CLUSTER HEALTHY', W / 2, H * 0.36); g.shadowBlur = 0;
      g.font = '600 16px ' + FONT; g.fillStyle = '#cfe0ff'; g.fillText('You won ' + game.line, W / 2, H * 0.36 + 48); g.globalAlpha = 1;
    }
    if (walk.banner && t - walk.banner.at < 3.6) {
      var age = t - walk.banner.at, pl = walk.banner.pl, nd = pl.node;
      g.globalAlpha = Math.min(1, age * 3) * Math.min(1, (3.6 - age) * 1.5); g.textAlign = 'center'; g.textBaseline = 'middle';
      g.fillStyle = '#fff'; g.font = '800 ' + Math.round(clamp(W * 0.034, 22, 46)) + 'px ' + FONT; g.shadowColor = 'rgba(80,150,255,.9)'; g.shadowBlur = 24;
      g.fillText((pl.limbo ? 'the waiting room' : pl.key).toUpperCase(), W / 2, H * 0.2);
      g.shadowBlur = 0; g.font = '600 14px ' + FONT; g.fillStyle = '#cfe0ff';
      g.fillText(pl.count + ' pod' + (pl.count === 1 ? '' : 's') + (pl.bad ? ' · ' + pl.bad + ' failing' : '')
        + (nd && nd.cpu_pct != null ? ' · cpu ' + nd.cpu_pct + '%' : '') + (nd && nd.mem_pct != null ? ' · memory ' + nd.mem_pct + '%' : ''), W / 2, H * 0.2 + 34);
    }
    var near = walk.near && ix.ref[walk.near];
    if (doc.asked && $('c3dSay').hidden) {
      // a pod's talk window covers the bottom of the stage, so the question rides above it
      var sb = stage.getBoundingClientRect(), askY = talk ? Math.min(H - 186, $('c3dTalk').getBoundingClientRect().top - sb.top - 24) : H - 186;
      var askT = doc.asked.who + ' is waiting for your answer   ·   press T to answer', askX = W / 2, card = $('c3dCard');
      g.font = '700 11.5px ' + FONT;
      // on a narrow stage the pod's card would cover the end of it: "press T" is the part that matters
      if (card && !card.hidden) askX = Math.max(g.measureText(askT).width / 2 + 16, Math.min(askX, card.getBoundingClientRect().left - sb.left - g.measureText(askT).width / 2 - 16));
      tag(askX, askY, askT, true, 1, true);
    }
    // Talking to the doctor is said on screen while it is here: "T tells it
    // something" in the key list was all there was, and a doctor that said its
    // piece and left looked like one that could not be answered.
    var free = !talk && $('c3dSay').hidden && !doc.asked;
    if (free && walk.doc) tag(W / 2, H - 134, 'E or T   talk to ' + docName(), true, 1, true);
    else if (!talk && walk.near) tag(W / 2, H - 134, 'E   talk to ' + (near ? near.name : 'the machine ' + walk.near.slice(5)), true, 1, true);
    if (free && !walk.doc && docHere()) tag(W / 2, walk.near ? H - 160 : H - 134, 'T   talk to ' + docName(), true, 1, true);
    for (var wid in wl) {
      var m = wl[wid]; if (!m.kind || Math.hypot(m.ax - walk.x, m.az - walk.z) > 7) continue;
      var cv2 = view(m.ax, m.ay + 2.0, m.az); if (cv2[2] < NEAR) continue;
      var cp2 = scr(cv2); tag(cp2[0], cp2[1] - 24, m.kind + ' ' + m.name + ' · keeps ' + m.n + (m.n === 1 ? ' pod' : ' pods') + ' alive', false, 0.9);
    }
    // what you carry, and whether it is live
    var name = tool === 1 ? WEAPONS[me.weapon].name : TOOLS[tool], bx = W - 316, by = H - 124, bw = 300;
    plate(bx, by, bw, 84, live ? HUDC.red : HUDC.amber, 0.94); g.globalAlpha = 1;
    ink('LOADOUT', bx + 14, by + 13, 9, HUDC.dim, 'left', 800, 1.6);
    ink(tool ? (armed ? 'ARMED · EVERY SHOT IS REAL' : 'SAFE · F ASKS YOU TO ARM') : 'E OR F TALKS', bx + bw - 12, by + 13, 9, live ? HUDC.red : HUDC.dim, 'right', 800, 1.2);
    x = bx + 14 + ink(name.toUpperCase(), bx + 14, by + 39, 24, HUDC.ink, 'left', 900, 0.6);
    // what it does goes beside its name only where a long name leaves room
    row = tool === 1 ? 'DELETES ONE POD' : tool === 2 ? 'RESTARTS ITS WORKLOAD' : 'OPENS A CONVERSATION';
    g.font = '700 9px ' + FONT; if (x + g.measureText(row).width + row.length * 1.2 + 26 < bx + bw) ink(row, bx + bw - 12, by + 41, 9, HUDC.dim, 'right', 700, 1.2);
    for (i = 0, x = bx + 14; i < 3; i++) x += ink((i + 1) + ' ' + (i === 1 ? WEAPONS[me.weapon].name : TOOLS[i]).toUpperCase(), x, by + 68, 10, i === tool ? HUDC.amber : HUDC.dim, 'left', 800, 0.8) + 14;
    if (x + 52 < bx + bw) ink(tool === 1 ? 'G NEXT' : 'Q NEXT', bx + bw - 12, by + 68, 9, HUDC.dim, 'right', 700, 1.2);
    // what you ride, and how fast it is going
    plate(bx, by - 34, bw, 28, null, 0.9); g.globalAlpha = 1;
    x = bx + 14 + ink(walk.riding ? RIDES[me.ride].name.toUpperCase() : 'ON FOOT', bx + 14, by - 20, 10, HUDC.ink, 'left', 800, 1) + 12;
    g.fillStyle = 'rgba(255,255,255,.14)'; g.fillRect(x, by - 23, 70, 6); g.fillStyle = HUDC.amber; g.fillRect(x, by - 23, 70 * clamp((walk.v || 0) / 24.9, 0, 1), 6);
    ink(Math.round(walk.v || 0) + ' M/S', x + 78, by - 20, 9.5, HUDC.dim, 'left', 700, 1);
    ink(me.ride ? (walk.riding ? 'V OFF' : 'V RIDE') : 'P CHOOSE', bx + bw - 12, by - 20, 9, HUDC.dim, 'right', 700, 1.2);
    // the reticle: wider on the move, and it takes the colour of what it is on
    var tone = pod ? (near.tone === 'bad' ? HUDC.red : near.tone === 'warn' ? HUDC.amber : HUDC.ok) : HUDC.ink, gap = 5 + (walk.moving ? 4 : 0);
    if (locked()) {
      g.globalAlpha = 0.9; g.fillStyle = tool === 1 ? HUDC.red : tool === 2 ? HUDC.ok : tone;
      g.fillRect(W / 2 - gap - 7, H / 2 - 0.75, 7, 1.5); g.fillRect(W / 2 + gap, H / 2 - 0.75, 7, 1.5);
      g.fillRect(W / 2 - 0.75, H / 2 - gap - 7, 1.5, 7); g.fillRect(W / 2 - 0.75, H / 2 + gap, 1.5, 7); g.fillRect(W / 2 - 1, H / 2 - 1, 2, 2);
    } else if (!talk) { g.textAlign = 'center'; tag(W / 2, H - 160, walk.nolock ? 'Drag to look around' : 'Click the world to take the mouse back', false, 0.9, true); }
    // what you would hit: brackets round it, and what a shot would really do to it
    if (pod && tool && pod.sx != null && pod.pr > 4 && !talk) {
      var br = pod.pr * 1.25, c = Math.max(6, br * 0.3), sgx, sgy;
      g.globalAlpha = 0.95; g.strokeStyle = tone; g.lineWidth = 2;
      for (sgx = -1; sgx <= 1; sgx += 2) for (sgy = -1; sgy <= 1; sgy += 2) {
        g.beginPath(); g.moveTo(pod.sx + sgx * br, pod.sy + sgy * (br - c)); g.lineTo(pod.sx + sgx * br, pod.sy + sgy * br); g.lineTo(pod.sx + sgx * (br - c), pod.sy + sgy * br); g.stroke();
      }
      row = tool === 2 ? (/^(Deployment|StatefulSet|DaemonSet)$/.test(near.kind) ? 'F   RESTARTS ' + near.kind.toUpperCase() + ' ' + near.workload.toUpperCase() : 'NOTHING OWNS IT: NOTHING TO RESTART')
        : near.workload ? 'F   DELETES IT · ' + near.kind.toUpperCase() + ' STARTS ANOTHER' : 'F   DELETES IT · NOTHING OWNS IT: IT WILL NOT COME BACK';
      g.font = '800 10px ' + FONT; wide = Math.max(g.measureText(row).width, g.measureText(near.name.toUpperCase()).width) + 40;
      x = clamp(pod.sx - wide / 2, 8, W - wide - 8); y = clamp(pod.sy - br - 56, 104, H - 180);
      plate(x, y, wide, 44, tone, 0.94); g.globalAlpha = 1;
      ink(near.name.toUpperCase(), x + 14, y + 13, 11, HUDC.ink, 'left', 800, 0.6);
      ink(((near.problem || 'healthy') + (near.restarts ? ' · ' + near.restarts + ' restart' + (near.restarts === 1 ? '' : 's') : '')).toUpperCase(), x + wide - 10, y + 13, 9, tone, 'right', 800, 1);
      ink(row, x + 14, y + 31, 10, HUDC.dim, 'left', 800, 0.8);
    }
    // the mark of a blow that landed
    if (t - hitAt < 0.32 && !calm) {
      g.globalAlpha = 1 - (t - hitAt) / 0.32; g.strokeStyle = '#fff'; g.lineWidth = 2.5;
      [[-1, -1], [1, -1], [-1, 1], [1, 1]].forEach(function (d) { g.beginPath(); g.moveTo(W / 2 + d[0] * 7, H / 2 + d[1] * 7); g.lineTo(W / 2 + d[0] * 16, H / 2 + d[1] * 16); g.stroke(); });
    }
    g.globalAlpha = 1; minimap();
  }
  /* ── talking ─────────────────────────────────────────────────────────
     E on anything opens a conversation with it: what it says is read off its
     own row, and what it can be asked is what the portal can already answer
     (its log, its description, who manages it) or already do (recycle this
     pod, restart its workload). Doing goes through /clusters/3d/act.json,
     which is the same guarded route the Pods tab's buttons use: an action this
     person may not take is offered DISABLED with the reason, never hidden. */
  var talk = null, QS = new URL(stage.getAttribute('data-json'), location.href).searchParams;
  function talkShow(text, out) {
    var o = $('c3dTalkOut');
    $('c3dTalkSay').textContent = text || '';
    o.hidden = !out; o.textContent = out || ''; if (out) o.scrollTop = o.scrollHeight;
  }
  function getJson(path, params) {
    var q = 'project=' + encodeURIComponent(QS.get('project')) + '&cluster=' + encodeURIComponent(QS.get('cluster')), k;
    for (k in params) q += '&' + k + '=' + encodeURIComponent(params[k]);
    return fetch(path + '?' + q, { credentials: 'same-origin', headers: { Accept: 'application/json' } }).then(function (r) { return r.json(); });
  }
  function ask(path, params, lead, none) {
    return function () {
      talkShow('One moment…');
      getJson(path, params).then(function (d) {
        if (!talk) return;
        if (d.error && !d.text) talkShow('I could not get that: ' + d.error); else talkShow(d.text ? lead : none, d.text || '');
      }).catch(function () { if (talk) talkShow('I could not reach the portal.'); });
    };
  }
  function act(action, r, words, key) {
    return function () {
      // a pod going, to be replaced or for good, is confirmed the house way, by typing the word; a restart of the workload is an ordinary question
      var kill = action === 'kill-pod', goes = kill || action === 'delete-pod';
      var sure = goes && window.confirmDelete ? window.confirmDelete('pod ' + r.name + (kill ? ', for good' : '')) : Promise.resolve(window.confirm(words));
      sure.then(function (yes) {
        if (!yes || !talk) return;
        var typed = data.can.prod ? (window.prompt('This cluster serves production. Type its name to go ahead:') || '') : '';
        talkShow('Doing it…');
        fetch('/clusters/3d/act.json', { method: 'POST', credentials: 'same-origin', headers: { Accept: 'application/json' },
          body: new URLSearchParams({ project: QS.get('project'), cluster: QS.get('cluster'), action: action, namespace: r.ns,
            name: action === 'restart' ? r.workload : r.name, kind: action === 'restart' ? r.kind.toLowerCase() : 'pod', confirm: typed }) })
          .then(function (res) { return res.json(); })
          .then(function (d) {
            if (d.ok && game) game.acts++;
            // done: the conversation gives way to the finisher. Refused: it stays, with the reason and a way back
            if (d.ok && key && items[key] && items[key].ax != null) { finish(items[key], r, goes ? WEAPONS[me.weapon] : MEDKIT, kill ? 'end' : goes ? 'kill' : 'restart'); return; }
            if (key && talk) talkOpts(d.ok ? [['Goodbye', talkClose]] : [['Back', function () { talkOpen(key); }], ['Goodbye', talkClose]]);
            if (talk) talkShow(d.ok ? (kill ? 'Done. I am going, and nothing is starting another me.' : goes ? 'Done. Watch: I am going, and my replacement is on its way.' : 'Done. We will be replaced one after another.') : 'It was refused: ' + d.message, d.ok ? d.message : '');
            poll(true);
          }).catch(function () { if (talk) talkShow('I could not reach the portal.'); });
      });
    };
  }
  function talkOpen(key) {
    var plat = !key.indexOf('plat:'), kind = key.slice(0, key.indexOf(':')), opts = [], no = data.can && data.can.act ? '' : (data.can || {}).why || 'not allowed', box = $('c3dTalkOpts');
    var r = plat ? lay.plats.filter(function (p) { return 'plat:' + p.key === key; })[0] : ix.ref[key], tech, nd;
    if (!r) return;
    talk = { key: key, relock: talk ? talk.relock : locked(), opts: opts };
    if (locked()) document.exitPointerLock();
    $('c3dTalk').hidden = false; stage.classList.add('talking');
    if (kind === 'pod') {
      tech = r.tech && data.techs[r.tech];
      $('c3dTalkWho').textContent = r.name + '   ·   ' + (tech ? tech.label + '   ·   ' : '') + r.ns;
      talkShow(speech(key, ix, data.techs || {}));
      opts.push(['Show me your logs', ask('/clusters/3d/logs.json', { namespace: r.ns, pod: r.name }, 'These are my last lines.', 'I have written nothing yet.')]);
      if (r.restarts) opts.push(['What did you write before your last restart?', ask('/clusters/3d/logs.json', { namespace: r.ns, pod: r.name, previous: 1 }, 'This is what I wrote before I went down.', 'Nothing was kept from before.')]);
      opts.push(['Describe yourself', ask('/clusters/describe.json', { kind: 'pod', namespace: r.ns, name: r.name }, 'This is everything Kubernetes says about me.', 'Kubernetes said nothing.')]);
      opts.push(['Who manages you?', function () { talkShow(managedLine(r)); }]);
      opts.push(['Who do you talk to?', function () { talkShow(linksLine(key, ix)); }]);
      if (r.tone === 'bad' || r.tone === 'warn') opts.push(['Call the doctor for you', function () { talkShow('Calling…'); callDoctor(key); }]);
      opts.push(['Restart you', function () { weaponMenu(key, r); }, no]);
      if (r.workload && /^(Deployment|StatefulSet|DaemonSet)$/.test(r.kind)) opts.push(['Restart all of ' + r.workload, act('restart', r, 'Restart every pod of ' + r.workload + ', one after another?', key), no]);
      opts.push(['Kill you', function () { weaponMenu(key, r, true); }, no || killWhy(r, ix)]);
      opts.push(['Dance with me', function () { danceStart(key); }]);
    } else if (plat) {
      nd = r.node;
      $('c3dTalkWho').textContent = r.key + '   ·   machine';
      talkShow('I am ' + r.key + ', and I am ' + (nd.ready ? 'ready' : 'NOT ready') + (nd.schedulable ? '' : ', cordoned') + (nd.pressure.length ? ', under ' + nd.pressure.join(' and ') : '')
        + '. ' + r.count + ' pod' + (r.count === 1 ? ' runs' : 's run') + ' on me' + (r.bad ? ', ' + r.bad + ' of them failing' : '') + '.'
        + (nd.cpu_pct != null ? ' I am using ' + nd.cpu_pct + '% of my CPU' + (nd.mem_pct != null ? ' and ' + nd.mem_pct + '% of my memory.' : '.') : ''));
      opts.push(['Describe yourself', ask('/clusters/describe.json', { kind: 'node', namespace: '', name: r.key }, 'This is everything Kubernetes says about me.', 'Kubernetes said nothing.')]);
      opts.push([nd.schedulable ? 'Stop new pods landing on you (cordon)' : 'Let pods land on you again (uncordon)', sendNode(nd.schedulable ? 'cordon' : 'uncordon', r), no]);
    } else {
      $('c3dTalkWho').textContent = r.name + '   ·   ' + (kind === 'svc' ? 'Service' : kind === 'route' ? r.kind : 'volume claim') + '   ·   ' + r.ns;
      talkShow(speech(key, ix, data.techs || {}));
      opts.push(['Describe yourself', ask('/clusters/describe.json', { kind: kind === 'svc' ? 'service' : kind === 'claim' ? 'pvc' : r.kind === 'IngressRoute' ? 'ingressroute' : 'ingress', namespace: r.ns, name: r.name },
        'This is everything Kubernetes says about me.', 'Kubernetes said nothing.')]);
    }
    opts.push(['Goodbye', talkClose]);
    talkOpts(opts);
  }
  /* The key beside a line: 1 to 9, then 0 for the tenth. A pod in trouble has
     more to offer than that, and its goodbye is then on Esc, where it always was. */
  function optKey(op, i) { return i < 9 ? String(i + 1) : i === 9 ? '0' : op[1] === talkClose ? 'Esc' : ''; }
  function talkOpts(opts) {
    var box = $('c3dTalkOpts'); talk.opts = opts; clear(box);
    opts.forEach(function (op, i) {
      var b = el('button', 'c3d-opt'); b.type = 'button';
      b.appendChild(el('kbd', '', optKey(op, i))); b.appendChild(el('span', '', op[0]));
      if (op[2]) { b.disabled = true; b.title = op[2]; b.appendChild(el('em', '', op[2])); }
      b.addEventListener('click', function () { if (!op[2]) op[1](); });
      box.appendChild(b);
    });
  }
  /* "Restart you" deletes the pod, and whatever owns it starts another. "Kill
     you" tells that owner to keep one fewer as well, so nothing does. What the
     pod goes WITH is the player's choice and changes nothing else: every
     weapon is the same one action, through the same typed word, the same
     production name and the same audit line. */
  function weaponMenu(key, r, kill) {
    var opts = WEAPONS.map(function (w, i) { return [w.name, function () { me.weapon = i; keep(); act(kill ? 'kill-pod' : 'delete-pod', r, '', key)(); }]; });
    opts.push(['Never mind', function () { talkOpen(key); }]);
    talkShow(kill ? killLine(r) : r.workload ? 'A restart means I go and ' + r.kind + ' ' + r.workload + ' starts a fresh me. Fine. Choose your weapon.'
      : 'Nothing owns me, so if I go I do not come back. Still sure? Choose your weapon.');
    talkOpts(opts);
  }
  function talkClose() {
    if (!talk) return;
    var again = talk.relock; talk = null;
    $('c3dTalk').hidden = true; stage.classList.remove('talking');
    if (again && walk) grab();
  }

  window.addEventListener('keydown', function (e) {
    if (!walk || e.metaKey || e.ctrlKey || e.altKey) return;
    // Somebody typing is not walking. Without this the keys that move you
    // (W A S D, E, C) never reached a text box, so the word the portal asks
    // for before a delete could not be typed while the walk was on.
    var at = e.target, typing = at && (at.tagName === 'INPUT' || at.tagName === 'TEXTAREA' || at.isContentEditable);
    if (typing || document.querySelector('dialog[open]')) { keys = {}; return; }
    var k = e.key.length === 1 ? e.key.toLowerCase() : e.key;
    if (picking) { pickKey(k); e.preventDefault(); return; }
    if (fin) { if (k === ' ' || k === 'Enter' || k === 'Escape') finEnd(); e.preventDefault(); return; }
    if (dance) { if (k === ' ' || k === 'Enter' || k === 'Escape' || k === 'b') danceEnd(true); e.preventDefault(); return; }
    keys[k] = 1;
    if (talk && k >= '0' && k <= '9') { var op = talk.opts[k === '0' ? 9 : +k - 1]; if (op && !op[2]) op[1](); e.preventDefault(); return; }
    if (!talk && k >= '1' && k <= '3') { tool = +k - 1; return; }
    if (!talk && k === 'q') { tool = (tool + 1) % 3; return; }
    if (!talk && k === 'g' && !e.repeat) { me.weapon = (me.weapon + 1) % WEAPONS.length; keep(); tool = 1; toast('Weapon: ' + WEAPONS[me.weapon].name); return; }
    if (!talk && k === 'v' && !e.repeat) { mount(); return; }
    if (!talk && k === 'p' && !e.repeat) { pickOpen(); return; }
    if (!talk && k === 'b' && !e.repeat) {      // a dance with the pod in reach; with none, your own move, because you can
      if (walk.near && !walk.near.indexOf('pod:')) danceStart(walk.near); else if (!walk.riding) walk.move = { at: performance.now() / 1000, dur: 1.6 };
      return;
    }
    if (!talk && k === 'm' && !e.repeat) { me.mute = !me.mute; keep(); toast('Sound ' + (me.mute ? 'off' : 'on')); sfx('tick'); return; }
    if (!talk && k === 'f' && !e.repeat) { if (tool) useTool(); else interact(); return; }
    if (!talk && k === 'h' && !e.repeat) { callDoctor(walk.near); return; }
    // T talks to the doctor from anywhere, a conversation with a pod included:
    // a dialog that swallowed the key left the person with something to say
    // to the doctor and no way to say it.
    if (k === 't' && !e.repeat) { if (talk) { talkClose(); select('', false); } sayOpen(); e.preventDefault(); return; }
    if ((k === 'e' || k === 'Enter') && !e.repeat) { if (walk.doc && !talk) { sayOpen(); e.preventDefault(); } else interact(); }
    else if (k === 'Escape') { if (talk) { talkClose(); select('', false); } else if (selKey) select('', false); else leaveWalk(); }
    if (' wasdce'.indexOf(k) >= 0 || !k.indexOf('Arrow')) e.preventDefault();
  });
  $('c3dSay').addEventListener('submit', function (e) {
    e.preventDefault();
    var text = $('c3dSayText').value.trim();
    sayClose(true); if (text) saySend(text);
  });
  $('c3dSayText').addEventListener('keydown', function (e) {
    var picks = doc.asked && doc.asked.choices || [], n = +e.key;
    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); sayClose(true); }
    else if (!this.value && n >= 1 && n <= picks.length) { e.preventDefault(); sayClose(true); saySend(picks[n - 1]); }
  });
  window.addEventListener('keyup', function (e) { delete keys[e.key.length === 1 ? e.key.toLowerCase() : e.key]; });
  window.addEventListener('blur', function () { keys = {}; });
  $('c3dWalk').addEventListener('click', function () { if (walk) leaveWalk(); else enterWalk(); });

  var last = 0;
  function frame(ms) {
    requestAnimationFrame(frame);
    var t = ms / 1000, dt = Math.min(0.05, t - last || 0.016); last = t;
    var k = calm ? 1 : 1 - Math.exp(-dt * 5.5), key;
    if (spin && !calm && !touring && !walk && data && Date.now() - lastInput > 3500 && !drag) goal.yaw += dt * (selKey ? 0.03 : 0.05);
    if (touring && data && t >= tourAt) {
      tourI = (tourI + 1) % tourList.length; tourAt = t + 5;
      select(tourList[tourI], false); fly(tourList[tourI], true); caption(tourList[tourI]);
    }
    if (touring && !calm) goal.yaw += dt * 0.12;      // the camera circles what it is showing
    if (walk && data) walkStep(t, dt);
    var kc = walk ? (calm ? 1 : 1 - Math.exp(-dt * 16)) : k;
    for (key in goal) cam[key] += (goal[key] - cam[key]) * kc;
    if (walk) {      // the mouse turns the head at once, and the camera never goes through the floor
      cam.yaw = goal.yaw; cam.pitch = goal.pitch;
      if (cam.pitch < 0 && walk.y >= 0) cam.dist = Math.min(cam.dist, Math.max(0.05, (cam.ty - 0.22) / -Math.sin(cam.pitch)));
    }
    basis();
    g.setTransform(DPR, 0, 0, DPR, 0, 0); g.clearRect(0, 0, W, H);
    N.box = N.ball = N.soft = N.orb = N.spr = N.glow = N.beam = N.sh = 0; nIsles = 0; nProps = 0; nFigs = 0;
    var bad = data && data.totals ? data.totals.bad || 0 : 0;
    moodNow += ((bad ? clamp(0.16 + bad * 0.05, 0.16, 0.55) : 0) - moodNow) * (calm ? 1 : Math.min(1, dt * 1.2));
    if (lay) world(t, dt, k);
    paint(t, { span: fit, mood: moodNow, pulse: t - pulseAt, gridY: GRIDY, bloom: walk ? 0.4 : 0.72, bays: lay && lay.bays, nBays: lay && lay.bays ? lay.plats.length : 0 });
    if (lay) names();
    g.globalAlpha = 1;
    if (data && t - statusAt > 1) { statusAt = t; status(); }
  }
  /* Everything pushed this frame, sent to the graphics card: one call, for a
     cluster and for the city alike, so the two can never disagree about what
     a row of numbers means. */
  function paint(t, o) {
    gpu.draw({ time: t, eye: [ex, ey, ez], right: [rx, 0, rz], up: [ux, uy, uz], fwd: [fx, fy, fz], focal: F, span: o.span,
      mood: o.mood, pulse: o.pulse, gridY: o.gridY, bloom: o.bloom,
      fogCol: [0.02 + o.mood * 0.07, 0.035 - o.mood * 0.015, 0.09 - o.mood * 0.05],
      boxes: A.boxes, nBoxes: N.box, balls: A.balls, nBalls: N.ball, softs: A.softs, nSofts: N.soft, orbs: A.orbs, nOrbs: N.orb, sprites: A.sprites, nSprites: N.spr, glows: A.glows, nGlows: N.glow,
      beams: A.beams, nBeams: N.beam, shadows: A.shadows, nShadows: N.sh, isles: A.isles, isleCols: A.isleCols, nIsles: nIsles, bays: o.bays || null, nBays: o.nBays || 0, town: o.town || null, props: PROPS, nProps: nProps, figs: FIGS, nFigs: nFigs, heroes: HEROES, screens: o.screens || null });
  }
  /* The start of a frame for the city: the camera comes to where it was sent
     (the mouse turns the head at once), and the last frame's shapes and names
     are cleared. */
  function begin(dt) {
    var kc = calm ? 1 : 1 - Math.exp(-dt * 16), key;
    for (key in goal) cam[key] += (goal[key] - cam[key]) * kc;
    cam.yaw = goal.yaw; cam.pitch = goal.pitch;
    if (cam.pitch < 0) cam.dist = Math.min(cam.dist, Math.max(0.05, (cam.ty - 0.22) / -Math.sin(cam.pitch)));
    basis();
    g.setTransform(DPR, 0, 0, DPR, 0, 0); g.clearRect(0, 0, W, H);
    N.box = N.ball = N.soft = N.orb = N.spr = N.glow = N.beam = N.sh = 0; nIsles = 0; nProps = 0; nFigs = 0; placed.length = 0;
  }
  var statusAt = 0, lost = false;
  function status() {
    if (lost) return;       // the failure is what the line is saying
    var live = $('c3dLive'), s = Math.round((Date.now() - lastOk) / 1000);
    live.className = 'c3d-live on';
    live.textContent = 'live · read ' + (s < 2 ? 'just now' : s + 's ago')
      + (data.truncated ? ' · ' + data.truncated + ' more pods not drawn' : '');
  }

  /* ── hands ───────────────────────────────────────────────────────── */
  function pick(x, y) {
    for (var n = list.length - 1; n >= 0; n--) {
      var it = list[n]; if (it.dead || it.dim) continue;
      var rr = Math.max(it.pr * 1.1, 7);
      if ((it.sx - x) * (it.sx - x) + (it.sy - y) * (it.sy - y) <= rr * rr) return it.key;
    }
    if (!lay) return '';
    for (var i = 0; i < lay.plats.length; i++) {      // then the floor under the pointer
      var pl = lay.plats[i], inside = false, pts = pl.ring.map(function (p) { var v = view(p[0], 0, p[1]); return v[2] < NEAR ? null : scr(v); });
      if (pts.indexOf(null) >= 0) continue;
      for (var a = 0, b = pts.length - 1; a < pts.length; b = a++) {
        if ((pts[a][1] > y) !== (pts[b][1] > y) && x < (pts[b][0] - pts[a][0]) * (y - pts[a][1]) / (pts[b][1] - pts[a][1]) + pts[a][0]) inside = !inside;
      }
      if (inside) return 'plat:' + pl.key;
    }
    return '';
  }
  function tip(key, x, y) {
    var box = $('c3dTip'); clear(box);
    if (!key || !key.indexOf('plat:')) { box.hidden = true; return; }
    var r = ix.ref[key], kind = key.slice(0, key.indexOf(':'));
    box.appendChild(el('b', '', r.name));
    box.appendChild(el('small', '', kind === 'pod' ? r.ns + ' · ' + (r.problem || r.phase) + ' · ready ' + r.ready
      : kind === 'svc' ? 'Service · ' + r.ns + ' · ' + (r.ports || []).join(', ')
        : kind === 'route' ? 'Route · ' + (r.hosts || []).join(', ') : 'Volume · ' + r.size + ' · ' + r.status));
    box.style.left = Math.min(x, W - 220) + 'px'; box.style.top = Math.min(y, H - 60) + 'px'; box.hidden = false;
  }
  var ptrs = {}, drag = null;
  function touched() { lastInput = Date.now(); if (touring) tour(false); $('c3dHint').className = 'c3d-hint gone'; }
  function local(e) { var b = cv.getBoundingClientRect(); return [e.clientX - b.left, e.clientY - b.top]; }
  function pan(dx, dy) {
    var k = cam.dist * 0.0016, gl = Math.hypot(fx, fz) || 1;
    goal.tx += (-dx * rx + dy * fx / gl) * k; goal.tz += (-dx * rz + dy * fz / gl) * k;
  }
  cv.addEventListener('pointerdown', function (e) {
    touched(); cv.setPointerCapture(e.pointerId); ptrs[e.pointerId] = [e.clientX, e.clientY];
    drag = { x: e.clientX, y: e.clientY, moved: 0, pan: e.button !== 0 || e.shiftKey, gap: 0 };
    cv.focus({ preventScroll: true });
  });
  cv.addEventListener('pointermove', function (e) {
    var p = local(e);
    if ((walk || city) && locked()) { goal.yaw -= e.movementX * 0.0026; goal.pitch = clamp(goal.pitch + e.movementY * 0.0026, -1.25, 1.45); return; }
    ptr.x = p[0]; ptr.y = p[1]; ptr.at = Date.now(); ptr.on = true;
    if (!drag) {
      var kk = data ? pick(p[0], p[1]) : '';
      if (kk !== hoverKey) { hoverKey = kk; hoverRel = kk ? related(kk, ix, lay.plats) : null; cv.className = kk ? 'point' : ''; }
      tip(kk, p[0], p[1]); return;
    }
    var ids = Object.keys(ptrs);
    if (ids.length >= 2 && ptrs[e.pointerId]) {      // two fingers: pinch to zoom, slide to move
      var was = ptrs[e.pointerId]; ptrs[e.pointerId] = [e.clientX, e.clientY];
      var o = ptrs[ids[0] === String(e.pointerId) ? ids[1] : ids[0]], gap = Math.hypot(e.clientX - o[0], e.clientY - o[1]);
      if (drag.gap) goal.dist = clamp(goal.dist * drag.gap / gap, 3, fit * 3);
      drag.gap = gap; pan((e.clientX - was[0]) / 2, (e.clientY - was[1]) / 2); drag.moved = 9; return;
    }
    var dx = e.clientX - drag.x, dy = e.clientY - drag.y;
    drag.x = e.clientX; drag.y = e.clientY; drag.moved += Math.abs(dx) + Math.abs(dy);
    if (drag.moved < 5) return;
    cv.className = 'drag'; $('c3dTip').hidden = true; lastInput = Date.now();
    if (drag.pan && !walk && !city) pan(dx, dy);
    else { goal.yaw -= dx * 0.0062; goal.pitch = clamp(goal.pitch + dy * 0.005, walk || city ? -1.25 : -0.25, 1.5); }
  });
  function up(e) {
    delete ptrs[e.pointerId];
    if (!drag || Object.keys(ptrs).length) return;
    var p = local(e), was = drag; drag = null; cv.className = hoverKey ? 'point' : '';
    if (was.moved >= 5 || e.type !== 'pointerup') return;
    if (city) { if (cityHook.click) cityHook.click(); return; }
    var hit = data ? pick(p[0], p[1]) : '';
    if (!walk) select(hit, false);
    else if (picking) return;      // the chooser takes the clicks
    else if (fin) finEnd();
    else if (dance) return;      // a click fires nothing at a partner, whatever is in your hand
    else if (locked()) { if (tool) useTool(); else interact(); }
    else if (hit && hit.indexOf('plat:')) { walk.near = hit; if (tool && !hit.indexOf('pod:')) useTool(); else interact(); }
    else grab();
  }
  cv.addEventListener('pointerup', up); cv.addEventListener('pointercancel', up);
  cv.addEventListener('pointerleave', function () { ptr.on = false; if (!drag) { hoverKey = ''; hoverRel = null; $('c3dTip').hidden = true; } });
  cv.addEventListener('dblclick', function (e) {
    if (walk || city) return;
    var p = local(e), kk = data ? pick(p[0], p[1]) : '';
    if (kk) { select(kk, false); fly(kk, true); } else { select('', false); home(false); }
  });
  cv.addEventListener('contextmenu', function (e) { e.preventDefault(); });
  cv.addEventListener('wheel', function (e) {
    e.preventDefault(); touched();
    if (city) { if (cityHook.wheel) cityHook.wheel(e); return; }
    if (walk) { walk.dist = clamp(walk.dist * Math.exp(e.deltaY * (e.deltaMode ? 0.05 : 0.0016)), 0.02, 9); return; }
    goal.dist = clamp(goal.dist * Math.exp(e.deltaY * (e.deltaMode ? 0.05 : 0.0014)), 3, fit * 3);
  }, { passive: false });

  function seg(attr, set) {
    Array.prototype.forEach.call(stage.querySelectorAll('[' + attr + ']'), function (b) {
      b.addEventListener('click', function () {
        Array.prototype.forEach.call(stage.querySelectorAll('[' + attr + ']'), function (o) { o.className = 'c3d-btn' + (o === b ? ' on' : ''); });
        set(b.getAttribute(attr));
      });
    });
  }
  seg('data-group', function (v) { groupBy = v; if (data) { relayout(false); home(false); } });
  seg('data-lines', function (v) { lines = v; });
  // a hall is tidy: it opens drawing only the connections of what you point at, and All is still one press away
  if (HALL) { var tidy = document.querySelector('[data-lines="focus"]'); if (tidy) tidy.click(); }
  function toggle(id, get, set) {
    $(id).addEventListener('click', function () {
      set(!get()); $(id).className = 'c3d-btn' + (get() ? ' on' : ''); $(id).setAttribute('aria-pressed', get() ? 'true' : 'false');
    });
  }
  toggle('c3dLabels', function () { return labels; }, function (v) { labels = v; });
  toggle('c3dSpin', function () { return spin; }, function (v) { spin = v; });
  toggle('c3dKey', function () { return !$('c3dSide').hidden; }, function (v) { $('c3dSide').hidden = !v; });
  $('c3dTour').addEventListener('click', function () { tour(!touring); });
  $('c3dReset').addEventListener('click', function () { focusNs = ''; toneOnly = ''; $('c3dSearch').value = ''; search(''); select('', false); home(false); if (data) hud(); });
  function full() {
    var on = document.fullscreenElement || document.webkitFullscreenElement;
    if (on) (document.exitFullscreen || document.webkitExitFullscreen).call(document);
    else (stage.requestFullscreen || stage.webkitRequestFullscreen).call(stage);
  }
  $('c3dFull').addEventListener('click', full);
  // both, and exactly: the prefixed name CONTAINS the standard one
  document.addEventListener('fullscreenchange', resize); document.addEventListener('webkitfullscreenchange', resize);
  var box = $('c3dSearch');
  box.addEventListener('input', function () { search(box.value); });
  box.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' && found && found._first) { select(found._first, true); e.preventDefault(); }
    if (e.key === 'Escape') { box.value = ''; search(''); cv.focus(); }
    e.stopPropagation();
  });
  stage.addEventListener('keydown', function (e) {
    if (walk || city) return;      // the keys belong to your feet
    if (e.target === box || e.metaKey || e.ctrlKey || e.altKey) return;
    var k = e.key, used = true;
    if (k === '/') box.focus();
    else if (k === 'Escape') { if (selKey) select('', false); else { focusNs = ''; toneOnly = ''; if (data) hud(); } }
    else if (k === 'r' || k === 'R') $('c3dReset').click();
    else if (k === 'f' || k === 'F') full();
    else if (k === 'l' || k === 'L') $('c3dLabels').click();
    else if (k === 't' || k === 'T') tour(!touring);
    else if (k === 'ArrowLeft') goal.yaw += 0.18; else if (k === 'ArrowRight') goal.yaw -= 0.18;
    else if (k === 'ArrowUp') goal.pitch = clamp(goal.pitch + 0.1, -0.25, 1.5); else if (k === 'ArrowDown') goal.pitch = clamp(goal.pitch - 0.1, -0.25, 1.5);
    else if (k === '+' || k === '=') goal.dist = clamp(goal.dist * 0.8, 3, fit * 3); else if (k === '-') goal.dist = clamp(goal.dist * 1.25, 3, fit * 3);
    else used = false;
    if (used) { e.preventDefault(); if (k !== 't' && k !== 'T') touched(); }
  });

  if (window.ResizeObserver) new ResizeObserver(resize).observe(stage); else window.addEventListener('resize', resize);
  document.addEventListener('visibilitychange', function () { if (!document.hidden && !city) poll(false); });
  if (!gpu) {
    veil('This picture is drawn on the graphics card, and this browser would not give it one (it needs WebGL 2). The same pods are on the cluster\u2019s Pods tab.', true);
    return;
  }
  if (city) {
    // The street takes the stage: it is given the engine, the figure and the
    // head-up display's pens, and runs its own frames. Nothing of a cluster
    // is read on this page.
    if (!window.C3DCity) { veil('The city could not be drawn: its script did not load.', true); return; }
    resize();
    window.C3DCity({ stage: stage, hall: HALL, cv: cv, g: g, calm: calm, me: me, keep: keep, HEROES: HEROES, RIDES: RIDES, FONT: FONT, HUDC: HUDC,
      BOX: BOX, BALL: BALL, SOFT: SOFT, cam: cam, goal: goal, begin: begin, paint: paint,
      size: function () { return { W: W, H: H, F: F }; }, eye: function () { return [ex, ey, ez]; },
      cube: cube, solid: solid, glo: glo, beam: beam, shad: shad, orb: orb, person: person, rideDraw: rideDraw, stand: stand, part: part,
      view: view, scr: scr, ink: ink, plate: plate, tag: tag, bubble: bubble, sfx: sfx, beep: beep, veil: veil, clamp: clamp, ease: ease,
      locked: locked, grab: grab, el: el, clear: clear, $: $, MOOD: MOOD, TONEF: TONEF,
      atlas: function () { M = gpu.atlas(MARKS.concat([{ key: 'cross', draw: cross }])); },
      // the chooser of who you are and what you ride: the one a cluster opens, handed over whole
      pick: { open: pickAt, close: pickClose, key: pickKey, aim: pickAim, scene: pickScene, on: function () { return picking; } } }, cityHook);
    return;
  }
  if (fromCity) { $('c3dBack').href = '/clusters/city?at=' + encodeURIComponent(QS.get('cluster') || ''); $('c3dBack').textContent = '\u2190 The city'; }
  resize(); legend(); poll(false); requestAnimationFrame(frame);
  // for the test that drives the page, and for nobody else
  window.__c3d = { state: function () { return { pods: data ? data.pods.length : -1, items: Object.keys(items).length, drawn: list.length, sel: selKey, cam: cam, fit: fit,
      walk: walk && { x: walk.x, y: walk.y, z: walk.z, near: walk.near, isle: walk.isle, say: walk.say && walk.say.text, seen: Object.keys(walk.seen).length },
      dance: dance && { key: dance.key, beat: dance.beat }, fin: fin && fin.kind, verdict: verdict && verdict.kind, note: note && note.text,
      doctor: { say: doc.say && doc.say.n, pod: doc.pod && doc.pod.n, asked: doc.asked, queued: doc.queue.length, placed: !!doc.placed, hands: doc.hands }, chatter: chatter.map(function (c) { return c.text; }) }; },
    select: select, fly: fly };
})();
