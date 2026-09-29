// Enough DOM to execute the portal's page scripts under node.
//
// WHY A STUB AND NOT JSDOM
//     jsdom is a hundred megabytes and a version to maintain, for scripts that
//     touch no layout — they read attributes, toggle classes, fetch, and stream.
//     This answers the handful of calls those scripts make and records what it
//     was told, so a failure points at the page rather than at a framework.
//
// WHY ONE FILE AND NOT ONE PER TEST
//     The log window's test had its own copy. A second copy for the service page
//     would be two stubs drifting apart, and a stub that is wrong in a way the
//     real browser is not costs more time than the bug it was written to find —
//     both of this stub's own bugs so far were exactly that (a fragment appended
//     whole instead of spliced, and a dialog looked up by the wrong id).
//
// WHAT IT IS NOT
//     Not a browser. No layout, no CSS cascade, no event bubbling beyond what
//     `document.addEventListener` + `closest()` need for delegated handlers. A
//     test that needs more than this needs a real browser instead.
'use strict';

let uid = 0;
const ALL = [];

class El {
  constructor(tag = 'div') {
    this.tagName = String(tag).toUpperCase();
    this.nodeName = this.tagName;
    this._id = ++uid;
    this.children = [];
    this.parentNode = null;
    this.attributes = {};
    this.dataset = {};
    this.style = {};
    this._text = '';
    this._html = '';
    this.hidden = false;
    this.value = '';
    this.open = false;
    this.disabled = false;
    this.type = '';
    this.title = '';
    this.href = '';
    this.checked = false;
    this.spellcheck = true;
    this.autocomplete = '';
    this._on = {};
    this._q = {};
    this.offsetHeight = 0;
    this.scrollTop = 0;
    this.scrollHeight = 0;
    this.clientHeight = 100;
    const self = this;
    this.classList = {
      _s: new Set(),
      add(...c) { c.forEach(x => x && this._s.add(x)); },
      remove(...c) { c.forEach(x => this._s.delete(x)); },
      contains(c) { return this._s.has(c); },
      toggle(c, on) {
        const want = on === undefined ? !this._s.has(c) : !!on;
        want ? this.add(c) : this.remove(c);
        return want;
      },
      get value() { return Array.from(this._s).join(' '); },
      toString() { return Array.from(self.classList._s).join(' '); },
    };
    ALL.push(this);
  }

  // Sibling walking. A page that opens a panel "under this row" reaches for it
  // this way, and without these the lookup answers undefined and the handler
  // returns silently — which reads as "the click did nothing".
  get nextElementSibling() {
    const kin = this.parentNode ? this.parentNode.children : [];
    return kin[kin.indexOf(this) + 1] || null;
  }
  get previousElementSibling() {
    const kin = this.parentNode ? this.parentNode.children : [];
    const i = kin.indexOf(this);
    return i > 0 ? kin[i - 1] : null;
  }
  get firstElementChild() { return this.children[0] || null; }
  get lastElementChild() { return this.children[this.children.length - 1] || null; }

  get id() { return this.attributes.id || ''; }
  set id(v) { this.attributes.id = v; }
  get className() { return this.classList.value; }
  set className(v) {
    this.classList._s = new Set(String(v).split(/\s+/).filter(Boolean));
  }
  // Descendant text included, as a browser does. Returning only the element's
  // own text made a container read as empty while its children held the
  // message — so a test asking "is the error on screen" said no about a page
  // that was showing it.
  /* A <select>'s option list. placeSync rebuilds it, so the tests that drive
     that behaviour need the real accessor rather than children.filter at each
     call site. */
  get options() {
    return _descendants(this).filter(e => e.tagName === 'OPTION');
  }

  cloneNode(deep) {
    const n = new El(this.tagName);
    Object.assign(n.attributes, this.attributes);
    Object.assign(n.dataset, this.dataset);
    n.value = this.value;
    n.selected = this.selected;
    n.disabled = this.disabled;
    n._text = this._text;
    if (deep) this.children.forEach(c => n.appendChild(c.cloneNode(true)));
    return n;
  }

  get textContent() {
    return this._text + this.children.map(c => c.textContent).join('');
  }
  set textContent(v) { this._text = String(v); this.children = []; }
  get innerHTML() { return this._html; }
  set innerHTML(v) { this._html = v; if (v === '') this.children = []; }

  setAttribute(k, v) { this.attributes[k] = String(v); }
  getAttribute(k) { return k in this.attributes ? this.attributes[k] : null; }
  removeAttribute(k) { delete this.attributes[k]; }
  hasAttribute(k) { return k in this.attributes; }

  // A fragment is spliced, as a real appendChild does. Appending it whole is
  // how this stub once reported one line where the window held three.
  appendChild(c) {
    if (c && c._frag) { c.children.forEach(x => this.appendChild(x)); return c; }
    if (c) { c.parentNode = this; this.children.push(c); }
    return c;
  }
  append(...cs) { cs.forEach(c => this.appendChild(c)); }
  // Honours the reference node. Ignoring it and unshifting looked harmless and
  // silently reordered the DOM, which is exactly the kind of thing a test using
  // this stub is supposed to be able to see.
  insertBefore(c, before) {
    if (!c) return c;
    c.parentNode = this;
    const at = before ? this.children.indexOf(before) : -1;
    if (at < 0) this.children.push(c);
    else this.children.splice(at, 0, c);
    return c;
  }
  replaceChildren(...n) {
    this.children = [];
    n.forEach(x => this.appendChild(x));
  }
  remove() {
    if (!this.parentNode) return;
    const i = this.parentNode.children.indexOf(this);
    if (i > -1) this.parentNode.children.splice(i, 1);
    this.parentNode = null;
  }

  addEventListener(t, f) { (this._on[t] = this._on[t] || []).push(f); }
  /* The real name for `fire`. enhanceSelect and enhanceCombo both announce a
     value change with dispatchEvent(new Event(...)) — that is how a page's own
     listeners find out — so a stub without it cannot exercise the path where a
     suggestion is chosen. */
  dispatchEvent(ev) { this.fire((ev && ev.type) || 'change', ev || {}); return true; }
  removeEventListener(t, f) {
    this._on[t] = (this._on[t] || []).filter(x => x !== f);
  }
  // Fires this element's own handlers, then walks up for delegated ones —
  // which is all `document.addEventListener('click', …)` + closest() needs.
  fire(t, ev = {}) {
    const event = Object.assign({type: t, target: this, preventDefault() {},
                                stopPropagation() {}}, ev);
    let node = this;
    while (node) {
      // currentTarget is the element the listener is ON, which is not the
      // element clicked once a handler is delegated. Handlers reach for it
      // routinely — `e.currentTarget.classList.toggle(...)` — and leaving it
      // undefined threw inside the page rather than pointing at the stub.
      event.currentTarget = node;
      (node._on[t] || []).forEach(f => f(event));
      node = node.parentNode;
    }
    event.currentTarget = global.document;
    (global.document._on[t] || []).forEach(f => f(event));
    return event;
  }

  matches(sel) { return _matches(this, sel); }
  closest(sel) {
    let node = this;
    while (node) {
      if (_matches(node, sel)) return node;
      node = node.parentNode;
    }
    return null;
  }
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
  querySelectorAll(sel) { return _descendants(this).filter(e => _matches(e, sel)); }

  /* Every real element has one. Nothing here lays out, so the box is a fixed
     plausible rectangle — enough for code that anchors a fixed-position menu to
     a control, which is what the themed dropdown and combobox both do. */
  getBoundingClientRect() {
    return {left: 0, top: 100, right: 240, bottom: 130,
            width: 240, height: 30, x: 0, y: 100};
  }

  focus() { global.document.activeElement = this; }
  blur() {}
  scrollIntoView() {}
  showModal() { this.open = true; }
  close() { this.open = false; this.fire('close'); }
  click() { this.fire('click'); }
}

function _descendants(root) {
  const out = [];
  const walk = n => n.children.forEach(c => { out.push(c); walk(c); });
  walk(root);
  return out;
}

// Only the selector forms the portal's scripts actually use. Anything else
// throws rather than silently matching nothing — a selector this cannot read is
// a test that passes for the wrong reason.
function _matches(el, sel) {
  return String(sel).split(',').some(part => _matchesOne(el, part.trim()));
}

function _matchesOne(el, sel) {
  const bits = String(sel).trim().split(/\s+/).filter(Boolean);
  if (!bits.length) return false;
  if (!_simple(el, bits[bits.length - 1])) return false;
  // Right-to-left, the way a browser reads a descendant selector: the element
  // matches the last part, then each earlier part has to be found somewhere
  // above it, in order.
  let node = el.parentNode;
  let i = bits.length - 2;
  while (node && i >= 0) {
    if (_simple(node, bits[i])) i--;
    node = node.parentNode;
  }
  return i < 0;
}

function _simple(el, sel) {
  const m = String(sel).match(/^([a-zA-Z][\w-]*)?((?:[#.][\w-]+|\[[^\]]+\])*)$/);
  if (!m) throw new Error('domstub: selector not supported: ' + sel);
  if (m[1] && el.tagName !== m[1].toUpperCase()) return false;
  const parts = (m[2] || '').match(/[#.][\w-]+|\[[^\]]+\]/g) || [];
  for (const p of parts) {
    if (p[0] === '#') {
      if (el.id !== p.slice(1)) return false;
    } else if (p[0] === '.') {
      if (!el.classList.contains(p.slice(1))) return false;
    } else {
      const body = p.slice(1, -1);
      const eq = body.indexOf('=');
      if (eq === -1) {
        if (!(body in el.attributes) && !(_dataKey(body) in el.dataset)) return false;
      } else {
        const k = body.slice(0, eq);
        const v = body.slice(eq + 1).replace(/^["']|["']$/g, '');
        const got = k in el.attributes ? el.attributes[k] : el.dataset[_dataKey(k)];
        if (String(got) !== v) return false;
      }
    }
  }
  return true;
}

function _dataKey(attr) {
  if (!attr.startsWith('data-')) return attr;
  return attr.slice(5).replace(/-([a-z])/g, (_m, c) => c.toUpperCase());
}

function _put(name, value) {
  Object.defineProperty(global, name, {value: value, writable: true,
                                       configurable: true, enumerable: true});
}


// ── the globals a page script expects ────────────────────────────────────
function install(ids = {}) {
  const byId = {};
  const root = new El('body');

  const document = {
    _on: {},
    hidden: false,
    activeElement: null,
    body: root,
    documentElement: new El('html'),
    createElement: t => new El(t),
    createDocumentFragment: () => { const f = new El('frag'); f._frag = true; return f; },
    createRange: () => ({setStartBefore() {}, setEndAfter() {}, deleteContents() {}}),
    createTextNode: t => Object.assign(new El('text'), {_text: String(t)}),
    getElementById: id => byId[id] || null,
    querySelector: sel => document.querySelectorAll(sel)[0] || null,
    querySelectorAll: sel => _descendants(root).filter(e => _matches(e, sel)),
    addEventListener(t, f) { (this._on[t] = this._on[t] || []).push(f); },
    removeEventListener() {},
  };

  global.document = document;
  global.window = global;
  if (typeof global.Event !== 'function') {
    global.Event = function (type, opts) {
      this.type = type;
      this.bubbles = !!(opts && opts.bubbles); };
  }
  // A viewport, so code that decides whether a fixed menu fits below its
  // control has a number to compare against instead of undefined.
  if (global.innerHeight === undefined) global.innerHeight = 900;
  if (global.innerWidth === undefined) global.innerWidth = 1400;
  // Pages listen on window as well as document — beforeunload, hashchange,
  // resize. Recorded rather than ignored so a test can fire them.
  global._winOn = {};
  global.addEventListener = (t, f) => {
    (global._winOn[t] = global._winOn[t] || []).push(f);
  };
  global.removeEventListener = (t, f) => {
    global._winOn[t] = (global._winOn[t] || []).filter(x => x !== f);
  };
  global.dispatchWindow = (t, ev = {}) =>
    (global._winOn[t] || []).forEach(f => f(Object.assign({type: t}, ev)));
  global.El = El;
  global.byId = byId;
  global.domRoot = root;
  global.requestAnimationFrame = f => { setTimeout(() => f(0), 0); return 1; };
  global.cancelAnimationFrame = () => {};
  global.getComputedStyle = () => ({getPropertyValue: () => ''});
  global.confirm = () => (global.confirmAnswer === undefined
                          ? true : global.confirmAnswer);
  // The house typed-"Delete" dialog (base.html) exposes this Promise-returning
  // global; a page's fetch-driven delete awaits it. Mirror confirm's answer.
  global.confirmDelete = () => Promise.resolve(
    global.confirmAnswer === undefined ? true : global.confirmAnswer);
  global.alert = () => {};
  _put('location', {pathname: '/p/p1/r1/dev/s/pay-values.yaml', search: '',
                    href: 'http://portal.invalid/p/p1/r1/dev/s/pay-values.yaml',
                    reload() { global.reloaded = (global.reloaded || 0) + 1; }});
  const store = () => ({_d: {}, getItem(k) { return this._d[k] ?? null; },
                        setItem(k, v) { this._d[k] = String(v); },
                        removeItem(k) { delete this._d[k]; },
                        clear() { this._d = {}; }});
  global.sessionStorage = store();
  global.localStorage = store();
  global.URL = {createObjectURL: () => 'blob:x', revokeObjectURL() {}};
  global.Blob = class {};
  // navigator and location are getter-only on newer node, so they are DEFINED
  // rather than assigned — plain assignment throws, and the throw is inside the
  // stub, which reads like the page under test is broken.
  _put('navigator', {clipboard: {writeText: () => Promise.resolve()}});
  global.URLSearchParams = URLSearchParams;

  // Every fetch recorded, and answered from a queue the test sets up. A stub
  // that answers everything the same way cannot tell "asked the right URL" from
  // "asked one URL four times".
  global.fetched = [];
  global.fetchReplies = {};
  global.fetch = (url, opts) => {
    const body = opts && opts.body ? String(opts.body) : '';
    global.fetched.push({url: String(url), method: (opts || {}).method || 'GET',
                        body: body});
    const key = Object.keys(global.fetchReplies)
      .find(k => String(url).includes(k));
    const doc = key ? global.fetchReplies[key] : {error: 'no stub reply for ' + url};
    return Promise.resolve({ok: true, status: 200, json: () => Promise.resolve(doc),
                            text: () => Promise.resolve(JSON.stringify(doc))});
  };

  global.opened = [];
  global.esList = [];
  global.EventSource = class {
    constructor(url) {
      global.opened.push(String(url));
      global.esList.push(this);
      this.url = String(url);
      this._on = {};
    }
    addEventListener(t, f) { (this._on[t] = this._on[t] || []).push(f); }
    close() { this.closed = true; }
    emit(t, data) { (this._on[t] || []).forEach(f => f({data: data})); }
  };

  // The ids a page asks for by name. Given as {id: tagName} so a <dialog> gets
  // showModal and an <input> gets a value.
  for (const [id, tag] of Object.entries(ids)) {
    const el = new El(tag || 'div');
    el.id = id;
    byId[id] = el;
    root.appendChild(el);
  }
  return {document, byId, root, El};
}

module.exports = {install, El, matches: _matches};
