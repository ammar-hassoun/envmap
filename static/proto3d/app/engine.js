/* The new look, as an ENGINE and nothing more: a PROTOTYPE.

   The 3D view and the city (cluster3d.js, cluster3d-city.js) decide what is
   where, what it says and what a key does, and hand a list of shapes to their
   engine each frame (cluster3d-gl.js, `window.C3DGL`). This file is another
   engine with the same four doors: `resize`, `draw`, `atlas`, `hdr`. Put in
   that one's place, every pod still talks, blinks and cries, you still walk,
   ride, fly and dance, the doctor still comes: none of that is in here, and
   none of it was touched. Only how a shape is drawn changes.

   Two attempts before this one rebuilt the place and the figures from
   scratch on Three.js. They looked right and did nothing: the pods had no
   soul, because the soul is the three thousand lines this now leaves alone.

   WHAT IS DRAWN DIFFERENTLY
     a solid   (box, ball, soft box) is real geometry, lit by one lamp and the
               room, casting a shadow. The six kinds keep their meaning: an
               island's deck, a plate, a Service's crystal, a gauge, metal
               with a lit edge, and the painted pieces a person is made of
     a pod     is a glazed ceramic ball. Its visor, eyes, tear, belt and cap
               are the old shader's own arithmetic, moved onto the ball's
               surface, so a mood reads exactly as it did
     light     glows, beams and the marks over a pod are the old shaders,
               carried across as they were
     the room  is new: the scene stands in a machine hall (a raised floor, a
               circuit board for walls, racks along them, fans at the ends,
               bars of light overhead). It is scenery and says nothing; every
               face of it looks inward, so from outside it is not in the way

   The camera is the caller's: an eye and three unit vectors, as before, so
   the names and speech it draws over the picture still land on the pods.

   Borrowed: ../three/ (Three.js 0.170.0, MIT). */
import * as THREE from 'three';
import { EffectComposer } from 'three/addons/postprocessing/EffectComposer.js';
import { RenderPass } from 'three/addons/postprocessing/RenderPass.js';
import { UnrealBloomPass } from 'three/addons/postprocessing/UnrealBloomPass.js';
import { OutputPass } from 'three/addons/postprocessing/OutputPass.js';
import { ShaderPass } from 'three/addons/postprocessing/ShaderPass.js';
import { RoomEnvironment } from 'three/addons/environments/RoomEnvironment.js';

// How brightly the traces on the hall's walls glow. They are the largest thing in view on a walk, so they are kept
// well under what blooms: at four times this they were the brightest thing in the room and tiring to walk beside.
const WALL_GLOW = 0.11;
const COLS = 8, SUN = new THREE.Vector3(0.45, 0.85, 0.3).normalize();      // the lamp stands where the old shaders said the light came from
const TURN = `
vec3 c3rz(vec3 v, float a) { float c = cos(a), s = sin(a); return vec3(v.x * c - v.y * s, v.x * s + v.y * c, v.z); }
vec3 c3rx(vec3 v, float a) { float c = cos(a), s = sin(a); return vec3(v.x, v.y * c - v.z * s, v.y * s + v.z * c); }
vec3 c3ry(vec3 v, float a) { float c = cos(a), s = sin(a); return vec3(v.x * c + v.z * s, v.y, -v.x * s + v.z * c); }`;

/* ── a solid: where it stands, as the old vertex shader placed it ── */
const SOLID_PARS = `attribute vec3 iPos; attribute vec3 iSize; attribute vec4 iColG; attribute vec4 iMisc;
varying vec3 vL; varying vec3 vSz; varying vec4 vColG; varying vec4 vMs; varying vec3 vWp;` + TURN + `
// A painted piece (what a person, a ride and a building's small parts are made of) has its edges rounded to a share
// of its own thinnest side: a box only softened, a soft box almost to a pill. Worked out here, at each corner of a
// finely cut cube, so a piece stretched long keeps a round edge instead of a squashed one.
vec3 c3round(vec3 p, vec3 size, float k, inout vec3 n) {
#ifdef C3_ROUND
  if (k > 4.5) { vec3 h = abs(size) * 0.5; float r = min(h.x, min(h.y, h.z)) * C3_ROUND; vec3 q = clamp(p, r - h, h - r), d = p - q; float L = length(d); if (L > 1e-6) { n = d / L; return q + n * r; } }
#endif
  return p;
}`;
const SOLID_NORMAL = `vec3 objectNormal = normal; float c3n = iMisc.w;
if (c3n > 1.5 && c3n < 2.5) objectNormal = c3rx(c3rz(objectNormal, 0.7854), 0.6155);
if (c3n > 4.5) { vec3 c3q = objectNormal / iSize; c3round(position * iSize, iSize, c3n, c3q); objectNormal = c3rz(c3rx(c3q, iMisc.y), iMisc.z); }
objectNormal = normalize(c3ry(objectNormal, iMisc.x));`;
const SOLID_BEGIN = `float c3k = iMisc.w; vec3 transformed = position;
if (c3k > 1.5 && c3k < 2.5) transformed = c3rx(c3rz(transformed, 0.7854), 0.6155);
vL = position; transformed *= iSize; vec3 c3u = vec3(0.0); transformed = c3round(transformed, iSize, c3k, c3u);
if (c3k > 4.5) transformed = c3rz(c3rx(transformed, iMisc.y), iMisc.z);
transformed = c3ry(transformed, iMisc.x) + iPos;
vSz = iSize; vColG = iColG; vMs = iMisc; vWp = transformed;`;
const SOLID_SKIP = '#include <project_vertex>\nif (c3k > 0.5 && c3k < 1.5) gl_Position = vec4(2.0, 2.0, 2.0, 1.0);';      // a plate is see-through: it has a pass of its own
/* what each kind is made of. The light a kind gave off is the old formula; what it is painted with is new. */
const SOLID_PAINT = `#include <color_fragment>
float c3k = vMs.w; vec3 c3c = pow(vColG.rgb, vec3(2.2)); vec3 c3glow = vec3(0.0); float c3r = 0.6, c3m = 0.05;
vec2 c3e = (0.5 - abs(vL.xz)) * vSz.xz; float c3ed = min(c3e.x, c3e.y);
if (c3k < 0.5) {
  diffuseColor.rgb = vec3(0.016, 0.022, 0.045); c3r = 0.5; c3m = 0.35;
  if (vL.y > 0.49) { vec2 gq = vWp.xz / 1.5; vec2 gw = fwidth(gq); vec2 g2 = abs(fract(gq - 0.5) - 0.5) / max(gw, vec2(1e-4));
    c3glow = c3c * (exp(-c3ed * 2.6) * 1.9 * vMs.y + (1.0 - min(min(g2.x, g2.y), 1.0)) * 0.07); }
  else if (vL.y < -0.49) c3glow = c3c * (0.12 + 0.5 * vColG.a) * exp(-c3ed * 0.5);
  else { float h = vL.y + 0.5; c3glow = c3c * (pow(h, 4.0) * 1.7 * vMs.y + (1.0 - h) * (0.10 + 0.5 * vColG.a)); }
} else if (c3k < 2.5) {
  vec3 al = abs(vL); float wire = smoothstep(0.40, 0.5, max(min(al.x, al.y), max(min(al.y, al.z), min(al.x, al.z))));
  diffuseColor.rgb = c3c * 0.25; c3r = 0.1; c3m = 0.9; c3glow = c3c * wire * (1.5 + vColG.a * 1.5);
} else if (c3k < 3.5) { diffuseColor.rgb = vec3(0.0); c3glow = c3c * (1.1 + vColG.a * 2.0); }
else if (c3k < 4.5) {
  vec3 de = (0.5 - abs(vL)) * vSz; float mn = min(de.x, min(de.y, de.z)), mx = max(de.x, max(de.y, de.z)), mid = de.x + de.y + de.z - mn - mx;
  diffuseColor.rgb = vec3(0.022, 0.028, 0.048); c3r = 0.34; c3m = 0.8; c3glow = c3c * smoothstep(0.06, 0.0, mid) * (0.55 + vColG.a);
} else { diffuseColor.rgb = c3c; c3r = 0.6; c3m = 0.04; c3glow = c3c * vColG.a * 2.0; }`;

/* ── a pod: the old face, on a real ball ── */
const ORB_PARS = 'attribute vec4 iPosr; attribute vec4 iCol; attribute vec4 iFace; attribute vec4 iOm;\nvarying vec3 vN0; varying vec4 vOc; varying vec4 vFace; varying vec4 vOm;';
const ORB_BEGIN = 'vec3 transformed = position * iPosr.w * vec3(1.0, max(iOm.z, 0.05), 1.0) + iPosr.xyz; vN0 = position; vOc = iCol; vFace = iFace; vOm = iOm;';
const ORB_FACE_PARS = `uniform float uTime; varying vec3 vN0; varying vec4 vOc; varying vec4 vFace; varying vec4 vOm;
float c3seg(vec2 p, vec2 a, vec2 b) { vec2 pa = p - a, ba = b - a; return length(pa - ba * clamp(dot(pa, ba) / dot(ba, ba), 0.0, 1.0)); }
float c3arc(vec2 p, vec2 c, float r) { return abs(length(p - c) - r); }
vec3 c3cap(float i) {
  if (i < 0.5) return vec3(0.22, 0.48, 0.95); if (i < 1.5) return vec3(0.58, 0.38, 0.95); if (i < 2.5) return vec3(0.95, 0.46, 0.20);
  if (i < 3.5) return vec3(0.16, 0.72, 0.62); if (i < 4.5) return vec3(0.92, 0.68, 0.10); if (i < 5.5) return vec3(0.88, 0.34, 0.62);
  if (i < 6.5) return vec3(0.22, 0.66, 0.90); if (i < 7.5) return vec3(0.36, 0.70, 0.22); if (i < 8.5) return vec3(0.40, 0.44, 0.55);
  return vec3(0.82, 0.52, 0.22); }
#include <common>`;
const ORB_FACE = `#include <color_fragment>
vec3 oN = normalize(vN0); float seed = vFace.w, dimk = vFace.z > 15.5 ? 0.2 : 1.0; int m = int(mod(vFace.z, 16.0) + 0.5);
if (vOc.a < 0.99) { float dn = fract(52.9829189 * fract(dot(gl_FragCoord.xy, vec2(0.06711056, 0.00583715)))); if (dn > vOc.a) discard; }
vec3 lite = pow(vOc.rgb, vec3(2.2)), oGlow = vec3(0.0); float oVis = 0.0;
if (m == 9) { diffuseColor.rgb = lite * 0.5; oGlow = lite * smoothstep(0.06, 0.0, abs(oN.y)) * 1.3; }
else {
  float yaw = vFace.x, pit = vFace.y;
  vec3 Fw = vec3(sin(yaw) * cos(pit), sin(pit), cos(yaw) * cos(pit)), Rt = normalize(cross(vec3(0.0, 1.0, 0.0), Fw)), Up = cross(Fw, Rt);
  vec2 p = vec2(dot(oN, Rt), dot(oN, Up)); float fz = dot(oN, Fw); vec2 pm = vec2(abs(p.x), p.y);
  vec3 body = vec3(0.60, 0.63, 0.70) * dimk;
  if (vOm.x >= 0.0) body = mix(body, pow(c3cap(vOm.x), vec3(2.2)) * dimk, smoothstep(0.50, 0.55, oN.y) * 0.92);
  float belt = smoothstep(0.036, 0.012, abs(oN.y + 0.36));
  float aa = clamp(fwidth(p.x) + fwidth(p.y), 0.004, 0.05);
  float vis = length(max(abs(p - vec2(0.0, 0.10)) - vec2(0.40, 0.085), 0.0)) - 0.17;
  float inVis = (1.0 - smoothstep(-aa, aa, vis)) * smoothstep(0.05, 0.25, fz);
  vec2 eye = vec2(0.24, 0.10); float th = 0.034, sd = 9.0;
  float blink = step(0.968, fract(uTime * 0.23 + seed * 7.0));
  float dots = length((pm - eye) / vec2(1.0, mix(1.0, 0.18, blink))) - 0.075;
  float dash = max(abs(pm.x - eye.x) - 0.085, abs(pm.y - eye.y) - 0.022);
  if (m == 0) sd = max(c3arc(pm, eye - vec2(0.0, 0.055), 0.095) - th, -(pm.y - eye.y + 0.03));
  else if (m == 1) sd = dots - 0.012 * sin(uTime * 22.0);
  else if (m == 2) sd = max(dots, pm.y - eye.y - 0.02 + (pm.x - eye.x) * 0.6);
  else if (m == 3) sd = dash;
  else if (m == 4) sd = max(c3arc(pm, eye, 0.07) - th * 0.8, sin(atan(pm.y - eye.y, pm.x - eye.x) + uTime * 5.0));
  else if (m == 5) sd = dash + 0.01;
  else if (m == 6) sd = c3seg(pm, eye + vec2(-0.085, 0.05), eye + vec2(0.085, -0.05)) - th;
  else if (m == 7) sd = min(c3seg(pm, eye - vec2(0.07), eye + vec2(0.07)), c3seg(pm, eye + vec2(-0.07, 0.07), eye + vec2(0.07, -0.07))) - th * 0.8;
  else sd = dash + 0.008;
  float ink = (1.0 - smoothstep(-aa, aa, sd)) * inVis;
  diffuseColor.rgb = mix(body, vec3(0.004, 0.006, 0.014) * (0.4 + 0.6 * dimk), inVis); oVis = inVis;
  oGlow = lite * (ink * 2.5 + belt * (0.85 + 0.35 * sin(uTime * 2.0 + seed * 20.0)));
  if (m == 6) { float f = fract(uTime * 0.8 + seed), dr = length((pm - vec2(eye.x, eye.y - 0.20 - f * 0.42)) / vec2(0.035, 0.06));
    oGlow += vec3(0.5, 0.85, 1.0) * 1.5 * smoothstep(1.0, 0.6, dr) * (1.0 - f) * step(0.15, fz) * dimk; }
  if (m == 4) oGlow += lite * smoothstep(0.035, 0.0, abs(oN.y - (fract(uTime * 0.5 + seed) * 2.0 - 1.0))) * 1.6;
}`;

/* ── small pictures drawn in code, for the room ── */
function paper(draw, w, h, repeat) {
  const c = document.createElement('canvas'); c.width = w; c.height = h; draw(c.getContext('2d'), w, h);
  const t = new THREE.CanvasTexture(c); t.colorSpace = THREE.SRGBColorSpace; t.anisotropy = 8;
  if (repeat) { t.wrapS = t.wrapT = THREE.RepeatWrapping; t.repeat.set(repeat[0], repeat[1]); }
  return t;
}
function rnd(seed) { let a = seed >>> 0; return () => { a = a + 0x6D2B79F5 | 0; let t = Math.imul(a ^ a >>> 15, 1 | a); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; }; }
function rackFace(seed) {      // the front of a rack: a column of machines, each with its vents and its lights
  const r = rnd(seed), leds = [], W = 256, H = 640;
  const map = paper((g, w, h) => {
    g.fillStyle = '#0b0e13'; g.fillRect(0, 0, w, h); g.fillStyle = '#141920'; g.fillRect(8, 10, w - 16, h - 20);
    for (let y = 18; y < h - 44;) {
      const u = r() < 0.28 ? 60 : 30; g.fillStyle = r() < 0.5 ? '#1b2029' : '#222935'; g.fillRect(16, y, w - 32, u - 4);
      g.fillStyle = 'rgba(0,0,0,.5)'; for (let x = 62; x < w - 62; x += 11) g.fillRect(x, y + 4, 6, u - 12);
      for (let i = 0, n = 1 + (r() * 3 | 0); i < n; i++) leds.push([24 + i * 11, y + (u - 4) / 2, r() < 0.76 ? '#3dff9e' : r() < 0.55 ? '#ffb23d' : '#4cc9ff']);
      y += u;
    }
    leds.forEach(([x, y, c]) => { g.fillStyle = c; g.fillRect(x, y - 3, 7, 6); });
  }, W, H);
  const glow = paper((g, w, h) => { g.fillStyle = '#000'; g.fillRect(0, 0, w, h); leds.forEach(([x, y, c]) => { g.fillStyle = c; g.fillRect(x - 1, y - 4, 9, 8); }); g.fillStyle = '#2f7dff'; g.fillRect(8, 3, w - 16, 5); }, W, H);
  return new THREE.MeshStandardMaterial({ map, emissiveMap: glow, emissive: 0xffffff, emissiveIntensity: 1.6, roughness: 0.5, metalness: 0.5 });
}
function boardWall() {      // the hall's walls are a circuit board: traces that turn at forty-five degrees and end in a pad
  const r = rnd(7), runs = [];
  for (let i = 0; i < 90; i++) { let x = r() * 1024, y = r() * 512; const pts = [[x, y]]; for (let k = 0; k < 5; k++) { const len = 30 + r() * 150, dir = (r() * 8 | 0) * Math.PI / 4; x += Math.cos(dir) * len; y += Math.sin(dir) * len; pts.push([x, y]); } runs.push(pts); }
  const draw = (bg, ink, wide) => (g, w, h) => {
    g.fillStyle = bg; g.fillRect(0, 0, w, h); g.strokeStyle = g.fillStyle = ink; g.lineWidth = wide; g.lineJoin = 'round';
    runs.forEach((pts) => { g.beginPath(); pts.forEach(([x, y], i) => (i ? g.lineTo(x, y) : g.moveTo(x, y))); g.stroke(); const [x, y] = pts[pts.length - 1]; g.beginPath(); g.arc(x, y, wide * 1.9, 0, 7); g.fill(); });
  };
  return new THREE.MeshStandardMaterial({ map: paper(draw('#04110e', '#0c4438', 5), 1024, 512, [3, 1]), emissiveMap: paper(draw('#000', '#17a88c', 3), 1024, 512, [3, 1]), emissive: 0xffffff, emissiveIntensity: WALL_GLOW, roughness: 0.65, metalness: 0.3 });
}
const floorTiles = () => paper((g, w, h) => {      // a raised floor: square tiles on a frame, one in four perforated
  const r = rnd(11); g.fillStyle = '#1a2130'; g.fillRect(0, 0, w, h);
  for (let i = 0; i < 2; i++) for (let j = 0; j < 2; j++) {
    const x = i * w / 2, y = j * h / 2; g.fillStyle = (i + j) % 2 ? '#1d2534' : '#18202d'; g.fillRect(x + 3, y + 3, w / 2 - 6, h / 2 - 6);
    g.fillStyle = 'rgba(150,180,230,.09)'; g.fillRect(x + 3, y + 3, w / 2 - 6, 2);
    if (i === 1 && j === 0) { g.fillStyle = 'rgba(0,0,0,.6)'; for (let a = 14; a < w / 2 - 10; a += 10) for (let b = 14; b < h / 2 - 10; b += 10) g.fillRect(x + a, y + b, 4, 4); }
  }
  for (let i = 0; i < 500; i++) { g.fillStyle = `rgba(255,255,255,${r() * 0.035})`; g.fillRect(r() * w, r() * h, 2, 2); }
}, 256, 256);

function roundable() {      // a cube cut finer toward its faces, so there is something to bend where an edge is rounded
  const g = new THREE.BoxGeometry(1, 1, 1, 6, 6, 6), at = g.attributes.position, near = (t) => Math.sign(t) * 0.5 * Math.pow(Math.abs(t) * 2, 0.6);
  for (let i = 0; i < at.count; i++) at.setXYZ(i, near(at.getX(i)), near(at.getY(i)), near(at.getZ(i)));
  return g;
}

/* Words as solid letters, in whatever bold face this machine has: the word is drawn on a hidden canvas, the outline of
   what was inked is walked (every edge between an inked dot and a bare one, joined end to end into loops), the
   stair-steps are straightened and the corners eased, and the loops become shapes with their holes. No font is
   shipped for it. The baseline is y = 0 and a unit is a dot of a 150-dot letter. */
const INK = 150;
function traced(text) {
  const c = document.createElement('canvas'), face = '900 ' + INK + 'px "Arial Black", "Helvetica Neue", Helvetica, Arial, system-ui, sans-serif';
  let g = c.getContext('2d'); g.font = face;
  const w = Math.ceil(g.measureText(text).width) + 8, h = Math.ceil(INK * 1.25), base = Math.round(INK * 0.98);
  c.width = w; c.height = h; g = c.getContext('2d', { willReadFrequently: true }); g.font = face; g.fillStyle = '#fff'; g.fillText(text, 4, base);
  const a = g.getImageData(0, 0, w, h).data, on = (x, y) => x >= 0 && y >= 0 && x < w && y < h && a[(y * w + x) * 4 + 3] > 127, next = new Map(), key = (x, y) => x * 4096 + y;
  const edge = (x0, y0, x1, y1) => { const k = key(x0, y0); if (!next.has(k)) next.set(k, []); next.get(k).push([x1, y1]); };
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
    if (!on(x, y)) continue;
    if (!on(x, y - 1)) edge(x, y, x + 1, y); if (!on(x + 1, y)) edge(x + 1, y, x + 1, y + 1);
    if (!on(x, y + 1)) edge(x + 1, y + 1, x, y + 1); if (!on(x - 1, y)) edge(x, y + 1, x, y);
  }
  const far = (pts, i, j, keep, eps) => {      // keep only the points a straight line between two others would miss
    let worst = 0, at = -1; const [ax, ay] = pts[i], [bx, by] = pts[j], len = Math.hypot(bx - ax, by - ay) || 1;
    for (let k = i + 1; k < j; k++) { const d = Math.abs((bx - ax) * (ay - pts[k][1]) - (ax - pts[k][0]) * (by - ay)) / len; if (d > worst) { worst = d; at = k; } }
    if (worst > eps) { far(pts, i, at, keep, eps); keep.push(at); far(pts, at, j, keep, eps); }
  };
  const path = new THREE.ShapePath();
  while (next.size) {
    const start = next.keys().next().value, sx = Math.floor(start / 4096), sy = start % 4096, loop = []; let x = sx, y = sy;
    for (;;) { const k = key(x, y), outs = next.get(k); if (!outs) break; const to = outs.pop(); if (!outs.length) next.delete(k); loop.push([x, y]); x = to[0]; y = to[1]; if (x === sx && y === sy) break; }
    if (loop.length < 8) continue;
    const half = loop.length >> 1, keep = [0]; far(loop, 0, half, keep, 0.9); keep.push(half); far(loop.concat([loop[0]]), half, loop.length, keep, 0.9);
    let pts = keep.filter((k) => k < loop.length).map((k) => loop[k]);
    const eased = []; for (let i = 0; i < pts.length; i++) { const p = pts[i], q = pts[(i + 1) % pts.length]; eased.push([p[0] * 0.8 + q[0] * 0.2, p[1] * 0.8 + q[1] * 0.2], [p[0] * 0.2 + q[0] * 0.8, p[1] * 0.2 + q[1] * 0.8]); }
    pts = eased; if (pts.length < 3) continue;
    pts.forEach(([px, py], i) => (i ? path.lineTo(px, base - py) : path.moveTo(px, base - py)));
  }
  return { shapes: path.toShapes(false), w: w - 4 };
}
function heartShape(wide, tall) {
  const sh = new THREE.Shape(), n = 72;
  for (let i = 0; i <= n; i++) {
    const t = i / n * Math.PI * 2, hx = 16 * Math.sin(t) ** 3, hy = 13 * Math.cos(t) - 5 * Math.cos(2 * t) - 2 * Math.cos(3 * t) - Math.cos(4 * t);
    const X = wide / 2 + hx / 32 * wide, Y = (hy + 17) / 30 * tall; if (i) sh.lineTo(X, Y); else sh.moveTo(X, Y);
  }
  return sh;
}

function make(canvas) {
  const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, powerPreference: 'high-performance' });
  renderer.shadowMap.enabled = true; renderer.shadowMap.type = THREE.PCFSoftShadowMap;
  renderer.toneMapping = THREE.ACESFilmicToneMapping; renderer.toneMappingExposure = 1.0;
  const scene = new THREE.Scene(), camera = new THREE.PerspectiveCamera(50, 1, 0.3, 1600), basis = new THREE.Matrix4();
  scene.environment = new THREE.PMREMGenerator(renderer).fromScene(new RoomEnvironment(), 0.04).texture; scene.environmentIntensity = 0.45;
  scene.fog = new THREE.FogExp2(0x061224, 0.004);
  const sun = new THREE.DirectionalLight(0xdfeaff, 2.4); sun.castShadow = true; sun.shadow.mapSize.set(4096, 4096); sun.shadow.bias = -0.0004; sun.shadow.normalBias = 0.05;
  scene.add(sun, sun.target, new THREE.HemisphereLight(0x6a92ff, 0x0c1320, 0.8));
  // a second, soft light that looks where you look, so whoever you are facing is never a black shape against the hall
  const fill = new THREE.DirectionalLight(0xc8d6ff, 0.75); scene.add(fill, fill.target);
  const composer = new EffectComposer(renderer), bloom = new UnrealBloomPass(new THREE.Vector2(1, 1), 0.5, 0.65, 0.9);
  composer.addPass(new RenderPass(scene, camera)); composer.addPass(bloom); composer.addPass(new OutputPass());
  composer.addPass(new ShaderPass({ uniforms: { tDiffuse: { value: null } },      // the grade: a little more colour and contrast, and the corners fall away
    vertexShader: 'varying vec2 vUv; void main() { vUv = uv; gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0); }',
    fragmentShader: `uniform sampler2D tDiffuse; varying vec2 vUv;
      void main() { vec3 c = texture2D(tDiffuse, vUv).rgb; c = mix(vec3(dot(c, vec3(0.299, 0.587, 0.114))), c, 1.14); c = (c - 0.5) * 1.06 + 0.5;
        vec2 q = vUv - 0.5; gl_FragColor = vec4(c * (1.0 - dot(q, q) * 0.6), 1.0); }` }));
  const U = { uTime: { value: 0 }, uRes: { value: new THREE.Vector2(1, 1) }, uPx: { value: new THREE.Vector2(1, 1) }, uFocal: { value: 1 }, uDpr: { value: 1 },
    uEye: { value: new THREE.Vector3() }, uR: { value: new THREE.Vector3(1, 0, 0) }, uU: { value: new THREE.Vector3(0, 1, 0) }, uF: { value: new THREE.Vector3(0, 0, -1) },
    uMood: { value: 0 }, uPulse: { value: 9 }, uGridY: { value: 0 }, uSpan: { value: 30 }, uIsles: { value: 0 }, uIsle: { value: new Float32Array(96) }, uIsleCol: { value: new Float32Array(72) },
    uAtlas: { value: null }, uBox: { value: new THREE.Vector3() } };
  let W = 1, H = 1;

  /* ── a list of shapes, read straight out of the caller's own array ── */
  function bank(base, stride, fields) {
    const geo = new THREE.InstancedBufferGeometry(); geo.index = base.index; for (const k in base.attributes) geo.setAttribute(k, base.attributes[k]);
    geo.instanceCount = 0; const one = { geo, stride, fields, arr: null, buf: null };
    one.take = (arr, n) => {
      if (!arr) { geo.instanceCount = 0; return; }
      if (one.arr !== arr) {      // the caller's array itself is the buffer: nothing is copied on the way
        one.arr = arr; one.buf = new THREE.InstancedInterleavedBuffer(arr, stride); one.buf.setUsage(THREE.DynamicDrawUsage);
        let off = 0; fields.forEach(([name, size]) => { geo.setAttribute(name, new THREE.InterleavedBufferAttribute(one.buf, size, off)); off += size; });
      }
      geo.instanceCount = n; if (n) { one.buf.clearUpdateRanges(); one.buf.addUpdateRange(0, n * stride); one.buf.needsUpdate = true; }
    };
    return one;
  }
  const shown = (geo, mat, order) => { const m = new THREE.Mesh(geo, mat); m.frustumCulled = false; if (order != null) m.renderOrder = order; scene.add(m); return m; };
  const SOLID = [['iPos', 3], ['iSize', 3], ['iColG', 4], ['iMisc', 4]], ORB = [['iPosr', 4], ['iCol', 4], ['iFace', 4], ['iOm', 4]];

  // one paint for each shape, differing only in how far an edge is rounded: a ball is round already
  const painted = (round) => {
    const paint = new THREE.MeshStandardMaterial({ roughness: 0.6, metalness: 0.05 }), depth = new THREE.MeshDepthMaterial({ depthPacking: THREE.RGBADepthPacking }), def = round ? '#define C3_ROUND ' + round.toFixed(2) + '\n' : '';
    paint.onBeforeCompile = (s) => {
      s.vertexShader = def + s.vertexShader.replace('#include <common>', SOLID_PARS + '\n#include <common>').replace('#include <beginnormal_vertex>', SOLID_NORMAL).replace('#include <begin_vertex>', SOLID_BEGIN).replace('#include <project_vertex>', SOLID_SKIP);
      s.fragmentShader = s.fragmentShader.replace('#include <common>', 'varying vec3 vL; varying vec3 vSz; varying vec4 vColG; varying vec4 vMs; varying vec3 vWp;\n#include <common>').replace('#include <color_fragment>', SOLID_PAINT)
        .replace('#include <roughnessmap_fragment>', '#include <roughnessmap_fragment>\nroughnessFactor = c3r;').replace('#include <metalnessmap_fragment>', '#include <metalnessmap_fragment>\nmetalnessFactor = c3m;')
        .replace('#include <emissivemap_fragment>', '#include <emissivemap_fragment>\ntotalEmissiveRadiance += c3glow * 1.5;');
    };
    depth.onBeforeCompile = (s) => { s.vertexShader = def + s.vertexShader.replace('#include <common>', SOLID_PARS + '\n#include <common>').replace('#include <begin_vertex>', SOLID_BEGIN).replace('#include <project_vertex>', SOLID_SKIP); };
    paint.customProgramCacheKey = depth.customProgramCacheKey = () => 'c3paint' + round;
    return [paint, depth];
  };
  /* a plate: only its top, see-through, brightest at its edge. The old fragment shader, as it was. */
  const plate = new THREE.ShaderMaterial({ transparent: true, depthWrite: false,
    vertexShader: SOLID_PARS + `\nvoid main() { ${SOLID_BEGIN} gl_Position = projectionMatrix * viewMatrix * vec4(transformed, 1.0); if (!(c3k > 0.5 && c3k < 1.5) || normal.y < 0.5) gl_Position = vec4(2.0, 2.0, 2.0, 1.0); }`,
    fragmentShader: `varying vec3 vL; varying vec3 vSz; varying vec4 vColG; varying vec4 vMs;
      void main() { vec2 e = (0.5 - abs(vL.xz)) * vSz.xz; float edge = smoothstep(0.14, 0.0, min(e.x, e.y)); gl_FragColor = vec4(pow(vColG.rgb, vec3(2.2)) * (0.5 + edge * 1.6), vMs.z * (0.10 + edge * 0.42)); }` });
  const boxGeo = roundable(), ballGeo = new THREE.SphereGeometry(0.5, 28, 20), softGeo = roundable();
  const boxes = bank(boxGeo, 14, SOLID), balls = bank(ballGeo, 14, SOLID), softs = bank(softGeo, 14, SOLID);
  [[boxes, 0.45], [balls, 0], [softs, 0.92]].forEach(([b, round]) => { const [paint, depth] = painted(round), m = shown(b.geo, paint); m.castShadow = m.receiveShadow = true; m.customDepthMaterial = depth; });
  shown(boxes.geo, plate, 4);

  const glaze = new THREE.MeshPhysicalMaterial({ roughness: 0.3, metalness: 0, clearcoat: 0.7, clearcoatRoughness: 0.18, envMapIntensity: 0.55 });
  glaze.onBeforeCompile = (s) => {
    s.uniforms.uTime = U.uTime;
    s.vertexShader = s.vertexShader.replace('#include <common>', ORB_PARS + '\n#include <common>').replace('#include <beginnormal_vertex>', 'vec3 objectNormal = normalize(normal / vec3(1.0, max(iOm.z, 0.05), 1.0));').replace('#include <begin_vertex>', ORB_BEGIN);
    s.fragmentShader = s.fragmentShader.replace('#include <common>', ORB_FACE_PARS).replace('#include <color_fragment>', ORB_FACE)
      .replace('#include <roughnessmap_fragment>', '#include <roughnessmap_fragment>\nroughnessFactor = mix(0.3, 0.07, oVis);')
      .replace('#include <emissivemap_fragment>', '#include <emissivemap_fragment>\ntotalEmissiveRadiance += oGlow * 1.5;');
  };
  const glazeDepth = new THREE.MeshDepthMaterial({ depthPacking: THREE.RGBADepthPacking });
  glazeDepth.onBeforeCompile = (s) => { s.vertexShader = s.vertexShader.replace('#include <common>', ORB_PARS + '\n#include <common>').replace('#include <begin_vertex>', ORB_BEGIN); };
  const orbGeo = new THREE.SphereGeometry(1, 44, 30), orbs = bank(orbGeo, 16, ORB), pod = shown(orbs.geo, glaze);
  pod.castShadow = pod.receiveShadow = true; pod.customDepthMaterial = glazeDepth;
  /* the bubble round a pod is its memory limit, filled to what it uses: the old shader, on a ball a little larger */
  shown(orbs.geo, new THREE.ShaderMaterial({ uniforms: { uTime: U.uTime }, transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
    vertexShader: ORB_PARS + `\nvarying vec3 vView; void main() { vec3 w = position * iPosr.w * 1.42 * vec3(1.0, max(iOm.z, 0.05), 1.0) + iPosr.xyz; vN0 = position; vOc = iCol; vFace = iFace; vOm = iOm; vView = cameraPosition - w;
      gl_Position = iOm.y < 0.0 ? vec4(2.0, 2.0, 2.0, 1.0) : projectionMatrix * viewMatrix * vec4(w, 1.0); }`,
    fragmentShader: `uniform float uTime; varying vec3 vN0; varying vec4 vOc; varying vec4 vFace; varying vec4 vOm; varying vec3 vView;
      void main() { vec3 N = normalize(vN0); float nz = abs(dot(N, normalize(vView))); float level = floor(vOm.y), fill = fract(vOm.y) / 0.999;
        vec3 tone = level > 1.5 ? vec3(1.0, 0.22, 0.30) : level > 0.5 ? vec3(1.0, 0.66, 0.14) : vec3(0.22, 0.95, 0.62);
        float h = N.y * 0.5 + 0.5 + 0.012 * sin(uTime * 2.2 + N.x * 7.0 + vFace.w * 30.0), fres = pow(1.0 - nz, 2.4), surf = exp(-pow((h - fill) / 0.03, 2.0));
        gl_FragColor = vec4(tone * (fres * 0.75 + step(h, fill) * 0.06 + surf * 0.4 * (1.0 - fres * 0.6)) * vOc.a * 0.6, 1.0); }` }), 5);
  /* In a hall every pod stands on a light of its own colour, which is its state: the eyes say it from the front, and
     this says it from across the room and from above. Read from the same list of pods; a thing that is not a pod, a
     pod in the air and a pod that is fading get none. */
  const lit = bank(new THREE.CircleGeometry(1, 28), 16, ORB);
  const podLights = shown(lit.geo, new THREE.ShaderMaterial({ transparent: true, depthWrite: false, polygonOffset: true, polygonOffsetFactor: -3, polygonOffsetUnits: -3,
    vertexShader: ORB_PARS + `\nvarying vec2 vC; varying vec3 vTint;
      void main() { vC = position.xy; vN0 = position; vOc = iCol; vFace = iFace; vOm = iOm; vTint = pow(iCol.rgb, vec3(2.2)) * (iFace.z > 15.5 ? 0.25 : 1.0);
        bool pod = mod(iFace.z, 16.0) < 8.5 && iPosr.y < iPosr.w * 3.0 && iCol.a > 0.99;
        gl_Position = pod ? projectionMatrix * viewMatrix * vec4(iPosr.x + position.x * iPosr.w * 1.5, 0.075, iPosr.z + position.y * iPosr.w * 1.5, 1.0) : vec4(2.0, 2.0, 2.0, 1.0); }`,
    fragmentShader: 'varying vec2 vC; varying vec3 vTint;\nvoid main() { float d = length(vC); gl_FragColor = vec4(vTint * (0.5 + 0.9 * smoothstep(0.7, 1.0, d)), smoothstep(1.0, 0.93, d) * 0.92); }', side: THREE.DoubleSide }), 2);
  podLights.visible = false;
  /* the ring round what is chosen or pointed at */
  const rings = [], ringGeo = new THREE.RingGeometry(1.07, 1.19, 48);
  for (let i = 0; i < 8; i++) { const r = shown(ringGeo, new THREE.MeshBasicMaterial({ color: 0xffffff, side: THREE.DoubleSide }), 6); r.visible = false; rings.push(r); }

  /* ── light that is only light: the old shaders, carried across ── */
  const quad = new THREE.BufferGeometry(); quad.setAttribute('position', new THREE.BufferAttribute(new Float32Array([-1, -1, 0, 1, -1, 0, -1, 1, 0, 1, 1, 0]), 3)); quad.setIndex([0, 1, 2, 2, 1, 3]);
  const strip = new THREE.BufferGeometry(); strip.setAttribute('position', new THREE.BufferAttribute(new Float32Array([0, -1, 0, 1, -1, 0, 0, 1, 0, 1, 1, 0]), 3)); strip.setIndex([0, 1, 2, 2, 1, 3]);
  const added = { transparent: true, depthWrite: false, blending: THREE.AdditiveBlending };
  const glows = bank(quad, 8, [['iPosr', 4], ['iCol', 4]]);
  shown(glows.geo, new THREE.ShaderMaterial(Object.assign({ uniforms: { uR: U.uR, uU: U.uU },
    vertexShader: 'attribute vec4 iPosr; attribute vec4 iCol; uniform vec3 uR, uU; varying vec2 vC; varying vec4 vCol;\nvoid main() { vC = position.xy; vCol = iCol; gl_Position = projectionMatrix * viewMatrix * vec4(iPosr.xyz + (uR * position.x + uU * position.y) * iPosr.w, 1.0); }',
    fragmentShader: 'varying vec2 vC; varying vec4 vCol;\nvoid main() { float f = max(exp(-dot(vC, vC) * 4.5) - 0.011, 0.0); gl_FragColor = vec4(pow(vCol.rgb, vec3(2.2)) * f * vCol.a * 1.25, 1.0); }' }, added)), 7);
  const beams = bank(strip, 16, [['iA', 3], ['iB', 3], ['iCol', 4], ['iW', 4], ['iD', 2]]);
  shown(beams.geo, new THREE.ShaderMaterial(Object.assign({ uniforms: { uTime: U.uTime, uRes: U.uRes, uFocal: U.uFocal },
    vertexShader: `attribute vec3 iA; attribute vec3 iB; attribute vec4 iCol; attribute vec4 iW; attribute vec2 iD; uniform vec2 uRes; uniform float uFocal;
      varying float vSide; varying float vU; varying vec4 vCol; varying vec4 vW; varying vec2 vD;
      void main() { vec4 pa = projectionMatrix * viewMatrix * vec4(iA, 1.0), pb = projectionMatrix * viewMatrix * vec4(iB, 1.0);
        if (pa.w < 0.3 || pb.w < 0.3) { gl_Position = vec4(2.0, 2.0, 2.0, 1.0); return; }
        vec2 dir = (pb.xy / pb.w - pa.xy / pa.w) * uRes; float len = length(dir); dir = len > 1e-4 ? dir / len : vec2(1.0, 0.0);
        vec4 p = mix(pa, pb, position.x); float px = max(iW.x * uFocal / p.w, 1.1); if (iW.x < 0.12) px = min(px, 5.0);
        p.xy += vec2(-dir.y, dir.x) * position.y * px / (uRes * 0.5) * p.w;
        vSide = position.y; vU = mix(iW.y, iW.z, position.x); vCol = iCol; vW = iW; vD = iD; gl_Position = p; }`,
    fragmentShader: `uniform float uTime; varying float vSide; varying float vU; varying vec4 vCol; varying vec4 vW; varying vec2 vD;
      void main() { float core = exp(-vSide * vSide * 4.5), pk = 0.0;
        if (vD.x > 0.0) { float ph = fract(vU * vD.x - uTime * vW.w + vD.y); pk = smoothstep(0.0, 0.05, ph) * smoothstep(0.32, 0.05, ph); }
        gl_FragColor = vec4(pow(vCol.rgb, vec3(2.2)) * (vCol.a * core * (0.5 + pk * 3.4)) * 1.25, 1.0); }` }, added)), 8);
  /* The dark under each pod. A deck is dark and lit by its own edge, so the lamp's shadow hardly shows on it: the
     old disc is what stands a pod on its deck, and it stays. */
  const discs = bank(quad, 4, [['iS', 4]]);
  shown(discs.geo, new THREE.ShaderMaterial({ transparent: true, depthWrite: false, blending: THREE.CustomBlending, blendSrc: THREE.ZeroFactor, blendDst: THREE.OneMinusSrcAlphaFactor, polygonOffset: true, polygonOffsetFactor: -2, polygonOffsetUnits: -2,
    vertexShader: 'attribute vec4 iS; varying vec2 vC; varying float vA;\nvoid main() { vC = position.xy; vA = iS.w; gl_Position = projectionMatrix * viewMatrix * vec4(iS.x + position.x * iS.z, 0.03, iS.y + position.y * iS.z, 1.0); }',
    fragmentShader: 'varying vec2 vC; varying float vA;\nvoid main() { gl_FragColor = vec4(0.0, 0.0, 0.0, vA * smoothstep(1.0, 0.15, length(vC))); }', side: THREE.DoubleSide }), 3);
  /* the marks that float over a pod: one sheet of them, drawn as the caller asks */
  const sheet = document.createElement('canvas'); sheet.width = sheet.height = COLS * 128;
  const marks = {}, sheetTex = new THREE.CanvasTexture(sheet); let markN = 0; sheetTex.flipY = false; sheetTex.colorSpace = THREE.SRGBColorSpace; U.uAtlas.value = sheetTex;
  const sprites = bank(quad, 8, [['iPosr', 4], ['iG', 4]]);
  shown(sprites.geo, new THREE.ShaderMaterial({ uniforms: { uR: U.uR, uU: U.uU, uAtlas: U.uAtlas }, transparent: true, depthWrite: false, blending: THREE.CustomBlending, blendSrc: THREE.OneFactor, blendDst: THREE.OneMinusSrcAlphaFactor,
    vertexShader: `attribute vec4 iPosr; attribute vec4 iG; uniform vec3 uR, uU; varying vec2 vC; varying vec4 vG;
      void main() { float c = cos(iG.z), s = sin(iG.z); vec2 r = vec2(position.x * c - position.y * s, position.x * s + position.y * c); vC = position.xy; vG = iG;
        gl_Position = projectionMatrix * viewMatrix * vec4(iPosr.xyz + (uR * r.x + uU * r.y) * iPosr.w, 1.0); }`,
    fragmentShader: `uniform sampler2D uAtlas; varying vec2 vC; varying vec4 vG;
      void main() { vec2 uv = vC * 0.5 + 0.5, cell = vec2(mod(vG.x, ${COLS}.0), floor(vG.x / ${COLS}.0)); vec4 t = texture2D(uAtlas, (cell + vec2(uv.x, 1.0 - uv.y)) / ${COLS}.0); gl_FragColor = vec4(t.rgb * t.a, t.a) * vG.y; }` }), 9);
  function atlas(list) {
    const k = sheet.getContext('2d'); let fresh = false;
    list.forEach((ch) => {
      const name = ch.key || ch; if (marks[name] != null || markN >= COLS * COLS) return;
      const i = markN++, cx = (i % COLS) * 128 + 64, cy = Math.floor(i / COLS) * 128 + 64; marks[name] = i; fresh = true;
      if (ch.draw) { k.save(); ch.draw(k, cx, cy, 54); k.restore(); return; }
      k.font = '96px "Apple Color Emoji","Segoe UI Emoji","Noto Color Emoji",sans-serif'; k.textAlign = 'center'; k.textBaseline = 'middle'; k.fillText(ch, cx, cy + 6);
    });
    if (fresh) sheetTex.needsUpdate = true;
    return marks;
  }

  /* ── what you ride ──
     The view says which ride, where it stands, how it leans and a number that turns its wheels (`props`). The
     models are made here, once each: tyres that are round, frames of bent tube, bodywork with a curve to it. They
     are the same five rides the view knows, with the seat, the bars and the deck where its rider's pose expects. */
  const garage = {};
  const buildRide = (() => {
    const std = (hex, rough, metal) => new THREE.MeshStandardMaterial({ color: hex, roughness: rough, metalness: metal });
    const gloss = (hex) => new THREE.MeshPhysicalMaterial({ color: hex, roughness: 0.32, metalness: 0.15, clearcoat: 1, clearcoatRoughness: 0.08 });
    const glow = (hex, k) => new THREE.MeshBasicMaterial({ color: new THREE.Color(hex).multiplyScalar(k) });
    const RUBBER = std(0x101114, 0.92, 0), CHROME = std(0xc9ced8, 0.18, 1), DARK = std(0x1a1d24, 0.5, 0.7), SEAT = std(0x15161a, 0.72, 0.05), WOOD = std(0xb9814a, 0.55, 0.05), GRIP = std(0x0c0d10, 0.95, 0);
    const V = (x, y, z) => new THREE.Vector3(x, y, z), UP = V(0, 1, 0);
    const bar = (g, a, b, r, mat) => { const d = b.clone().sub(a), m = new THREE.Mesh(new THREE.CylinderGeometry(r, r, d.length(), 12), mat); m.position.copy(a).addScaledVector(d, 0.5); m.quaternion.setFromUnitVectors(UP, d.normalize()); g.add(m); return m; };
    const pipe = (g, pts, r, mat) => { const m = new THREE.Mesh(new THREE.TubeGeometry(new THREE.CatmullRomCurve3(pts), pts.length * 8, r, 10), mat); g.add(m); return m; };
    const ball = (g, r, mat, x, y, z, sx = 1, sy = 1, sz = 1) => { const m = new THREE.Mesh(new THREE.SphereGeometry(r, 20, 14), mat); m.position.set(x, y, z); m.scale.set(sx, sy, sz); g.add(m); return m; };
    const ease = (pts, times) => { let q = pts; for (let k = 0; k < times; k++) { const out = []; for (let i = 0; i < q.length; i++) { const a = q[i], b = q[(i + 1) % q.length]; out.push([a[0] * 0.75 + b[0] * 0.25, a[1] * 0.75 + b[1] * 0.25], [a[0] * 0.25 + b[0] * 0.75, a[1] * 0.25 + b[1] * 0.75]); } q = out; } return q; };
    // a body panel: its outline seen from the side, as [ahead, up] points round it, pushed out to a width with its edge turned over
    const panel = (g, pts, wide, mat, turn = 0.02, round = 2, x = 0) => {
      const sh = new THREE.Shape(); ease(pts, round).forEach(([z, y], i) => (i ? sh.lineTo(z, y) : sh.moveTo(z, y))); sh.closePath();
      const geo = new THREE.ExtrudeGeometry(sh, { depth: Math.max(0.001, wide - turn * 2), bevelEnabled: true, bevelSize: turn, bevelThickness: turn, bevelSegments: 4, curveSegments: 8 });
      geo.translate(0, 0, turn - wide / 2); geo.rotateY(-Math.PI / 2);
      const m = new THREE.Mesh(geo, mat); m.position.x = x; g.add(m); return m;
    };
    const wheel = (R, w, spokes, hub, tyreMat) => {      // it rolls about the axle: a tyre, a rim, spokes and a hub
      const g = new THREE.Group(), tyre = new THREE.Mesh(new THREE.TorusGeometry(R - w * 0.5, w * 0.5, 16, 40), tyreMat || RUBBER), rim = new THREE.Mesh(new THREE.TorusGeometry(R - w, Math.max(0.006, w * 0.16), 8, 36), CHROME);
      const core = new THREE.Mesh(new THREE.CylinderGeometry(hub, hub, w * 0.9, 16), CHROME);
      tyre.rotation.y = rim.rotation.y = Math.PI / 2; core.rotation.z = Math.PI / 2; g.add(tyre, rim, core);
      for (let i = 0; i < spokes; i++) { const a = i * Math.PI * 2 / spokes; bar(g, V(0, 0, 0), V(0, Math.cos(a) * (R - w), Math.sin(a) * (R - w)), spokes > 8 ? 0.004 : hub * 0.5, CHROME); }
      return g;
    };
    return (kind) => {
      const g = new THREE.Group(), wheels = [], on = (w, x, y, z) => { w.position.set(x, y, z); g.add(w); wheels.push(w); };
      if (kind === 1) {             // a skateboard: a deck kicked up at each end, grip on top, two trucks, four small wheels
        panel(g, [[-0.43, 0.135], [-0.33, 0.1], [0.33, 0.1], [0.43, 0.135], [0.43, 0.152], [0.33, 0.118], [-0.33, 0.118], [-0.43, 0.152]], 0.23, WOOD, 0.01, 1);
        panel(g, [[-0.41, 0.146], [-0.33, 0.119], [0.33, 0.119], [0.41, 0.146], [0.41, 0.152], [0.33, 0.125], [-0.33, 0.125], [-0.41, 0.152]], 0.2, GRIP, 0.004, 1);
        for (const z of [-0.27, 0.27]) { bar(g, V(-0.1, 0.045, z), V(0.1, 0.045, z), 0.011, CHROME); bar(g, V(0, 0.045, z), V(0, 0.1, z), 0.03, CHROME); for (const x of [-0.1, 0.1]) on(wheel(0.042, 0.036, 0, 0.016, std(0xf0f2f5, 0.4, 0)), x, 0.042, z); }
      } else if (kind === 2) {      // a bicycle: a diamond of thin tube, spoked wheels, a saddle, bars, a chainring and pedals
        const RED = gloss(0xd22630), BB = V(0, 0.24, -0.04), ST = V(0, 0.57, -0.12), HT = V(0, 0.6, 0.3), HB = V(0, 0.5, 0.33);
        [[BB, ST], [ST, HT], [BB, HB], [HB, HT]].forEach(([a, b]) => bar(g, a, b, 0.013, RED));
        for (const x of [-0.035, 0.035]) { bar(g, V(x, 0.5, 0.33), V(x, 0.22, 0.44), 0.01, CHROME); bar(g, V(x, 0.24, -0.04), V(x, 0.22, -0.44), 0.009, RED); bar(g, V(x * 0.5, 0.57, -0.12), V(x, 0.22, -0.44), 0.008, RED); }
        bar(g, ST, V(0, 0.64, -0.13), 0.011, CHROME); panel(g, [[-0.25, 0.63], [-0.23, 0.665], [-0.03, 0.66], [0.02, 0.645], [-0.1, 0.625]], 0.1, SEAT, 0.02);
        bar(g, HT, V(0, 0.76, 0.37), 0.011, CHROME); pipe(g, [V(-0.22, 0.77, 0.34), V(-0.12, 0.78, 0.39), V(0, 0.775, 0.4), V(0.12, 0.78, 0.39), V(0.22, 0.77, 0.34)], 0.011, CHROME);
        for (const x of [-1, 1]) bar(g, V(x * 0.225, 0.77, 0.335), V(x * 0.16, 0.778, 0.372), 0.016, GRIP);
        const ring = new THREE.Mesh(new THREE.CylinderGeometry(0.062, 0.062, 0.008, 28), CHROME); ring.rotation.z = Math.PI / 2; ring.position.set(0.045, 0.24, -0.04); g.add(ring);
        bar(g, V(0.055, 0.24, -0.04), V(0.055, 0.14, 0.02), 0.008, CHROME); bar(g, V(-0.055, 0.24, -0.04), V(-0.055, 0.34, -0.1), 0.008, CHROME);
        bar(g, V(0.04, 0.14, 0.02), V(0.115, 0.14, 0.02), 0.013, GRIP); bar(g, V(-0.115, 0.34, -0.1), V(-0.04, 0.34, -0.1), 0.013, GRIP);
        on(wheel(0.22, 0.026, 20, 0.02), 0, 0.22, 0.44); on(wheel(0.22, 0.026, 20, 0.02), 0, 0.22, -0.44);
      } else if (kind === 3) {      // a scooter: a round tail over the engine, a flat floor, a shield up to the bars, a long seat
        const TEAL = gloss(0x1fb5a8);
        panel(g, [[-0.64, 0.22], [-0.62, 0.38], [-0.46, 0.46], [-0.04, 0.45], [0.04, 0.3], [0.06, 0.18], [-0.3, 0.15]], 0.32, TEAL, 0.05);
        panel(g, [[0.0, 0.13], [0.42, 0.13], [0.42, 0.19], [0.0, 0.19]], 0.3, DARK, 0.02, 1);
        panel(g, [[0.36, 0.14], [0.5, 0.2], [0.56, 0.52], [0.5, 0.74], [0.42, 0.76], [0.44, 0.56], [0.38, 0.26]], 0.34, TEAL, 0.04);
        panel(g, [[-0.54, 0.46], [-0.5, 0.54], [-0.06, 0.53], [-0.02, 0.46]], 0.26, SEAT, 0.035);
        panel(g, [[0.34, 0.26], [0.42, 0.33], [0.56, 0.33], [0.66, 0.24], [0.6, 0.22], [0.52, 0.28], [0.44, 0.28], [0.4, 0.22]], 0.12, TEAL, 0.02);
        for (const x of [-0.06, 0.06]) bar(g, V(x, 0.3, 0.5), V(x, 0.14, 0.5), 0.012, CHROME);
        bar(g, V(0, 0.74, 0.46), V(0, 0.86, 0.42), 0.02, DARK); pipe(g, [V(-0.24, 0.84, 0.37), V(-0.1, 0.86, 0.42), V(0.1, 0.86, 0.42), V(0.24, 0.84, 0.37)], 0.016, CHROME);
        for (const x of [-1, 1]) bar(g, V(x * 0.245, 0.838, 0.365), V(x * 0.17, 0.85, 0.4), 0.021, GRIP);
        ball(g, 0.075, glow(0xfff1c4, 2.0), 0, 0.64, 0.555, 1, 1, 0.45); ball(g, 0.03, glow(0xff2a3a, 2.2), 0, 0.4, -0.655, 2.2, 1, 0.6);
        on(wheel(0.14, 0.075, 5, 0.03), 0, 0.14, 0.5); on(wheel(0.14, 0.075, 5, 0.03), 0, 0.14, -0.42);
      } else if (kind === 4) {      // a motorbike: an engine under a deep tank, a low seat and a short tail, forks, a pipe down one side
        const RED = gloss(0xd0202c);
        panel(g, [[-0.24, 0.2], [-0.26, 0.4], [-0.1, 0.46], [0.2, 0.44], [0.3, 0.3], [0.22, 0.18]], 0.22, DARK, 0.04);
        panel(g, [[-0.04, 0.47], [-0.02, 0.6], [0.2, 0.67], [0.44, 0.62], [0.52, 0.5], [0.3, 0.45]], 0.26, RED, 0.06);
        panel(g, [[-0.52, 0.5], [-0.5, 0.58], [-0.06, 0.56], [-0.02, 0.49], [-0.3, 0.47]], 0.22, SEAT, 0.04);
        panel(g, [[-0.76, 0.58], [-0.5, 0.62], [-0.46, 0.5], [-0.62, 0.5]], 0.18, RED, 0.04);
        panel(g, [[0.4, 0.5], [0.52, 0.56], [0.68, 0.56], [0.8, 0.46], [0.74, 0.44], [0.64, 0.5], [0.54, 0.5], [0.46, 0.44]], 0.13, RED, 0.02);
        panel(g, [[-0.8, 0.44], [-0.66, 0.52], [-0.5, 0.5], [-0.52, 0.46], [-0.66, 0.47], [-0.76, 0.41]], 0.14, DARK, 0.015);
        for (const x of [-0.075, 0.075]) { bar(g, V(x, 0.78, 0.5), V(x, 0.24, 0.64), 0.02, CHROME); bar(g, V(x, 0.3, -0.16), V(x, 0.24, -0.58), 0.022, DARK); }
        pipe(g, [V(-0.27, 0.8, 0.44), V(-0.14, 0.83, 0.5), V(0, 0.82, 0.52), V(0.14, 0.83, 0.5), V(0.27, 0.8, 0.44)], 0.016, CHROME);
        for (const x of [-1, 1]) bar(g, V(x * 0.275, 0.798, 0.435), V(x * 0.2, 0.815, 0.47), 0.021, GRIP);
        ball(g, 0.09, glow(0xfff1c4, 2.0), 0, 0.68, 0.635, 1, 1, 0.5); const lens = new THREE.Mesh(new THREE.TorusGeometry(0.092, 0.012, 8, 28), CHROME); lens.position.set(0, 0.68, 0.64); g.add(lens);
        pipe(g, [V(0.12, 0.22, 0.16), V(0.16, 0.2, -0.1), V(0.18, 0.26, -0.4), V(0.19, 0.33, -0.7)], 0.028, CHROME); bar(g, V(0.186, 0.29, -0.5), V(0.192, 0.345, -0.8), 0.046, CHROME);
        ball(g, 0.03, glow(0xff2a3a, 2.2), 0, 0.575, -0.765, 2.4, 0.9, 0.6);
        on(wheel(0.24, 0.1, 5, 0.04), 0, 0.24, 0.64); on(wheel(0.24, 0.12, 5, 0.045), 0, 0.24, -0.58);
      } else if (kind === 5) {      // a go-kart: a floor, a nose, a pod each side, a bucket seat, a wheel to steer by, a wing
        const YEL = gloss(0xf2b61a), RED = gloss(0xd0202c);
        panel(g, [[-0.74, 0.08], [0.8, 0.08], [0.8, 0.12], [-0.74, 0.12]], 0.72, DARK, 0.02, 1);
        panel(g, [[0.44, 0.12], [0.9, 0.13], [0.9, 0.2], [0.6, 0.3], [0.42, 0.24]], 0.5, YEL, 0.05);
        for (const x of [-0.34, 0.34]) panel(g, [[-0.5, 0.12], [0.32, 0.12], [0.28, 0.26], [-0.46, 0.3]], 0.16, RED, 0.04, 2, x);
        panel(g, [[-0.5, 0.13], [-0.1, 0.13], [-0.06, 0.2], [-0.28, 0.22], [-0.36, 0.62], [-0.48, 0.64]], 0.42, SEAT, 0.04);
        panel(g, [[-0.74, 0.14], [-0.54, 0.14], [-0.54, 0.34], [-0.74, 0.34]], 0.24, DARK, 0.03, 1, 0.2);
        panel(g, [[-0.86, 0.58], [-0.62, 0.6], [-0.62, 0.64], [-0.86, 0.64]], 0.86, RED, 0.02, 1);
        for (const x of [-0.3, 0.3]) bar(g, V(x, 0.2, -0.7), V(x, 0.6, -0.74), 0.014, CHROME);
        bar(g, V(0, 0.2, 0.42), V(0, 0.5, 0.2), 0.016, CHROME); const steer = new THREE.Mesh(new THREE.TorusGeometry(0.13, 0.018, 10, 28), GRIP); steer.position.set(0, 0.5, 0.2); steer.rotation.x = -0.95; g.add(steer);
        pipe(g, [V(-0.36, 0.14, 0.86), V(0, 0.14, 0.95), V(0.36, 0.14, 0.86)], 0.02, CHROME); pipe(g, [V(-0.4, 0.16, -0.8), V(0, 0.16, -0.88), V(0.4, 0.16, -0.8)], 0.02, CHROME);
        for (const x of [-0.18, 0.18]) { ball(g, 0.04, glow(0xfff1c4, 2.0), x, 0.2, 0.9, 1, 1, 0.5); ball(g, 0.03, glow(0xff2a3a, 2.2), x * 1.2, 0.3, -0.77, 1.6, 1, 0.5); }
        for (const x of [-0.47, 0.47]) for (const z of [-0.52, 0.52]) on(wheel(0.14, 0.13, 5, 0.035), x, 0.14, z);
      }
      g.traverse((m) => { if (m.isMesh) m.castShadow = m.receiveShadow = true; });
      const lean = new THREE.Group(); lean.rotation.order = 'YXZ'; lean.add(g); scene.add(lean);
      return { lean, g, wheels };
    };
  })();
  function park(f) {      // every ride the view named this frame, each on a model of its own
    const used = {};
    for (const k in garage) garage[k].forEach((m) => { m.lean.visible = false; });
    for (let i = 0; i < (f.nProps || 0); i++) {
      const o = i * 9, kind = f.props[o + 7] | 0; if (kind < 1 || kind > 5) continue;
      const list = garage[kind] || (garage[kind] = []), n = used[kind] = (used[kind] || 0) + 1; if (list.length < n) list.push(buildRide(kind));
      const m = list[n - 1], k = f.props[o + 5], piv = f.props[o + 6];
      m.lean.visible = true; m.lean.scale.setScalar(k); m.lean.position.set(f.props[o], f.props[o + 1] + piv * k, f.props[o + 2]); m.lean.rotation.set(f.props[o + 4], f.props[o + 3], 0); m.g.position.y = -piv;
      m.wheels.forEach((w) => { w.rotation.x = f.props[o + 8] * 9; });
    }
  }

  /* ── people ──
     The view says who each person is, where, and how every joint stands (`figs`, with its own table of the eight as
     `heroes`: their colours and what they wear are read from there, never kept here). The figure is this engine's
     design on the view's skeleton: the same hips, knees, shoulders and elbows at the same lengths, so the walk, a
     seat on a ride, a blow and each role's own move all land as they were worked out, and what a hand holds sits in
     the hand. A body with a shape to it, a face that looks at you, and each role known by its head and its clothes. */
  const cast = {};
  const buildFigure = (() => {
    const col = (c, rough = 0.62, metal = 0.02) => new THREE.MeshStandardMaterial({ color: new THREE.Color().setRGB(c[0], c[1], c[2], THREE.SRGBColorSpace), roughness: rough, metalness: metal });
    const shine = (hexv, k) => new THREE.MeshBasicMaterial({ color: new THREE.Color(hexv).multiplyScalar(k) });
    const BALL = new THREE.SphereGeometry(0.5, 28, 20), CARD = new THREE.BoxGeometry(1, 1, 1), ring = (r, t, arc) => new THREE.TorusGeometry(r, t, 10, 30, arc || Math.PI * 2), rod = (r, len) => new THREE.CapsuleGeometry(r, len, 6, 12);
    const put = (g, geo, mat, x, y, z, sx = 1, sy = sx, sz = sx, rx = 0, ry = 0, rz = 0) => { const m = new THREE.Mesh(geo, mat); m.position.set(x, y, z); m.scale.set(sx, sy, sz); m.rotation.set(rx, ry, rz); g.add(m); return m; };
    const taper = (r0, r1, len) => {      // a limb: round at its joint, narrowing to the next, hanging from where it turns
      const pts = []; for (let i = 0; i <= 8; i++) { const a = i / 8 * Math.PI / 2; pts.push(new THREE.Vector2(Math.sin(a) * r0, Math.cos(a) * r0)); }
      for (let i = 0; i <= 8; i++) { const a = Math.PI / 2 + i / 8 * Math.PI / 2; pts.push(new THREE.Vector2(Math.sin(a) * r1, -len + Math.cos(a) * r1)); }
      return new THREE.LatheGeometry(pts.reverse(), 22);
    };
    const turned = (profile, flat) => { const geo = new THREE.LatheGeometry(profile.map(([r, y]) => new THREE.Vector2(r, y)), 30); geo.scale(1, 1, flat); return geo; };
    const HIPS = turned([[0, 0.78], [0.15, 0.8], [0.19, 0.88], [0.185, 0.97], [0, 0.99]], 0.74), CHEST = turned([[0, 0.93], [0.175, 0.95], [0.17, 1.08], [0.2, 1.22], [0.235, 1.36], [0.2, 1.46], [0.09, 1.52], [0, 1.53]], 0.72);
    const THIGH = taper(0.105, 0.085, 0.4), SHIN = taper(0.085, 0.068, 0.34), UPPER = taper(0.088, 0.072, 0.3), LOWER = taper(0.07, 0.058, 0.26), HOOD = new THREE.SphereGeometry(0.29, 28, 18, Math.PI / 2 + 0.9, Math.PI * 2 - 1.8);
    return (L) => {
      const g = new THREE.Group(), kit = L.kit, dim = (c, k) => [c[0] * k, c[1] * k, c[2] * k];
      const skin = col(L.skin, 0.55), hair = col(L.hair, 0.72), top = col(L.top), legs = col(L.legs), shoe = col(L.shoes, 0.5), sleeve = col(L.arm || L.top), fore = col(L.arm || L.skin, L.arm ? 0.62 : 0.55);
      const white = col([0.93, 0.94, 0.96], 0.5), ink = col([0.05, 0.05, 0.06], 0.4), red = col([0.82, 0.14, 0.16]), wood = col([0.55, 0.36, 0.2]), brow = col(kit === 'ceo' || kit === 'dba' ? [0.45, 0.45, 0.48] : L.hair, 0.7);
      put(g, HIPS, legs, 0, 0, 0); put(g, CHEST, top, 0, 0, 0); put(g, BALL, skin, 0, 1.52, 0, 0.13, 0.14, 0.13);
      const limb = (x, y, len, upGeo, upMat, lowGeo, lowMat) => { const a = new THREE.Group(), b = new THREE.Group(); a.position.set(x, y, 0); a.rotation.order = 'ZXY'; b.position.y = -len; a.add(new THREE.Mesh(upGeo, upMat), b); b.add(new THREE.Mesh(lowGeo, lowMat)); g.add(a); return [a, b]; };
      const legL = limb(-0.1, 0.86, 0.4, THIGH, legs, SHIN, legs), legR = limb(0.1, 0.86, 0.4, THIGH, legs, SHIN, legs), armL = limb(-0.27, 1.42, 0.3, UPPER, sleeve, LOWER, fore), armR = limb(0.27, 1.42, 0.3, UPPER, sleeve, LOWER, fore);
      [legL, legR].forEach(([, shin]) => { put(shin, BALL, shoe, 0, -0.4, 0.055, 0.17, 0.12, 0.31); put(shin, BALL, white, 0, -0.445, 0.055, 0.165, 0.045, 0.305); });      // a shoe, on its sole
      [armL, armR].forEach(([, low], i) => { put(low, BALL, skin, 0, -0.31, 0, 0.125, 0.14, 0.125); put(low, BALL, skin, (i ? -1 : 1) * 0.05, -0.29, 0.035, 0.05); });      // a hand, and its thumb
      // the head nods on the neck: a face first, then what the role wears on it
      const neck = new THREE.Group(), H = 0.27; neck.position.y = 1.5; g.add(neck);
      put(neck, BALL, skin, 0, H, 0, 0.46, 0.48, 0.45);
      for (const s of [-1, 1]) {
        put(neck, BALL, white, s * 0.088, H + 0.02, 0.185, 0.11, 0.13, 0.07); put(neck, BALL, ink, s * 0.088, H + 0.015, 0.208, 0.06, 0.075, 0.04);
        put(neck, BALL, shine(0xffffff, 1.5), s * 0.1, H + 0.042, 0.226, 0.018); put(neck, BALL, brow, s * 0.088, H + 0.108, 0.196, 0.1, 0.024, 0.035, 0, 0, -s * 0.14);
        put(neck, BALL, skin, s * 0.228, H, 0, 0.06, 0.11, 0.08);
      }
      put(neck, BALL, col(dim(L.skin, 0.9), 0.55), 0, H - 0.045, 0.226, 0.05, 0.055, 0.05); put(neck, ring(0.055, 0.011, Math.PI), col([0.42, 0.15, 0.15]), 0, H - 0.092, 0.198, 1, 1, 1, 0, 0, Math.PI);
      if (kit !== 'sec' && kit !== 'dba') { put(neck, BALL, hair, 0, H + 0.075, -0.03, 0.5, 0.36, 0.5); put(neck, BALL, hair, 0, H - 0.02, -0.11, 0.46, 0.4, 0.3); }
      const lanyard = (cord) => { for (const s of [-1, 1]) put(g, rod(0.007, 0.28), cord, s * 0.05, 1.33, 0.158, 1, 1, 1, -0.12, 0, s * 0.19); put(g, CARD, white, 0, 1.14, 0.165, 0.1, 0.13, 0.012); put(g, CARD, top, 0, 1.16, 0.172, 0.06, 0.04, 0.006); };
      if (kit === 'devops') {             // unruly hair and a short beard; a hoodie with its hood down, a pocket, drawstrings, headphones round the neck
        [[0.07, 0.2, 0.06, 0.16], [-0.09, 0.19, 0, 0.15], [0, 0.21, -0.08, 0.15]].forEach(([x, y, z, r]) => put(neck, BALL, hair, x, H + y, z, r));
        put(neck, BALL, col(dim(L.hair, 1.2), 0.75), 0, H - 0.13, 0.09, 0.36, 0.2, 0.26);
        put(g, BALL, top, 0, 1.47, -0.13, 0.38, 0.17, 0.22); put(g, BALL, col(dim(L.top, 0.8)), 0, 1.12, 0.13, 0.26, 0.11, 0.06);
        for (const s of [-1, 1]) { put(g, rod(0.008, 0.14), white, s * 0.05, 1.34, 0.162); put(g, BALL, ink, s * 0.14, 1.5, 0.03, 0.09, 0.11, 0.11); }
        put(g, ring(0.14, 0.02), ink, 0, 1.5, 0, 1, 1, 1, Math.PI / 2);
      } else if (kit === 'sec') {         // the hood is up, and the glasses glow; a shield on the chest, pockets on the trousers
        const up = col(L.top); up.side = THREE.DoubleSide; put(neck, HOOD, up, 0, H + 0.01, -0.02); put(neck, BALL, top, 0, H + 0.21, 0.09, 0.36, 0.14, 0.22); put(g, BALL, top, 0, 1.5, -0.12, 0.4, 0.2, 0.26);
        for (const s of [-1, 1]) put(neck, BALL, shine(0x33ff99, 1.25), s * 0.088, H + 0.02, 0.222, 0.11, 0.085, 0.02);
        put(neck, CARD, ink, 0, H + 0.025, 0.224, 0.07, 0.014, 0.012); put(g, BALL, shine(0x33d880, 1.3), 0.11, 1.33, 0.162, 0.11, 0.13, 0.03);
        [legL, legR].forEach(([thigh], i) => put(thigh, BALL, col(dim(L.legs, 0.85)), (i ? 1 : -1) * 0.05, -0.2, 0.05, 0.1, 0.14, 0.09));
      } else if (kit === 'noc') {         // a side parting under a headset with its microphone; a collar, and a badge on a lanyard
        put(neck, BALL, hair, 0.05, H + 0.17, 0.07, 0.28, 0.1, 0.18, 0, 0, 0.2);
        put(neck, ring(0.245, 0.02, Math.PI), ink, 0, H, 0); for (const s of [-1, 1]) put(neck, BALL, ink, s * 0.245, H - 0.01, 0, 0.07, 0.15, 0.14);
        put(neck, rod(0.008, 0.17), ink, 0.2, H - 0.1, 0.1, 1, 1, 1, 1.1, 0, 0.35); put(neck, BALL, ink, 0.13, H - 0.15, 0.2, 0.05);
        put(g, ring(0.11, 0.028), white, 0, 1.49, 0.01, 1, 1, 1, Math.PI / 2); lanyard(red);
      } else if (kit === 'net') {         // a cap with a peak; a vest whose stripes shine, a tool belt with a pouch, a coil of cable on the shoulder
        const cap = col([0.14, 0.2, 0.42], 0.6); put(neck, BALL, cap, 0, H + 0.1, 0, 0.5, 0.34, 0.5); put(neck, BALL, cap, 0, H + 0.085, 0.24, 0.34, 0.05, 0.28); put(neck, CARD, white, 0, H + 0.15, 0.235, 0.09, 0.07, 0.02);
        for (const [y, r] of [[1.14, 0.198], [1.31, 0.228]]) put(g, ring(r, 0.02), shine(0xffffff, 1.05), 0, y, 0, 1, 0.74, 1, Math.PI / 2);
        put(g, rod(0.02, 0.3), col([0.2, 0.22, 0.3]), 0, 1.25, 0.156); put(g, ring(0.19, 0.03), wood, 0, 0.97, 0, 1, 0.76, 1, Math.PI / 2); put(g, BALL, wood, 0.15, 0.9, 0.11, 0.11, 0.14, 0.08);
        put(g, ring(0.12, 0.028), col([0.15, 0.4, 0.95], 0.5), -0.3, 1.36, 0, 1, 1, 1, 0, Math.PI / 2);
      } else if (kit === 'ceo') {         // hair swept back; a suit over a white shirt, a red tie with its knot, lapels, a pocket square
        put(neck, BALL, hair, 0, H + 0.14, 0.02, 0.44, 0.16, 0.4, -0.25);
        put(g, BALL, white, 0, 1.36, 0.135, 0.15, 0.3, 0.07); put(g, BALL, red, 0, 1.3, 0.162, 0.05, 0.26, 0.03); put(g, BALL, red, 0, 1.455, 0.158, 0.06, 0.05, 0.04);
        for (const s of [-1, 1]) put(g, BALL, col([0.11, 0.14, 0.27]), s * 0.09, 1.36, 0.15, 0.08, 0.28, 0.04, 0, 0, -s * 0.28);
        put(g, BALL, white, -0.14, 1.36, 0.16, 0.06, 0.03, 0.02);
      } else if (kit === 'pm') {          // a bun and a fringe; a collar, a badge on a lanyard, and a watch worn where it can be seen
        put(neck, BALL, hair, 0, H + 0.2, -0.13, 0.19); put(neck, BALL, hair, 0, H + 0.15, 0.12, 0.42, 0.12, 0.2);
        put(g, ring(0.11, 0.028), white, 0, 1.49, 0.01, 1, 1, 1, Math.PI / 2); lanyard(col([0.2, 0.6, 0.4])); put(armR[1], ring(0.062, 0.016), ink, 0, -0.22, 0, 1, 1, 1, Math.PI / 2);
      } else if (kit === 'qa') {          // a bob with a fringe, round glasses; a bug on the shirt
        for (const s of [-1, 1]) { put(neck, BALL, hair, s * 0.19, H - 0.06, -0.02, 0.13, 0.36, 0.34); put(neck, ring(0.06, 0.009), ink, s * 0.088, H + 0.02, 0.226); }
        put(neck, BALL, hair, 0, H + 0.15, 0.12, 0.42, 0.12, 0.2); put(neck, CARD, ink, 0, H + 0.025, 0.226, 0.06, 0.012, 0.01); put(g, BALL, shine(0x33d880, 1.15), 0, 1.32, 0.164, 0.12, 0.09, 0.03);
      } else {                            // bald on top, grey at the sides, a beard, square glasses; a cardigan over a shirt, and a database on the pocket
        for (const s of [-1, 1]) { put(neck, BALL, hair, s * 0.17, H + 0.02, -0.05, 0.12, 0.24, 0.3); put(neck, CARD, ink, s * 0.088, H + 0.02, 0.222, 0.105, 0.08, 0.012); put(neck, CARD, col([0.75, 0.85, 0.95], 0.2), s * 0.088, H + 0.02, 0.229, 0.082, 0.058, 0.008); }
        put(neck, BALL, hair, 0, H - 0.01, -0.16, 0.34, 0.3, 0.14); put(neck, BALL, hair, 0, H - 0.135, 0.09, 0.34, 0.22, 0.26); put(neck, CARD, ink, 0, H + 0.025, 0.226, 0.06, 0.012, 0.01);
        put(g, BALL, col([0.9, 0.86, 0.74]), 0, 1.3, 0.14, 0.16, 0.38, 0.06);
        for (let k = 0; k < 3; k++) { put(g, BALL, wood, 0.1, 1.38 - k * 0.11, 0.158, 0.03); put(g, BALL, shine(0x59d9ff, 1.1), -0.12, 1.36 - k * 0.035, 0.158, 0.1, 0.022, 0.02); }
      }
      g.traverse((m) => { if (m.isMesh) m.castShadow = m.receiveShadow = true; });
      const lean = new THREE.Group(), swing = (pair, ang, bend, out) => { pair[0].rotation.set(-ang, 0, out || 0); pair[1].rotation.x = -bend; };
      lean.rotation.order = 'YXZ'; lean.add(g); g.position.y = -1; scene.add(lean);
      return { lean, pose(a, o) { swing(legL, a[o + 7], a[o + 9]); swing(legR, a[o + 8], a[o + 10]); swing(armL, a[o + 11], a[o + 13], a[o + 15]); swing(armR, a[o + 12], a[o + 14], a[o + 16]); neck.rotation.x = a[o + 17]; } };
    };
  })();
  function people(f) {      // every person the view named this frame, each on a figure of its own
    const used = {};
    for (const k in cast) cast[k].forEach((m) => { m.lean.visible = false; });
    if (!f.heroes) return;
    for (let i = 0; i < (f.nFigs || 0); i++) {
      const o = i * 18, who = f.figs[o + 6] | 0, L = f.heroes[who]; if (!L) continue;
      const list = cast[who] || (cast[who] = []), n = used[who] = (used[who] || 0) + 1; if (list.length < n) list.push(buildFigure(L));
      const m = list[n - 1], k = f.figs[o + 5];
      m.lean.visible = true; m.lean.scale.setScalar(k); m.lean.position.set(f.figs[o], f.figs[o + 1] + k, f.figs[o + 2]); m.lean.rotation.set(f.figs[o + 4], f.figs[o + 3], 0); m.pose(f.figs, o);
    }
  }

  /* ── the boards at the gate ──
     In a hall the view's boards are screens, laid out the way a newsroom lays out a story: the board's name, which story
     of how many, the place it is about over what happened there, a bar running down to the next one, and every
     headline passing along the foot. Who needs help is a list, a row to a building. Nothing is on a screen that the view
     did not say: the layout only divides its words where the view's own punctuation does (": " after a place, " · "
     before a detail), and a word too long for its line is cut with an ellipsis. */
  const boards = {}, FACE = 'ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif', PX = 2;      // laid out 1024 across, drawn at twice that
  const DIM = 'rgba(242,245,247,.62)', probe = document.createElement('canvas').getContext('2d');
  const rrect = (g, x, y, w, h, r) => { g.beginPath(); g.moveTo(x + r, y); g.arcTo(x + w, y, x + w, y + h, r); g.arcTo(x + w, y + h, x, y + h, r); g.arcTo(x, y + h, x, y, r); g.arcTo(x, y, x + w, y, r); g.closePath(); };
  const spaced = (g, px) => { if ('letterSpacing' in g) g.letterSpacing = px + 'px'; };
  const toneOf = (css) => { probe.fillStyle = '#ffffff'; probe.fillStyle = css; const v = probe.fillStyle, m = v.match(/[\d.]+/g); return v[0] === '#' ? new THREE.Color(v) : new THREE.Color(+m[0] / 255, +m[1] / 255, +m[2] / 255).convertSRGBToLinear(); };
  function rows(g, text, width, most) {      // the words in at most `most` lines of `width`
    const out = []; let cur = '';
    String(text).split(/\s+/).filter(Boolean).forEach((w) => { const next = cur ? cur + ' ' + w : w; if (!cur || g.measureText(next).width <= width) cur = next; else { out.push(cur); cur = w; } });
    if (cur) out.push(cur);
    if (out.length > most) { let last = out.slice(most - 1).join(' '); while (last.length > 1 && g.measureText(last + '…').width > width) last = last.slice(0, -1); out.length = most - 1; out.push(last.trimEnd() + '…'); }
    return out;
  }
  function glass(g, W, H, tone) {      // the panel: deep blue, lit a little from the corner by the board's own colour, with its lines
    const bg = g.createLinearGradient(0, 0, 0, H); bg.addColorStop(0, '#0c1629'); bg.addColorStop(1, '#03060d'); g.fillStyle = bg; g.fillRect(0, 0, W, H);
    const lit = g.createRadialGradient(W * 0.12, 0, 0, W * 0.12, 0, W * 0.85); lit.addColorStop(0, tone); lit.addColorStop(1, 'rgba(0,0,0,0)');
    g.globalAlpha = 0.13; g.fillStyle = lit; g.fillRect(0, 0, W, H); g.globalAlpha = 1;
    g.fillStyle = 'rgba(140,170,255,.03)'; for (let y = 0; y < H; y += 4) g.fillRect(0, y, W, 1.5);
  }
  function heading(g, W, hh, text, tone) {      // the board's name, in its colour, on a band of its own
    g.fillStyle = 'rgba(255,255,255,.035)'; g.fillRect(0, 0, W, hh);
    g.fillStyle = tone; g.globalAlpha = 0.85; g.fillRect(0, hh - 3, W, 3); g.globalAlpha = 1;
    rrect(g, 34, hh * 0.27, 9, hh * 0.46, 3); g.fill();
    g.font = '800 ' + Math.round(hh * 0.4) + 'px ' + FACE; spaced(g, 4); g.textAlign = 'left'; g.textBaseline = 'middle';
    g.fillText(text, 60, hh * 0.53, W * 0.62); spaced(g, 0);
  }
  function paintNews(g, W, H, sc) {
    const head = sc.lines[0] || ['', '#fff'], tone = sc.tone || head[1], hh = Math.round(H * 0.17), story = sc.story != null ? String(sc.story) : sc.lines.slice(1).map((l) => l[0]).join(' ');
    glass(g, W, H, tone); heading(g, W, hh, head[0], head[1]);
    const n = sc.of || 0;      // which story of how many: a dot each, the one on the screen lit
    if (n > 1 && n <= 16) for (let i = 0; i < n; i++) { const on = i === sc.at; g.fillStyle = on ? head[1] : 'rgba(242,245,247,.22)'; g.beginPath(); g.arc(W - 96 - (n - 1 - i) * 24, hh * 0.53, on ? 7 : 5, 0, Math.PI * 2); g.fill(); }
    const cut = story.indexOf(': '), place = cut > 0 ? story.slice(0, cut) : '', what = cut > 0 ? story.slice(cut + 2) : story;
    const top = hh + H * 0.075, left = 74, width = W - left - 56, foot = H * 0.76;
    g.fillStyle = 'rgba(255,255,255,.028)'; rrect(g, 26, top - 14, W - 52, foot - top - 4, 14); g.fill();
    g.save(); g.shadowColor = tone; g.shadowBlur = 22; g.fillStyle = tone; rrect(g, 38, top, 10, foot - top - 32, 5); g.fill(); g.restore();
    const most = place ? 2 : 3, kick = place ? H * 0.095 : 0; let size = Math.round(H * 0.155), said;      // the largest the story fits at, and the whole of it in the middle of its card
    for (; size > H * 0.07; size -= 4) { g.font = '800 ' + size + 'px ' + FACE; said = rows(g, what, width, 9); if (said.length <= most) break; }
    g.font = '800 ' + size + 'px ' + FACE; said = rows(g, what, width, most);
    let y = top + Math.max(6, (foot - 32 - top - kick - said.length * size * 1.1) / 2);
    if (place) { g.font = '700 ' + Math.round(H * 0.058) + 'px ' + FACE; spaced(g, 2); g.fillStyle = tone; g.textBaseline = 'top'; g.fillText(rows(g, place.toUpperCase(), width, 1)[0], left, y, width); spaced(g, 0); y += kick; }
    g.font = '800 ' + size + 'px ' + FACE; g.fillStyle = '#f2f5f7'; g.textBaseline = 'top'; said.forEach((l, i) => g.fillText(l, left, y + i * size * 1.1, width));
    g.fillStyle = 'rgba(242,245,247,.12)'; rrect(g, 38, foot, W - 76, 6, 3); g.fill();      // the track the time to the next story runs along
    g.fillStyle = 'rgba(0,0,0,.45)'; g.fillRect(0, H * 0.83, W, H * 0.17); g.fillStyle = head[1]; g.globalAlpha = 0.6; g.fillRect(0, H * 0.83, W, 2); g.globalAlpha = 1;
  }
  function paintHelp(g, W, H, sc) {
    const head = sc.lines[0] || ['', '#fff'], list = sc.lines.slice(1, 5), hh = Math.round(H * 0.17);
    glass(g, W, H, head[1]); heading(g, W, hh, head[0], head[1]);
    if (list.length === 1 && list[0][0].indexOf(' · ') < 0) {      // nothing to list: the one thing said, large, in a ring of the board's colour
      g.save(); g.strokeStyle = head[1]; g.globalAlpha = 0.35; g.lineWidth = 10; g.shadowColor = head[1]; g.shadowBlur = 30; g.beginPath(); g.arc(W / 2, hh + (H - hh) * 0.5, (H - hh) * 0.36, 0, Math.PI * 2); g.stroke(); g.restore();
      g.font = '700 ' + Math.round(H * 0.075) + 'px ' + FACE; g.fillStyle = list[0][1]; g.textAlign = 'center'; g.textBaseline = 'middle';
      rows(g, list[0][0], W * 0.56, 2).forEach((l, i, all) => g.fillText(l, W / 2, hh + (H - hh) * 0.5 + (i - (all.length - 1) / 2) * H * 0.09, W * 0.6));
      return;
    }
    const rh = Math.min(H * 0.19, (H - hh - 36) / Math.max(1, list.length));
    list.forEach(([text, ink], i) => {
      const y = hh + 22 + i * rh, cut = text.indexOf(' · '), name = cut > 0 ? text.slice(0, cut) : text, why = cut > 0 ? text.slice(cut + 3) : '';
      g.fillStyle = 'rgba(255,255,255,.045)'; rrect(g, 30, y, W - 60, rh - 12, 14); g.fill();
      g.save(); g.fillStyle = head[1]; g.shadowColor = head[1]; g.shadowBlur = 16; g.beginPath(); g.arc(68, y + (rh - 12) / 2, 10, 0, Math.PI * 2); g.fill(); g.restore();
      g.textBaseline = 'middle'; g.textAlign = 'right'; g.font = '600 ' + Math.round(rh * 0.3) + 'px ' + FACE; g.fillStyle = DIM;
      const room = why ? Math.min(W * 0.46, g.measureText(why).width) : 0; if (why) g.fillText(why, W - 58, y + (rh - 12) / 2, W * 0.46);
      g.textAlign = 'left'; g.font = '800 ' + Math.round(rh * 0.38) + 'px ' + FACE; g.fillStyle = ink; g.fillText(name, 96, y + (rh - 12) / 2, W - 96 - 58 - room - 30);
    });
  }
  function paintGate(g, W, H, sc) {      // over the gate: the city's name, and how it is, as a lit strip
    const name = sc.lines[0] || ['', '#fff'], sum = sc.lines[1];
    glass(g, W, H, name[1]);
    g.fillStyle = 'rgba(255,255,255,.05)'; for (let x = 3; x < W; x += 7) for (let y = 3; y < H; y += 7) g.fillRect(x, y, 2, 2);
    g.textAlign = 'center'; g.textBaseline = 'middle';
    g.save(); g.shadowColor = name[1]; g.shadowBlur = 18; g.font = '800 ' + Math.round(H * (sum ? 0.4 : 0.6)) + 'px ' + FACE; spaced(g, 6); g.fillStyle = name[1]; g.fillText(name[0], W / 2, H * (sum ? 0.33 : 0.5), W - 80); g.restore(); spaced(g, 0);
    if (sum) { g.font = '700 ' + Math.round(H * 0.24) + 'px ' + FACE; spaced(g, 2); g.fillStyle = sum[1]; g.fillText(sum[0], W / 2, H * 0.72, W - 80); spaced(g, 0); }
    g.fillStyle = name[1]; g.globalAlpha = 0.7; rrect(g, 14, H * 0.3, 6, H * 0.4, 3); g.fill(); rrect(g, W - 20, H * 0.3, 6, H * 0.4, 3); g.fill(); g.globalAlpha = 1;
  }
  const PAINT = { news: paintNews, help: paintHelp, gate: paintGate };
  const edgeMat = () => new THREE.MeshBasicMaterial({ color: 0xffffff });
  const fade = (() => { const c = document.createElement('canvas'); c.width = 256; c.height = 1; const g = c.getContext('2d'), gr = g.createLinearGradient(0, 0, 256, 0); gr.addColorStop(0, '#000'); gr.addColorStop(0.07, '#fff'); gr.addColorStop(0.93, '#fff'); gr.addColorStop(1, '#000'); g.fillStyle = gr; g.fillRect(0, 0, 256, 1); return new THREE.CanvasTexture(c); })();
  function screen(sc) {      // the panel, its bezel, the light along its foot and, standing on the floor, its feet
    const W = 1024, H = Math.max(64, Math.round(W * sc.h / sc.w)), c = document.createElement('canvas'); c.width = W * PX; c.height = H * PX;
    const tex = new THREE.CanvasTexture(c); tex.colorSpace = THREE.SRGBColorSpace; tex.anisotropy = 8;
    const g = new THREE.Group(), face = new THREE.Group(), r = Math.min(0.32, sc.h * 0.12), shape = new THREE.Shape(), bw = sc.w + 0.34, bh = sc.h + 0.34;
    shape.moveTo(-bw / 2 + r, -bh / 2); shape.lineTo(bw / 2 - r, -bh / 2); shape.quadraticCurveTo(bw / 2, -bh / 2, bw / 2, -bh / 2 + r); shape.lineTo(bw / 2, bh / 2 - r); shape.quadraticCurveTo(bw / 2, bh / 2, bw / 2 - r, bh / 2);
    shape.lineTo(-bw / 2 + r, bh / 2); shape.quadraticCurveTo(-bw / 2, bh / 2, -bw / 2, bh / 2 - r); shape.lineTo(-bw / 2, -bh / 2 + r); shape.quadraticCurveTo(-bw / 2, -bh / 2, -bw / 2 + r, -bh / 2);
    const metal = new THREE.MeshStandardMaterial({ color: 0x151a24, roughness: 0.32, metalness: 0.8 });
    const shell = new THREE.Mesh(new THREE.ExtrudeGeometry(shape, { depth: 0.32, bevelEnabled: true, bevelSize: 0.05, bevelThickness: 0.05, bevelSegments: 3, curveSegments: 8 }), metal); shell.position.z = -0.39; shell.castShadow = true;      // its front, bevel and all, a little behind the picture
    const panel = new THREE.Mesh(new THREE.PlaneGeometry(sc.w, sc.h), new THREE.MeshBasicMaterial({ map: tex, color: new THREE.Color(0.78, 0.78, 0.78) }));      // the words are kept under what blooms, so they stay sharp
    const edge = new THREE.Mesh(new THREE.BoxGeometry(sc.w * 0.86, 0.07, 0.07), edgeMat()); edge.position.set(0, -bh / 2 - 0.02, 0.02);      // its light, along the foot, in the board's colour
    face.add(shell, panel, edge); g.add(face);
    const b = { g, face, c, tex, edge, said: '', W, H };
    if (sc.feet != null) {      // a screen above the heads stands on two feet of its own and leans a little to the street
      const low = sc.y - sc.h / 2 - 0.17, len = low - sc.feet, post = new THREE.CylinderGeometry(0.11, 0.14, len, 18), foot = new THREE.BoxGeometry(1.1, 0.14, 0.9), seam = new THREE.BoxGeometry(0.03, len * 0.8, 0.03);
      for (const s of [-1, 1]) {
        const x = s * sc.w * 0.3, p = new THREE.Mesh(post, metal); p.position.set(x, sc.feet + len / 2 - sc.y, -0.2); p.castShadow = true;
        const f2 = new THREE.Mesh(foot, metal); f2.position.set(x, sc.feet + 0.07 - sc.y, -0.2); f2.castShadow = f2.receiveShadow = true;
        const ln = new THREE.Mesh(seam, edge.material); ln.position.set(x, sc.feet + len * 0.5 - sc.y, -0.07);
        g.add(p, f2, ln);
      }
      face.rotation.x = 0.09;
    }
    if (sc.kind === 'news') {      // the bar to the next story, the headlines passing along the foot, and the light that says it is live
      const px = (x) => (x / W - 0.5) * sc.w, py = (y) => (0.5 - y / H) * sc.h, z = 0.012;
      const bar = new THREE.Mesh(new THREE.PlaneGeometry(1, 1).translate(0.5, 0, 0), new THREE.MeshBasicMaterial({ color: 0xffffff }));
      bar.position.set(px(38), py(H * 0.76 + 3), z); bar.userData.w = px(W - 38) - px(38); bar.scale.set(0.001, sc.h * 6 / H, 1);
      const tc = document.createElement('canvas'); tc.height = 64 * PX; tc.width = 16;
      const ttex = new THREE.CanvasTexture(tc); ttex.colorSpace = THREE.SRGBColorSpace; ttex.wrapS = THREE.RepeatWrapping; ttex.anisotropy = 8;
      const tw = sc.w - 0.5, th = sc.h * 0.13, tick = new THREE.Mesh(new THREE.PlaneGeometry(tw, th), new THREE.MeshBasicMaterial({ map: ttex, alphaMap: fade, transparent: true, depthWrite: false, color: new THREE.Color(0.78, 0.78, 0.78) }));
      tick.position.set(0, py(H * 0.915), z);
      const live = new THREE.Mesh(new THREE.CircleGeometry(sc.h * 0.022, 24), new THREE.MeshBasicMaterial({ color: 0xff3048 })); live.position.set(px(W - 54), py(H * 0.17 * 0.53), z);
      face.add(bar, tick, live); Object.assign(b, { bar, tick, ttex, tc, tw, th, live, ticked: '' });
    }
    scene.add(g);
    return b;
  }
  function ticker(b, list) {      // every headline in one line, a diamond between each, long enough to pass round without a seam
    const g = b.tc.getContext('2d'), size = 30 * PX, join = '      ◆      ';
    g.font = '600 ' + size + 'px ' + FACE; const text = list.join(join) + join, w = Math.min(16384, Math.ceil(g.measureText(text).width) + 8);
    b.tc.width = w; g.font = '600 ' + size + 'px ' + FACE; g.clearRect(0, 0, w, b.tc.height); g.fillStyle = '#e8edf3'; g.textBaseline = 'middle'; g.fillText(text, 0, b.tc.height / 2);
    b.ttex.dispose(); b.ttex.image = b.tc; b.ttex.needsUpdate = true;
    b.tick.material.map.repeat.x = b.tw / b.th * b.tc.height / w; b.tickW = w;
  }
  function screensOf(f) {
    const live = {};
    (f.screens || []).forEach((sc) => {
      const key = [sc.w, sc.h, sc.feet, sc.y].join();
      let b = boards[sc.kind];
      if (b && b.key !== key) { scene.remove(b.g); b = null; }
      if (!b) { b = boards[sc.kind] = screen(sc); b.key = key; }
      live[sc.kind] = 1; b.g.visible = true; b.g.position.set(sc.x, sc.y, sc.z);
      const said = JSON.stringify([sc.lines, sc.story, sc.at, sc.of, sc.tone]);
      if (said !== b.said) {
        b.said = said; const g = b.c.getContext('2d'); g.setTransform(PX, 0, 0, PX, 0, 0); (PAINT[sc.kind] || paintGate)(g, b.W, b.H, sc); b.tex.needsUpdate = true;
        const tone = toneOf(sc.tone || (sc.lines[0] || [])[1] || '#fff'); b.edge.material.color.copy(tone).multiplyScalar(2.2);
        if (b.bar) b.bar.material.color.copy(tone).multiplyScalar(0.9);
      }
      if (b.bar) {
        b.bar.scale.x = Math.max(0.001, b.bar.userData.w * Math.min(1, sc.beat || 0));
        b.live.material.color.setRGB(1, 0.19, 0.28).multiplyScalar(0.35 + 0.65 * Math.abs(Math.sin(f.time * 2.4)));
        const list = sc.ticker && sc.ticker.length ? sc.ticker : [], tk = JSON.stringify(list);
        if (tk !== b.ticked) { b.ticked = tk; ticker(b, list.length ? list : [' ']); }
        b.tick.material.map.offset.x = (f.time * 64 * PX / b.tickW) % 1;
      }
    });
    for (const k in boards) if (!live[k]) boards[k].g.visible = false;
  }

  /* ── what is under and round everything ── */
  // The light under the islands, each island's own glow in it, and the ring that leaves the middle when fresh data
  // lands: the old sky shader's lower half, kept whole because every part of it says something. Its upper half was a
  // night sky; the hall stands there now.
  const tri = new THREE.BufferGeometry(); tri.setAttribute('position', new THREE.BufferAttribute(new Float32Array([-1, -1, 0, 3, -1, 0, -1, 3, 0]), 3));
  shown(tri, new THREE.ShaderMaterial({ uniforms: U, depthTest: false, depthWrite: false,
    vertexShader: 'void main() { gl_Position = vec4(position.xy, 1.0, 1.0); }',
    fragmentShader: `uniform vec3 uEye, uR, uU, uF; uniform vec2 uRes, uPx; uniform float uFocal, uTime, uMood, uPulse, uGridY, uSpan;
      uniform vec4 uIsle[24]; uniform vec3 uIsleCol[24]; uniform int uIsles;
      void main() {
        vec2 p = (gl_FragCoord.xy / uPx - 0.5) * uRes; vec3 d = normalize(uF * uFocal + uR * p.x + uU * p.y);
        vec3 hor = mix(vec3(0.05, 0.09, 0.30), vec3(0.34, 0.05, 0.09), uMood);
        vec3 col = mix(hor, vec3(0.008, 0.014, 0.05), smoothstep(0.0, 0.6, abs(d.y))) + hor * 0.9 * exp(-abs(d.y) * 9.0);
        float t = (uGridY - uEye.y) / d.y;
        if (t > 0.0) {
          vec2 w = uEye.xz + d.xz * t; float fade = exp(-t * 0.22 / uSpan);
          vec2 q = w / 3.0, gw = fwidth(q), gl2 = abs(fract(q - 0.5) - 0.5) / max(gw, vec2(1e-4));
          float line = (1.0 - min(min(gl2.x, gl2.y), 1.0)) * exp(-t * 0.75 / uSpan);
          vec3 oc = vec3(0.010, 0.016, 0.045) + mix(vec3(0.10, 0.36, 0.85), vec3(0.85, 0.16, 0.20), uMood) * line * 0.55;
          for (int i = 0; i < 24; i++) { if (i >= uIsles) break; vec2 dd = w - uIsle[i].xy; float r = uIsle[i].z;
            oc += uIsleCol[i] * exp(-dot(dd, dd) / (r * r)) * (0.42 + 0.08 * sin(uTime * 1.4 + float(i) * 1.7)); }
          float ring = exp(-pow((length(w) - uPulse * uSpan * 0.55) / (uSpan * 0.02 + 0.6), 2.0)) * exp(-uPulse * 0.9);
          oc += mix(vec3(0.25, 0.75, 1.0), vec3(1.0, 0.3, 0.3), uMood) * ring * 0.9;
          oc += vec3(0.03, 0.08, 0.2) * (0.5 + 0.5 * sin(length(w) * 0.7 - uTime * 1.1)) * 0.10;
          col = mix(col, oc, fade);
        }
        gl_FragColor = vec4(pow(col, vec3(2.2)) * 1.6, 1.0);
      }` }), -10);
  const motes = new THREE.BufferGeometry(), seeds = new Float32Array(700 * 4), dice = rnd(3); for (let i = 0; i < seeds.length; i++) seeds[i] = dice();
  motes.setAttribute('position', new THREE.BufferAttribute(new Float32Array(700 * 3), 3)); motes.setAttribute('aS', new THREE.BufferAttribute(seeds, 4));
  const dust = new THREE.Points(motes, new THREE.ShaderMaterial(Object.assign({ uniforms: { uTime: U.uTime, uFocal: U.uFocal, uDpr: U.uDpr, uBox: U.uBox },
    vertexShader: `attribute vec4 aS; uniform float uTime, uFocal, uDpr; uniform vec3 uBox; varying float vA;
      void main() { vec3 p = (fract(aS.xyz + vec3(0.0, uTime * 0.012 * (0.3 + aS.w), 0.0)) - 0.5) * uBox;
        p.x += sin(uTime * 0.3 + aS.w * 40.0) * 0.6; p.z += cos(uTime * 0.25 + aS.w * 31.0) * 0.6; p.y += uBox.y * 0.32;
        vec4 c = projectionMatrix * viewMatrix * vec4(p, 1.0); gl_Position = c; gl_PointSize = clamp(uFocal * 0.07 * (0.4 + aS.w) / max(c.w, 0.5), 1.0, 7.0) * uDpr;
        vA = (0.35 + 0.65 * sin(uTime * (0.6 + aS.w) + aS.w * 60.0)) * smoothstep(0.5, 3.0, c.w); }`,
    fragmentShader: 'varying float vA;\nvoid main() { vec2 c = gl_PointCoord - 0.5; float f = max(1.0 - dot(c, c) * 4.0, 0.0); gl_FragColor = vec4(vec3(0.45, 0.75, 1.0) * f * f * max(vA, 0.0) * 0.4, 1.0); }' }, added)));
  dust.frustumCulled = false; dust.renderOrder = 7; scene.add(dust);

  /* The hall: built to the size of what stands in it, and built again when that changes much. Every face of it looks
     inward, so a camera drawn back out through a wall sees the scene and not the wall. */
  const wallSkin = boardWall(), rackSkins = [1, 2, 3, 4].map((i) => rackFace(40 + i)), fans = [];
  const tiles = new THREE.MeshStandardMaterial({ map: floorTiles(), roughness: 0.3, metalness: 0.6, transparent: true, opacity: 0.5, depthWrite: false });
  const ember = paper((g, w, h) => { const k = g.createRadialGradient(w / 2, h / 2, 4, w / 2, h / 2, w / 2); k.addColorStop(0, '#ffffff'); k.addColorStop(0.45, '#b9b9b9'); k.addColorStop(1, '#2a2a2a'); g.fillStyle = k; g.fillRect(0, 0, w, h); }, 256, 256);
  let hall = null, hallSpan = 0, hallY = 1e9;
  function room(span, y) {
    if (hall) { scene.remove(hall); hall.traverse((o) => { if (o.geometry) o.geometry.dispose(); }); }
    hall = new THREE.Group(); hallSpan = span; hallY = y; fans.length = 0; scene.add(hall);
    const D = span * 1.5 + 46, tall = Math.max(48, span * 0.55 + 34), dice2 = rnd(42);
    const flat = (w, h, mat, x, yy, z, rx, ry) => { const m = new THREE.Mesh(new THREE.PlaneGeometry(w, h), mat); m.position.set(x, yy, z); m.rotation.set(rx || 0, ry || 0, 0); hall.add(m); return m; };
    tiles.map.repeat.set(D / 3, D / 3);
    flat(D * 2, D * 2, tiles, 0, y - 0.05, 0, -Math.PI / 2).renderOrder = -5;
    const shade = flat(D * 2, D * 2, new THREE.ShadowMaterial({ opacity: 0.42 }), 0, y - 0.04, 0, -Math.PI / 2); shade.receiveShadow = true; shade.renderOrder = -4;
    wallSkin.map.repeat.set(Math.max(2, Math.round(D / 40)), 1); wallSkin.emissiveMap.repeat.copy(wallSkin.map.repeat);
    [[0, -D, 0], [0, D, Math.PI], [-D, 0, Math.PI / 2], [D, 0, -Math.PI / 2]].forEach(([x, z, turn], side) => {
      flat(D * 2, tall, wallSkin, x, y + tall / 2, z, 0, turn);
      const ax = side < 2 ? 1 : 0, inward = 1.2;      // racks stand along every wall, and on two of them a row of fans turns above the racks
      for (let u = -D + 7; u < D - 6; u += 11) {
        const h = [14, 19, 25][dice2() * 3 | 0], px = ax ? u : x + (x < 0 ? inward : -inward), pz = ax ? z + (z < 0 ? inward : -inward) : u;
        flat(10, h, rackSkins[dice2() * 4 | 0], px, y + h / 2, pz, 0, turn);
      }
      if (side < 2) for (const u of [-D * 0.5, 0, D * 0.5]) {
        const R = Math.min(14, tall * 0.2), g = new THREE.Group(), blades = new THREE.Group(), hot = side ? 0xff8a3d : 0x3dc8ff;
        g.add(new THREE.Mesh(new THREE.CircleGeometry(R, 40), new THREE.MeshBasicMaterial({ map: ember, color: new THREE.Color(hot).multiplyScalar(1.5) })));
        for (let i = 0; i < 7; i++) { const b = new THREE.Mesh(new THREE.PlaneGeometry(R * 0.9, R * 0.26), new THREE.MeshBasicMaterial({ color: 0x06080c })); b.geometry.translate(R * 0.5, 0, 0); b.rotation.z = i * Math.PI * 2 / 7; blades.add(b); }
        const rim = new THREE.Mesh(new THREE.RingGeometry(R, R * 1.1, 48), new THREE.MeshBasicMaterial({ color: 0x06080c })); blades.position.z = 0.05; rim.position.z = 0.06; g.add(blades, rim);
        g.position.set(u, y + tall * 0.66, z + (z < 0 ? 0.6 : -0.6)); g.rotation.y = turn; hall.add(g); fans.push(blades);
      }
    });
    for (const z of [-D * 0.45, 0, D * 0.45]) flat(D * 1.8, 1.6, new THREE.MeshBasicMaterial({ color: new THREE.Color(0xbfdcff).multiplyScalar(2.2) }), 0, y + tall - 1, z, Math.PI / 2);      // bars of light, seen only from under them
    scene.fog.density = 0.36 / (D * 1.4);
  }

  /* A cluster in a hall: the view has stood its machines either side of an aisle and says where each bay is. Behind
     every bay goes its rack, dark where the machine is not ready; down the aisle runs the bus, black glass with a
     line of light each side; the floor is glass over the light the old view keeps under everything, so the volumes
     that hang under the pods are still there to be seen; and the far end is the fan that cools the room. */
  let bayMark = 0;
  function bayHall(b, n, y, mark) {
    if (hall) { scene.remove(hall); hall.traverse((o) => { if (o.geometry) o.geometry.dispose(); }); }
    hall = new THREE.Group(); hallSpan = -1; bayMark = mark; fans.length = 0; scene.add(hall);
    let x0 = 1e9, x1 = -1e9, deep = 0, half = 1e9;
    for (let i = 0; i < n; i++) { const o = i * 6, z = b[o + 1], d = b[o + 3]; x0 = Math.min(x0, b[o]); x1 = Math.max(x1, b[o] + b[o + 2]); deep = Math.max(deep, d); half = Math.min(half, b[o + 4] < 0 ? -(z + d) : z); }
    const mid = (x0 + x1) / 2, len = x1 - x0 + 44, wide = half + deep + 15, tall = 44, RH = 8.5;
    const flat = (w, h, mat, x, yy, z, rx, ry) => { const m = new THREE.Mesh(new THREE.PlaneGeometry(w, h), mat); m.position.set(x, yy, z); m.rotation.set(rx || 0, ry || 0, 0); hall.add(m); return m; };
    const lamp = (w, h, d, hex, power, x, yy, z) => { const m = new THREE.Mesh(new THREE.BoxGeometry(w, h, d), new THREE.MeshBasicMaterial({ color: new THREE.Color(hex).multiplyScalar(power) })); m.position.set(x, yy, z); hall.add(m); return m; };
    tiles.map.repeat.set(len / 3, wide * 2 / 3); tiles.opacity = 0.4;
    flat(len, wide * 2, tiles, mid, -0.07, 0, -Math.PI / 2).renderOrder = -5;
    const shade = flat(len, wide * 2, new THREE.ShadowMaterial({ opacity: 0.4 }), mid, -0.06, 0, -Math.PI / 2); shade.receiveShadow = true; shade.renderOrder = -4;
    flat(len - 8, half * 2 - 1.0, new THREE.MeshStandardMaterial({ color: 0x04070c, roughness: 0.07, metalness: 0.92, transparent: true, opacity: 0.82 }), mid, -0.04, 0, -Math.PI / 2).renderOrder = -3;
    for (const side of [-1, 1]) {
      lamp(len - 8, 0.07, 0.16, 0x35d6ff, 1.7, mid, 0.0, side * (half - 0.5));
      wallSkin.map.repeat.set(Math.max(2, Math.round(len / 60)), 1); wallSkin.emissiveMap.repeat.copy(wallSkin.map.repeat);
      flat(len, tall, wallSkin, mid, tall / 2 - 4, side * wide, 0, side > 0 ? Math.PI : 0);
      flat(len - 10, 1.4, new THREE.MeshBasicMaterial({ color: new THREE.Color(0xbfdcff).multiplyScalar(2.2) }), mid, tall - 5, side * (half + 3), Math.PI / 2);
    }
    for (let i = 0; i < n; i++) {      // its rack, behind each bay
      const o = i * 6, w = b[o + 2], side = b[o + 4] || -1, back = side < 0 ? b[o + 1] : b[o + 1] + b[o + 3], kind = b[o + 5], face = rackSkins[i % 4].clone();
      face.map = face.map.clone(); face.emissiveMap = face.emissiveMap.clone();
      [face.map, face.emissiveMap].forEach((t) => { t.wrapS = THREE.RepeatWrapping; t.repeat.set(Math.max(1, Math.round(w / 7)), 1); t.needsUpdate = true; });
      face.emissiveIntensity = kind === 3 ? 0.05 : 1.5; face.userData.live = kind !== 3; face.userData.beat = 0.5 + (i % 5) * 0.21;
      const dark = new THREE.MeshStandardMaterial({ color: 0x0d1016, roughness: 0.45, metalness: 0.6 });
      const rack = new THREE.Mesh(new THREE.BoxGeometry(w, RH, 1.3), [dark, dark, dark, dark, face, dark]);
      rack.position.set(b[o] + w / 2, RH / 2, back + side * 0.85); rack.rotation.y = side < 0 ? 0 : Math.PI; rack.castShadow = rack.receiveShadow = true; rack.userData.face = face; hall.add(rack);
      lamp(w, 0.08, 0.14, kind === 3 ? 0xff4d5e : kind === 2 ? 0xffb23d : kind === 1 ? 0x3b82f6 : 0x35d6ff, 1.8, b[o] + w / 2, RH + 0.1, back + side * 0.2);
    }
    for (const end of [-1, 1]) {      // the two ends: a board each, and at the far one the fan
      flat(wide * 2, tall, wallSkin, mid + end * len / 2, tall / 2 - 4, 0, 0, end > 0 ? -Math.PI / 2 : Math.PI / 2);
      if (end < 0) continue;
      const R = 9, g = new THREE.Group(), blades = new THREE.Group();
      g.add(new THREE.Mesh(new THREE.CircleGeometry(R, 40), new THREE.MeshBasicMaterial({ map: ember, color: new THREE.Color(0x3dc8ff).multiplyScalar(1.6) })));
      for (let i = 0; i < 7; i++) { const bl = new THREE.Mesh(new THREE.PlaneGeometry(R * 0.9, R * 0.26), new THREE.MeshBasicMaterial({ color: 0x06080c })); bl.geometry.translate(R * 0.5, 0, 0); bl.rotation.z = i * Math.PI * 2 / 7; blades.add(bl); }
      const rim = new THREE.Mesh(new THREE.RingGeometry(R, R * 1.1, 48), new THREE.MeshBasicMaterial({ color: 0x06080c })); blades.position.z = 0.05; rim.position.z = 0.06; g.add(blades, rim);
      g.position.set(mid + len / 2 - 0.6, 14, 0); g.rotation.y = -Math.PI / 2; hall.add(g); fans.push(blades);
    }
    scene.fog.density = 0.0052;
  }

  /* A city in a hall: the view has laid out its streets and lots and says where they are (`town`). The streets become
     the bus, black glass with a line of light each side; a rack block stands on every lot no cluster stands on; and a
     ring of racks, the board and the fans close the hall round the whole city, beyond the gate and its square. The
     clusters, the gate, the people and everything they do are the view's own, as before. */
  let townSeen = null, signHeart = null;
  function townHall(T, y) {
    if (hall) { scene.remove(hall); hall.traverse((o) => { if (o.geometry) o.geometry.dispose(); }); }
    hall = new THREE.Group(); hallSpan = -2; townSeen = T; fans.length = 0; scene.add(hall);
    const hw = T.w / 2 + T.road + 36, north = -T.d / 2 - T.road - 36, south = T.gate + 76, cz = (north + south) / 2, hz = (south - north) / 2, tall = 66, dice2 = rnd(42);
    const flat = (w, h, mat, x, yy, z, rx, ry) => { const m = new THREE.Mesh(new THREE.PlaneGeometry(w, h), mat); m.position.set(x, yy, z); m.rotation.set(rx || 0, ry || 0, 0); hall.add(m); return m; };
    const lamp = (w, h, d, hex, power, x, yy, z) => { const m = new THREE.Mesh(new THREE.BoxGeometry(w, h, d), new THREE.MeshBasicMaterial({ color: new THREE.Color(hex).multiplyScalar(power) })); m.position.set(x, yy, z); hall.add(m); return m; };
    const shade = flat(hw * 2, hz * 2, new THREE.ShadowMaterial({ opacity: 0.38 }), 0, 0.012, cz, -Math.PI / 2); shade.receiveShadow = true; shade.renderOrder = -4;
    const glass = new THREE.MeshStandardMaterial({ color: 0x04070c, roughness: 0.08, metalness: 0.9, transparent: true, opacity: 0.55, depthWrite: false, polygonOffset: true, polygonOffsetFactor: -1, polygonOffsetUnits: -1 });
    const long = T.d + T.road * 2, across = T.w + T.road;
    T.xs.forEach((x) => { flat(T.road - 1.4, long, glass, x, 0.006, 0, -Math.PI / 2).renderOrder = -3; for (const k of [-1, 1]) lamp(0.12, 0.04, long, 0x35d6ff, 1.25, x + k * (T.road / 2 - 0.45), 0.03, 0); });
    T.zs.forEach((z) => { flat(across, T.road - 1.4, glass, 0, 0.007, z, -Math.PI / 2).renderOrder = -3; for (const k of [-1, 1]) lamp(across, 0.04, 0.12, 0x35d6ff, 1.25, 0, 0.03, z + k * (T.road / 2 - 0.45)); });
    const dark = new THREE.MeshStandardMaterial({ color: 0x0d1016, roughness: 0.45, metalness: 0.6 }), shapes = {};
    const rack = (x, z, h, turn) => {      // one cabinet, a face of machines on every side you can walk past
      const f = rackSkins[dice2() * 4 | 0], m = new THREE.Mesh(shapes[h] || (shapes[h] = new THREE.BoxGeometry(7.4, h, 8)), [f, f, dark, dark, f, f]);
      m.position.set(x, h / 2, z); m.rotation.y = turn || 0; m.castShadow = m.receiveShadow = true; hall.add(m);
    };
    const tallOf = () => [12, 17, 23][dice2() * 3 | 0];
    T.parks.forEach((o) => { for (const i of [-1, 0, 1]) for (const j of [-1, 1]) rack(o.x + i * 7.1, o.z + j * 4.6, tallOf()); });      // a block of them where no cluster stands
    for (let x = -hw + 20; x <= hw - 20; x += 9) { rack(x, north + 12, tallOf() + 6); rack(x, south - 12, tallOf() + 6); }
    for (let z = north + 24; z <= south - 24; z += 9) { rack(-hw + 12, z, tallOf() + 6, Math.PI / 2); rack(hw - 12, z, tallOf() + 6, Math.PI / 2); }
    wallSkin.map.repeat.set(Math.max(2, Math.round(hw / 40)), 1); wallSkin.emissiveMap.repeat.copy(wallSkin.map.repeat);
    [[0, north, 0, hw * 2], [0, south, Math.PI, hw * 2], [-hw, cz, Math.PI / 2, hz * 2], [hw, cz, -Math.PI / 2, hz * 2]].forEach(([x, z, turn, wide], side) => {
      flat(wide, tall, wallSkin, x, tall / 2 - 2, z, 0, turn);
      if (side > 1) return;
      for (const u of [-hw * 0.5, 0, hw * 0.5]) {
        const R = 13, g = new THREE.Group(), blades = new THREE.Group(), hot = side ? 0xff8a3d : 0x3dc8ff;
        g.add(new THREE.Mesh(new THREE.CircleGeometry(R, 40), new THREE.MeshBasicMaterial({ map: ember, color: new THREE.Color(hot).multiplyScalar(1.5) })));
        for (let i = 0; i < 7; i++) { const b = new THREE.Mesh(new THREE.PlaneGeometry(R * 0.9, R * 0.26), new THREE.MeshBasicMaterial({ color: 0x06080c })); b.geometry.translate(R * 0.5, 0, 0); b.rotation.z = i * Math.PI * 2 / 7; blades.add(b); }
        const rim = new THREE.Mesh(new THREE.RingGeometry(R, R * 1.1, 48), new THREE.MeshBasicMaterial({ color: 0x06080c })); blades.position.z = 0.05; rim.position.z = 0.06; g.add(blades, rim);
        g.position.set(u, tall * 0.62, z + (z < cz ? 0.6 : -0.6)); g.rotation.y = turn; hall.add(g); fans.push(blades);
      }
    });
    for (const x of T.xs) flat(1.5, hz * 1.7, new THREE.MeshBasicMaterial({ color: new THREE.Color(0xbfdcff).multiplyScalar(2.0) }), x, tall - 2, cz, Math.PI / 2);      // a bar of light over each street
    signHeart = null;
    if (T.love) {      // the sign every city has, in letters you can walk round: I, a heart, and the name of the place
      const L = T.love, word = traced(L.name), eye = traced('I'), cap = INK * 0.72, gap = INK * 0.26, heartW = INK * 0.84, total = eye.w + gap + heartW + gap + word.w;
      const k = Math.min(L.w / total, L.tall * 1.45 / cap), deep = { depth: 0.95 / k, bevelEnabled: true, bevelSize: 0.06 / k, bevelThickness: 0.07 / k, bevelSegments: 3, curveSegments: 6 };
      const white = new THREE.MeshPhysicalMaterial({ color: 0xb9bfcc, roughness: 0.34, metalness: 0.05, clearcoat: 0.8, clearcoatRoughness: 0.14, emissive: 0x8fa6e6, emissiveIntensity: 0.05 });      // under white: lit from in front it reads as white, and brighter than this it burns out
      signHeart = new THREE.MeshPhysicalMaterial({ color: 0xc8102a, roughness: 0.24, metalness: 0.05, clearcoat: 1, clearcoatRoughness: 0.08, emissive: 0xff1838, emissiveIntensity: 0.3 });
      const words = new THREE.Group(), stand = (shapes, mat, at) => { if (!shapes.length) return; const m = new THREE.Mesh(new THREE.ExtrudeGeometry(shapes, deep), mat); m.position.x = at; m.castShadow = m.receiveShadow = true; words.add(m); };
      let x = -total / 2;
      stand(eye.shapes, white, x); x += eye.w + gap; stand([heartShape(heartW, cap * 1.04)], signHeart, x); x += heartW + gap; stand(word.shapes, white, x);
      words.scale.setScalar(k); words.position.set(0, 0.3, L.z - 0.48); hall.add(words);
      for (const side of [-0.3, 0.3]) { const up = new THREE.PointLight(0xe6eeff, 26, 30, 2); up.position.set(side * L.w, 3.2, L.z + 7); hall.add(up); }
    }
    scene.fog.density = 0.0034;
  }

  function resize(w, h, ratio) {
    W = w; H = h; renderer.setPixelRatio(ratio); renderer.setSize(w, h, false); composer.setPixelRatio(ratio); composer.setSize(w, h);
    U.uRes.value.set(w, h); U.uPx.value.set(Math.max(2, Math.round(w * ratio)), Math.max(2, Math.round(h * ratio))); U.uDpr.value = ratio;
    camera.aspect = w / h;
  }
  const R3 = new THREE.Vector3(), U3 = new THREE.Vector3(), F3 = new THREE.Vector3(), focus = new THREE.Vector3();
  function draw(f) {
    R3.fromArray(f.right); U3.fromArray(f.up); F3.fromArray(f.fwd);
    camera.position.fromArray(f.eye); camera.quaternion.setFromRotationMatrix(basis.makeBasis(R3, U3, F3.clone().negate()));
    camera.fov = 2 * Math.atan(H / (2 * f.focal)) * 180 / Math.PI; camera.updateProjectionMatrix(); camera.updateMatrixWorld();
    U.uTime.value = f.time; U.uFocal.value = f.focal; U.uEye.value.copy(camera.position); U.uR.value.copy(R3); U.uU.value.copy(U3); U.uF.value.copy(F3);
    U.uMood.value = f.mood; U.uPulse.value = f.pulse; U.uGridY.value = f.gridY; U.uSpan.value = f.span; U.uIsles.value = f.nIsles || 0;
    if (f.nIsles) { U.uIsle.value.set(f.isles.subarray(0, f.nIsles * 4)); U.uIsleCol.value.set(f.isleCols.subarray(0, f.nIsles * 3)); }
    U.uBox.value.set(f.span * 2.4, f.span * 0.7, f.span * 2.4);
    if (f.fogCol) scene.fog.color.setRGB(f.fogCol[0], f.fogCol[1], f.fogCol[2], THREE.SRGBColorSpace);      // the air takes the cluster's mood, as it did
    if (f.nBays) { let mark = f.nBays; for (let i = 0; i < f.nBays * 6; i++) mark += f.bays[i] * (i + 1); if (mark !== bayMark || hallSpan !== -1) bayHall(f.bays, f.nBays, f.gridY, mark); }
    else if (f.town) { if (f.town !== townSeen || hallSpan !== -2) townHall(f.town, f.gridY); }
    else if (!hall || hallSpan < 0 || Math.abs(f.span - hallSpan) > hallSpan * 0.25 + 2 || Math.abs(f.gridY - hallY) > 0.5) room(f.span, f.gridY);
    podLights.visible = !!f.nBays; lit.take(f.nBays ? f.orbs : null, f.nOrbs);
    if (hall && hallSpan === -1) hall.children.forEach((o) => { const fc = o.userData.face; if (fc && fc.userData.live) fc.emissiveIntensity = 1.0 + 0.7 * Math.abs(Math.sin(f.time * fc.userData.beat)); });
    fans.forEach((b, i) => { b.rotation.z = f.time * (i % 2 ? 1.1 : 0.8); });
    wallSkin.emissiveIntensity = WALL_GLOW + WALL_GLOW * 0.35 * Math.abs(Math.sin(f.time * 0.35)); rackSkins.forEach((m, i) => { m.emissiveIntensity = 1.1 + 0.6 * Math.abs(Math.sin(f.time * (0.5 + i * 0.23))); });
    park(f); people(f); screensOf(f); fill.position.copy(camera.position); fill.target.position.copy(camera.position).addScaledVector(F3, 10);
    if (signHeart) signHeart.emissiveIntensity = 0.22 + 0.45 * Math.pow(Math.abs(Math.sin(f.time * 2.2)), 6);
    boxes.take(f.boxes, f.nBoxes); balls.take(f.balls, f.nBalls || 0); softs.take(f.softs, f.nSofts || 0); orbs.take(f.orbs, f.nOrbs);
    glows.take(f.glows, f.nGlows); beams.take(f.beams, f.nBeams); sprites.take(f.sprites, f.nSprites); discs.take(f.shadows, f.nShadows);
    let used = 0;
    for (let i = 0; i < f.nOrbs && used < rings.length; i++) {
      const o = i * 16, on = f.orbs[o + 15]; if (!(on > 0)) continue;
      const r = rings[used++]; r.visible = true; r.position.set(f.orbs[o], f.orbs[o + 1], f.orbs[o + 2]); r.quaternion.copy(camera.quaternion); r.scale.setScalar(f.orbs[o + 3]); r.material.color.setScalar(1.35 * on);
    }
    for (; used < rings.length; used++) rings[used].visible = false;
    // the lamp follows what you are looking at, so the shadows are sharp where you are and reach as far as you can see
    const reach = Math.max(6, Math.min(f.span * 1.4, (f.eye[1] - f.gridY) / Math.max(0.12, -f.fwd[1]))), half = [30, 45, 70, 110, 170, 260].find((s) => s >= reach * 1.15 + 16) || 260;
    focus.copy(camera.position).addScaledVector(F3, reach); focus.set(Math.round(focus.x / 4) * 4, f.gridY, Math.round(focus.z / 4) * 4);
    sun.target.position.copy(focus); sun.position.copy(focus).addScaledVector(SUN, half * 2.2);
    if (sun.shadow.camera.right !== half) { Object.assign(sun.shadow.camera, { left: -half, right: half, top: half, bottom: -half, near: 1, far: half * 4.6 }); sun.shadow.camera.updateProjectionMatrix(); }
    bloom.strength = 0.25 + 0.3 * (f.bloom == null ? 1 : f.bloom);
    composer.render();
  }
  return { resize, draw, atlas, hdr: true, hall: true };      // `hall`: this engine stands a cluster's machines along an aisle, and the view lays them out that way
}
window.C3DGL = make;
