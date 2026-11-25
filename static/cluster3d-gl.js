/* The GPU half of the 3D cluster view (static/cluster3d.js decides WHAT is
   where; this draws it).

   STILL NO LIBRARY, AND NOW IT IS WEBGL. Everything in the scene is one of six
   instanced shapes, so the engine is six small shaders and a bloom chain:

     orbs     a pod is a sphere drawn on a flat square (the fragment shader
              works out the sphere), a ceramic robot whose visor and eyes are
              drawn on the sphere's own surface: it can turn its head, blink
              and cry, per pod, for free
     boxes    the islands, the frame and plinths that make each one a hall,
              the painted solids a walking figure is built of,
              its gauges, and the Service crystals
     beams    the connection lines, with light travelling along them
     glows    soft additive light
     sprites  the emoji marks that float over a pod
     shadows  a dark disc under each pod

   plus the sky and the ocean of light under everything, which are one
   full-screen shader. The camera is not a matrix: cluster3d.js already has an
   eye and three unit vectors for its own picking and labels, and the same four
   go to every shader, so the GPU and the labels can never disagree about where
   something is on screen.

   A shader that fails to compile says so in the console BY NAME. A black
   stage with nothing in the console is the one failure this file must not
   have. */
(function () {
  'use strict';

  var CAM = [
    'uniform vec3 uEye, uR, uU, uF; uniform vec2 uRes; uniform float uFocal;',
    'const float NEAR = 0.3; const float FAR = 1600.0;',
    'vec4 proj(vec3 p) { vec3 d = p - uEye; float z = dot(d, uF);',
    '  return vec4(dot(d, uR) * uFocal / (uRes.x * 0.5), dot(d, uU) * uFocal / (uRes.y * 0.5),',
    '    (z * (FAR + NEAR) - 2.0 * FAR * NEAR) / (FAR - NEAR), z); }',
    'float depthOf(vec3 p) { float z = max(dot(p - uEye, uF), NEAR);',
    '  return ((z * (FAR + NEAR) - 2.0 * FAR * NEAR) / (FAR - NEAR)) / z * 0.5 + 0.5; }'
  ].join('\n');
  var FOG = [
    'uniform float uFog; uniform vec3 uFogCol;',
    'vec3 fog(vec3 c, float dist) { return mix(uFogCol, c, exp(-dist * uFog)); }'
  ].join('\n');
  var HEAD = '#version 300 es\nprecision highp float;\n';

  var SRC = {};
  SRC.skyV = HEAD + 'void main() { vec2 p = vec2(float((gl_VertexID << 1) & 2), float(gl_VertexID & 2)); gl_Position = vec4(p * 2.0 - 1.0, 1.0, 1.0); }';
  SRC.skyF = HEAD + [
    'uniform vec3 uEye, uR, uU, uF; uniform vec2 uRes, uPx; uniform float uFocal, uTime, uMood, uPulse, uGridY, uSpan;',
    'uniform vec4 uIsle[24]; uniform vec3 uIsleCol[24]; uniform int uIsles;',
    'out vec4 o;',
    'float hash(vec2 p) { p = fract(p * vec2(123.34, 456.21)); p += dot(p, p + 45.32); return fract(p.x * p.y); }',
    'float noise(vec2 p) { vec2 i = floor(p), f = fract(p); f = f * f * (3.0 - 2.0 * f);',
    '  return mix(mix(hash(i), hash(i + vec2(1, 0)), f.x), mix(hash(i + vec2(0, 1)), hash(i + vec2(1, 1)), f.x), f.y); }',
    'float fbm(vec2 p) { float a = 0.5, s = 0.0; for (int i = 0; i < 5; i++) { s += a * noise(p); p = p * 2.03 + 17.0; a *= 0.5; } return s; }',
    'void main() {',
    '  vec2 p = (gl_FragCoord.xy / uPx - 0.5) * uRes;',
    '  vec3 d = normalize(uF * uFocal + uR * p.x + uU * p.y);',
    '  vec3 hor = mix(vec3(0.05, 0.09, 0.30), vec3(0.34, 0.05, 0.09), uMood);',
    '  vec3 col = mix(hor, vec3(0.008, 0.014, 0.05), smoothstep(0.0, 0.6, abs(d.y)));',
    '  col += hor * 0.9 * exp(-abs(d.y) * 9.0);',
    // the sky is flattened onto a plane, so there is no seam to hide
    '  vec2 sp = d.xz / (0.4 + abs(d.y));',
    '  float up = smoothstep(-0.02, 0.35, d.y);',
    '  float n = fbm(sp * 1.3 + vec2(uTime * 0.006, 0.0)), n2 = fbm(sp * 2.4 + 9.0);',
    '  col += mix(vec3(0.22, 0.08, 0.40), vec3(0.45, 0.06, 0.10), uMood) * smoothstep(0.45, 0.85, n) * 0.5 * up;',
    '  col += vec3(0.03, 0.22, 0.30) * smoothstep(0.5, 0.9, n2) * 0.42 * up * (1.0 - uMood * 0.6);',
    '  vec2 g = sp * 70.0, id = floor(g), f = fract(g) - 0.5; float st = hash(id);',
    '  float star = smoothstep(0.975, 1.0, st) * smoothstep(0.2, 0.0, length(f)) * (0.55 + 0.45 * sin(uTime * (1.0 + st * 3.0) + st * 40.0));',
    '  col += vec3(0.8, 0.9, 1.0) * star * 1.5 * up;',
    '  float t = (uGridY - uEye.y) / d.y;',
    '  if (t > 0.0) {',
    // the ocean of light the islands hang over
    '    vec2 w = uEye.xz + d.xz * t; float fade = exp(-t * 0.22 / uSpan);',
    '    vec2 q = w / 3.0, gw = fwidth(q), gl2 = abs(fract(q - 0.5) - 0.5) / max(gw, vec2(1e-4));',
    '    float line = (1.0 - min(min(gl2.x, gl2.y), 1.0)) * exp(-t * 0.75 / uSpan);',
    '    vec3 oc = vec3(0.010, 0.016, 0.045) + mix(vec3(0.10, 0.36, 0.85), vec3(0.85, 0.16, 0.20), uMood) * line * 0.55;',
    '    for (int i = 0; i < 24; i++) { if (i >= uIsles) break;',
    '      vec2 dd = w - uIsle[i].xy; float r = uIsle[i].z;',
    '      oc += uIsleCol[i] * exp(-dot(dd, dd) / (r * r)) * (0.42 + 0.08 * sin(uTime * 1.4 + float(i) * 1.7)); }',
    // the heartbeat: a ring leaves the middle each time fresh data lands
    '    float ring = exp(-pow((length(w) - uPulse * uSpan * 0.55) / (uSpan * 0.02 + 0.6), 2.0)) * exp(-uPulse * 0.9);',
    '    oc += mix(vec3(0.25, 0.75, 1.0), vec3(1.0, 0.3, 0.3), uMood) * ring * 0.9;',
    '    oc += vec3(0.03, 0.08, 0.2) * (0.5 + 0.5 * sin(length(w) * 0.7 - uTime * 1.1)) * 0.10;',
    '    col = mix(col, oc, fade);',
    '  }',
    '  o = vec4(col, 1.0);',
    '}'
  ].join('\n');

  SRC.boxV = HEAD + CAM + [
    'layout(location=0) in vec3 a_pos; layout(location=1) in vec3 a_nrm;',
    'layout(location=2) in vec3 i_pos; layout(location=3) in vec3 i_size; layout(location=4) in vec4 i_colg; layout(location=5) in vec4 i_misc;',
    'uniform float uPass;',
    'out vec3 vN, vW, vL, vSize; out vec4 vCol, vMisc;',
    'vec3 rz(vec3 v, float a) { float c = cos(a), s = sin(a); return vec3(v.x * c - v.y * s, v.x * s + v.y * c, v.z); }',
    'vec3 rx(vec3 v, float a) { float c = cos(a), s = sin(a); return vec3(v.x, v.y * c - v.z * s, v.y * s + v.z * c); }',
    'vec3 ry(vec3 v, float a) { float c = cos(a), s = sin(a); return vec3(v.x * c + v.z * s, v.y, -v.x * s + v.z * c); }',
    'void main() {',
    '  float kind = i_misc.w; vec3 p = a_pos, n = a_nrm;',
    // a beacon is a cube standing on one corner
    '  if (kind > 1.5 && kind < 2.5) { p = rx(rz(p, 0.7854), 0.6155); n = rx(rz(n, 0.7854), 0.6155); }',
    '  vL = a_pos; p = p * i_size;',
    // A painted box may lean about its own x and tip about its own z before it
    // turns: that is what lets a limb swing from a joint and a figure flip.
    // Painted boxes use neither a rim nor an alpha, so those two carry the angles.
    // A shape stretched along one axis keeps its roundness only if its normal
    // is squeezed the other way: that is what makes a ball pulled long read
    // as an arm and not as a flat-lit blob.
    '  if (kind > 4.5) { n = n / i_size; p = rz(rx(p, i_misc.y), i_misc.z); n = rz(rx(n, i_misc.y), i_misc.z); }',
    '  p = ry(p, i_misc.x); n = ry(n, i_misc.x);',
    '  vW = p + i_pos; vN = n; vCol = i_colg; vMisc = i_misc; vSize = i_size;',
    '  bool blended = kind > 0.5 && kind < 1.5;',
    '  gl_Position = (blended == (uPass > 0.5)) ? proj(vW) : vec4(2.0, 2.0, 2.0, 1.0);',
    '}'
  ].join('\n');
  SRC.boxF = HEAD + [
    'uniform vec3 uEye; uniform float uTime;', FOG,
    'in vec3 vN, vW, vL, vSize; in vec4 vCol, vMisc; out vec4 o;',
    'void main() {',
    '  float kind = vMisc.w; vec3 N = normalize(vN), c = vCol.rgb; float dist = length(vW - uEye);',
    '  vec2 e = (0.5 - abs(vL.xz)) * vSize.xz; float ed = min(e.x, e.y);',
    '  if (kind < 0.5) {',
    '    vec3 base = vec3(0.030, 0.045, 0.105), col;',
    '    if (N.y > 0.5) {',
    '      vec2 gq = vW.xz / 1.5, gw = fwidth(gq), gl2 = abs(fract(gq - 0.5) - 0.5) / max(gw, vec2(1e-4));',
    '      float grid = (1.0 - min(min(gl2.x, gl2.y), 1.0)) * 0.07;',
    '      col = base + c * (exp(-ed * 2.6) * 1.9 * vMisc.y + grid) + vec3(0.02, 0.03, 0.06) * exp(-dist * 0.03);',
    '    } else if (N.y < -0.5) col = base * 0.5 + c * (0.12 + 0.5 * vCol.a) * exp(-ed * 0.5);',
    '    else { float h = vL.y + 0.5; col = base * 0.7 + c * (pow(h, 4.0) * 1.7 * vMisc.y + (1.0 - h) * (0.10 + 0.5 * vCol.a)); }',
    '    o = vec4(fog(col, dist), 1.0);',
    '  } else if (kind < 1.5) {',
    '    if (N.y < 0.5) discard;',
    '    float edge = smoothstep(0.14, 0.0, ed);',
    '    o = vec4(c * (0.5 + edge * 1.1), vMisc.z * (0.10 + edge * 0.42));',
    '  } else if (kind < 2.5) {',
    '    vec3 V = normalize(uEye - vW);',
    // a Service is a crystal: dark faces, and every edge alight
    '    vec3 al = abs(vL); float wire = smoothstep(0.40, 0.5, max(min(al.x, al.y), max(min(al.y, al.z), min(al.x, al.z))));',
    '    float l = 0.5 + 0.5 * max(dot(N, normalize(vec3(0.45, 0.85, 0.3))), 0.0), fr = pow(1.0 - abs(dot(N, V)), 2.0);',
    '    o = vec4(fog(c * (l * 0.22 + fr * 0.5 + wire * (1.5 + vCol.a * 1.5)), dist), 1.0);',
    '  } else if (kind < 3.5) {',
    // a gauge: nothing but its own light
    '    o = vec4(fog(c * (1.1 + vCol.a * 2.0), dist), 1.0);',
    '  } else if (kind < 4.5) {',
    // metal: a dark frame, plinth or post with a thin line of light along every edge
    '    vec3 de = (0.5 - abs(vL)) * vSize; float mn = min(de.x, min(de.y, de.z)), mx = max(de.x, max(de.y, de.z)), mid = de.x + de.y + de.z - mn - mx;',
    '    float l = 0.35 + 0.65 * max(dot(N, normalize(vec3(0.45, 0.85, 0.3))), 0.0);',
    '    o = vec4(fog(vec3(0.05, 0.062, 0.095) * l * 1.5 + c * smoothstep(0.06, 0.0, mid) * (0.55 + vCol.a), dist), 1.0);',
    '  } else {',
    // painted: a solid in its own colour, lit like clay. The figures that are
    // not pods (the person walking, a doctor) are built of these; its glow is
    // light of its own, for an eye or a trim.
    '    vec3 V = normalize(uEye - vW); float l = 0.40 + 0.60 * max(dot(N, normalize(vec3(0.45, 0.85, 0.3))), 0.0);',
    '    vec3 amb = mix(vec3(0.10, 0.11, 0.20), vec3(0.36, 0.42, 0.60), N.y * 0.5 + 0.5);',
    '    float sp = pow(max(dot(reflect(-normalize(vec3(0.45, 0.85, 0.3)), N), V), 0.0), 22.0) * 0.16;',
    '    o = vec4(fog(c * (l + amb * 0.4 + pow(1.0 - abs(dot(N, V)), 3.0) * 0.25 + vCol.a * 2.0) + vec3(sp), dist), 1.0);',
    '  }',
    '}'
  ].join('\n');

  SRC.orbV = HEAD + CAM + [
    'layout(location=0) in vec2 a_c;',
    'layout(location=1) in vec4 i_posr; layout(location=2) in vec4 i_col; layout(location=3) in vec4 i_face; layout(location=4) in vec4 i_misc;',
    'uniform float uGrow;',
    'out vec2 vC; out vec4 vPosr, vCol, vFace, vMisc;',
    'void main() {',
    '  vC = a_c * 1.2; float rad = i_posr.w * uGrow;',
    '  vec3 w = i_posr.xyz + (uR * vC.x + uU * vC.y * i_misc.z) * rad;',
    '  vPosr = vec4(i_posr.xyz, rad); vCol = i_col; vFace = i_face; vMisc = i_misc;',
    '  gl_Position = (uGrow > 1.1 && i_misc.y < 0.0) ? vec4(2.0, 2.0, 2.0, 1.0) : proj(w);',
    '}'
  ].join('\n');
  // A pod is a small ceramic robot: a dark visor with two eyes of light. The
  // eyes are the whole expression, and their colour is its state. Nothing else
  // on it is coloured, except a cap in the colour of the software it runs.
  SRC.orbF = HEAD + CAM + FOG + [
    'uniform float uTime;',
    'in vec2 vC; in vec4 vPosr, vCol, vFace, vMisc; out vec4 o;',
    'float seg(vec2 p, vec2 a, vec2 b) { vec2 pa = p - a, ba = b - a; return length(pa - ba * clamp(dot(pa, ba) / dot(ba, ba), 0.0, 1.0)); }',
    'float arc(vec2 p, vec2 c, float r) { return abs(length(p - c) - r); }',
    'vec3 cap(float i) {',
    '  if (i < 0.5) return vec3(0.22, 0.48, 0.95); if (i < 1.5) return vec3(0.58, 0.38, 0.95); if (i < 2.5) return vec3(0.95, 0.46, 0.20);',
    '  if (i < 3.5) return vec3(0.16, 0.72, 0.62); if (i < 4.5) return vec3(0.92, 0.68, 0.10); if (i < 5.5) return vec3(0.88, 0.34, 0.62);',
    '  if (i < 6.5) return vec3(0.22, 0.66, 0.90); if (i < 7.5) return vec3(0.36, 0.70, 0.22); if (i < 8.5) return vec3(0.40, 0.44, 0.55);',
    '  return vec3(0.82, 0.52, 0.22); }',
    'void main() {',
    '  vec2 q = vC; float r2 = dot(q, q);',
    '  if (r2 > 1.0) {',
    // outside the ball: only the ring round what is selected or pointed at
    '    float rr = sqrt(r2), ring = smoothstep(1.07, 1.10, rr) * smoothstep(1.19, 1.16, rr);',
    '    if (vMisc.w <= 0.0 || ring < 0.5) discard;',
    '    o = vec4(vec3(1.35) * vMisc.w, 1.0); gl_FragDepth = depthOf(vPosr.xyz); return;',
    '  }',
    // a see-through pod is drawn as a screen door, so nothing needs sorting
    '  if (vCol.a < 0.99) { float dn = fract(52.9829189 * fract(dot(gl_FragCoord.xy, vec2(0.06711056, 0.00583715)))); if (dn > vCol.a) discard; }',
    '  float nz = sqrt(1.0 - r2);',
    '  vec3 N = normalize(uR * q.x + uU * q.y - uF * nz), wp = vPosr.xyz + N * vPosr.w;',
    '  gl_FragDepth = depthOf(wp);',
    '  float seed = vFace.w, dimk = vFace.z > 15.5 ? 0.2 : 1.0; int m = int(mod(vFace.z, 16.0) + 0.5);',
    '  vec3 L = normalize(vec3(0.45, 0.85, 0.3)), V = -uF, lite = vCol.rgb;',
    '  float diff = max(dot(N, L), 0.0), spec = pow(max(dot(N, normalize(L + V)), 0.0), 70.0), fres = pow(1.0 - nz, 3.0);',
    '  vec3 amb = mix(vec3(0.10, 0.11, 0.20), vec3(0.36, 0.42, 0.60), N.y * 0.5 + 0.5);',
    '  vec3 lightc = amb * 0.45 + (diff * 0.7 + 0.18) * vec3(1.0, 0.97, 0.93), col;',
    '  if (m == 9) {',
    // not a pod: a plain ball lit in its own colour, with a seam of light
    '    col = lite * 0.5 * lightc + lite * fres * 0.9 + spec * 0.6 + lite * smoothstep(0.06, 0.0, abs(N.y)) * 1.3;',
    '  } else {',
    '    float yaw = vFace.x, pit = vFace.y;',
    '    vec3 Fw = vec3(sin(yaw) * cos(pit), sin(pit), cos(yaw) * cos(pit)), Rt = normalize(cross(vec3(0.0, 1.0, 0.0), Fw)), Up = cross(Fw, Rt);',
    '    vec2 p = vec2(dot(N, Rt), dot(N, Up)); float fz = dot(N, Fw); vec2 pm = vec2(abs(p.x), p.y);',
    '    vec3 body = vec3(0.86, 0.88, 0.93) * dimk;',
    '    if (vMisc.x >= 0.0) body = mix(body, cap(vMisc.x) * dimk, smoothstep(0.50, 0.55, N.y) * 0.92);',
    '    float belt = smoothstep(0.036, 0.012, abs(N.y + 0.36));',
    '    float aa = clamp(fwidth(p.x) + fwidth(p.y), 0.004, 0.05);',
    '    float vis = length(max(abs(p - vec2(0.0, 0.10)) - vec2(0.40, 0.085), 0.0)) - 0.17;',
    '    float inVis = (1.0 - smoothstep(-aa, aa, vis)) * smoothstep(0.05, 0.25, fz);',
    '    vec2 eye = vec2(0.24, 0.10); float th = 0.034, sd = 9.0;',
    '    float blink = step(0.968, fract(uTime * 0.23 + seed * 7.0));',
    '    float dots = length((pm - eye) / vec2(1.0, mix(1.0, 0.18, blink))) - 0.075;',
    '    float dash = max(abs(pm.x - eye.x) - 0.085, abs(pm.y - eye.y) - 0.022);',
    '    if (m == 0) sd = max(arc(pm, eye - vec2(0.0, 0.055), 0.095) - th, -(pm.y - eye.y + 0.03));',
    '    else if (m == 1) sd = dots - 0.012 * sin(uTime * 22.0);',
    '    else if (m == 2) sd = max(dots, pm.y - eye.y - 0.02 + (pm.x - eye.x) * 0.6);',
    '    else if (m == 3) sd = dash;',
    '    else if (m == 4) sd = max(arc(pm, eye, 0.07) - th * 0.8, sin(atan(pm.y - eye.y, pm.x - eye.x) + uTime * 5.0));',
    '    else if (m == 5) sd = dash + 0.01;',
    '    else if (m == 6) sd = seg(pm, eye + vec2(-0.085, 0.05), eye + vec2(0.085, -0.05)) - th;',
    '    else if (m == 7) sd = min(seg(pm, eye - vec2(0.07), eye + vec2(0.07)), seg(pm, eye + vec2(-0.07, 0.07), eye + vec2(0.07, -0.07))) - th * 0.8;',
    '    else sd = dash + 0.008;',
    '    float ink = (1.0 - smoothstep(-aa, aa, sd)) * inVis;',
    '    col = body * lightc + spec * 0.5 * dimk + fres * vec3(0.30, 0.45, 0.9) * 0.2 * dimk;',
    '    col = mix(col, (vec3(0.022, 0.03, 0.06) + fres * 0.07 + spec * 0.55) * (0.4 + 0.6 * dimk), inVis);',
    '    col += lite * (ink * 2.5 + belt * (0.85 + 0.35 * sin(uTime * 2.0 + seed * 20.0)));',
    '    if (m == 6) {',
    // one tear, falling from the visor
    '      float f = fract(uTime * 0.8 + seed), dr = length((pm - vec2(eye.x, eye.y - 0.20 - f * 0.42)) / vec2(0.035, 0.06));',
    '      col = mix(col, vec3(0.5, 0.85, 1.0) * 1.5, smoothstep(1.0, 0.6, dr) * (1.0 - f) * step(0.15, fz) * dimk);',
    '    }',
    // a starting pod is still being drawn: a line of light sweeps up it
    '    if (m == 4) col += lite * smoothstep(0.035, 0.0, abs(N.y - (fract(uTime * 0.5 + seed) * 2.0 - 1.0))) * 1.6;',
    '  }',
    '  o = vec4(fog(col, length(wp - uEye)), 1.0);',
    '}'
  ].join('\n');
  // The bubble round a pod is its memory limit, filled to what it uses.
  SRC.bubF = HEAD + CAM + [
    'uniform float uTime;',
    'in vec2 vC; in vec4 vPosr, vCol, vFace, vMisc; out vec4 o;',
    'void main() {',
    '  float r2 = dot(vC, vC); if (r2 > 1.0) discard; float nz = sqrt(1.0 - r2);',
    '  vec3 N = normalize(uR * vC.x + uU * vC.y - uF * nz);',
    '  gl_FragDepth = depthOf(vPosr.xyz + N * vPosr.w);',
    '  float level = floor(vMisc.y), fill = fract(vMisc.y) / 0.999;',
    '  vec3 tone = level > 1.5 ? vec3(1.0, 0.22, 0.30) : level > 0.5 ? vec3(1.0, 0.66, 0.14) : vec3(0.22, 0.95, 0.62);',
    '  float h = N.y * 0.5 + 0.5 + 0.012 * sin(uTime * 2.2 + N.x * 7.0 + vFace.w * 30.0);',
    '  float fres = pow(1.0 - nz, 2.4), surf = exp(-pow((h - fill) / 0.03, 2.0));',
    '  vec3 col = tone * (fres * 0.75 + step(h, fill) * 0.06 + surf * 0.4 * (1.0 - fres * 0.6));',
    '  o = vec4(col * vCol.a * 0.6, 1.0);',
    '}'
  ].join('\n');

  SRC.sprV = HEAD + CAM + [
    'layout(location=0) in vec2 a_c; layout(location=1) in vec4 i_posr; layout(location=2) in vec4 i_g;',
    'out vec2 vC; out vec4 vG;',
    'void main() { float c = cos(i_g.z), s = sin(i_g.z); vec2 r = vec2(a_c.x * c - a_c.y * s, a_c.x * s + a_c.y * c);',
    '  vC = a_c; vG = i_g; gl_Position = proj(i_posr.xyz + (uR * r.x + uU * r.y) * i_posr.w); }'
  ].join('\n');
  SRC.sprF = HEAD + [
    'uniform sampler2D uAtlas; uniform float uCols; in vec2 vC; in vec4 vG; out vec4 o;',
    'void main() { vec2 uv = vC * 0.5 + 0.5, cell = vec2(mod(vG.x, uCols), floor(vG.x / uCols));',
    '  vec4 t = texture(uAtlas, (cell + vec2(uv.x, 1.0 - uv.y)) / uCols); o = vec4(t.rgb * t.a, t.a) * vG.y; }'
  ].join('\n');

  SRC.glowV = HEAD + CAM + [
    'layout(location=0) in vec2 a_c; layout(location=1) in vec4 i_posr; layout(location=2) in vec4 i_col;',
    'out vec2 vC; out vec4 vCol;',
    'void main() { vC = a_c; vCol = i_col; gl_Position = proj(i_posr.xyz + (uR * a_c.x + uU * a_c.y) * i_posr.w); }'
  ].join('\n');
  SRC.glowF = HEAD + 'in vec2 vC; in vec4 vCol; out vec4 o;\nvoid main() { float d = dot(vC, vC); float f = max(exp(-d * 4.5) - 0.011, 0.0); o = vec4(vCol.rgb * f * vCol.a, 1.0); }';

  SRC.beamV = HEAD + CAM + [
    'layout(location=0) in vec2 a_c; layout(location=1) in vec3 i_a; layout(location=2) in vec3 i_b;',
    'layout(location=3) in vec4 i_col; layout(location=4) in vec4 i_w; layout(location=5) in vec2 i_d;',
    'out float vSide, vU; out vec4 vCol, vW; out vec2 vD;',
    'void main() {',
    '  vec4 pa = proj(i_a), pb = proj(i_b);',
    '  if (pa.w < NEAR || pb.w < NEAR) { gl_Position = vec4(2.0, 2.0, 2.0, 1.0); return; }',
    '  vec2 dir = (pb.xy / pb.w - pa.xy / pa.w) * uRes; float len = length(dir); dir = len > 1e-4 ? dir / len : vec2(1.0, 0.0);',
    '  vec4 p = mix(pa, pb, a_c.x);',
    // as wide as it is in the world, and never thinner than a hair
    '  float px = max(i_w.x * uFocal / p.w, 1.1);',
    // a connection is a thread however close you stand to it; only a column of light is wide
    '  if (i_w.x < 0.12) px = min(px, 5.0);',
    '  p.xy += vec2(-dir.y, dir.x) * a_c.y * px / (uRes * 0.5) * p.w;',
    '  vSide = a_c.y; vU = mix(i_w.y, i_w.z, a_c.x); vCol = i_col; vW = i_w; vD = i_d; gl_Position = p;',
    '}'
  ].join('\n');
  SRC.beamF = HEAD + [
    'uniform float uTime; in float vSide, vU; in vec4 vCol, vW; in vec2 vD; out vec4 o;',
    'void main() { float core = exp(-vSide * vSide * 4.5), pk = 0.0;',
    '  if (vD.x > 0.0) { float ph = fract(vU * vD.x - uTime * vW.w + vD.y); pk = smoothstep(0.0, 0.05, ph) * smoothstep(0.32, 0.05, ph); }',
    '  o = vec4(vCol.rgb * (vCol.a * core * (0.5 + pk * 3.4)), 1.0); }'
  ].join('\n');

  SRC.shV = HEAD + CAM + [
    'layout(location=0) in vec2 a_c; layout(location=1) in vec4 i_s; out vec2 vC; out float vA;',
    'void main() { vC = a_c; vA = i_s.w; gl_Position = proj(vec3(i_s.x + a_c.x * i_s.z, 0.03, i_s.y + a_c.y * i_s.z)); }'
  ].join('\n');
  SRC.shF = HEAD + 'in vec2 vC; in float vA; out vec4 o;\nvoid main() { o = vec4(0.0, 0.0, 0.0, vA * smoothstep(1.0, 0.15, length(vC))); }';

  SRC.dustV = HEAD + CAM + [
    'layout(location=0) in vec4 a_s; uniform float uTime, uDpr; uniform vec3 uBox; out float vA;',
    'void main() { vec3 p = (fract(a_s.xyz + vec3(0.0, uTime * 0.012 * (0.3 + a_s.w), 0.0)) - 0.5) * uBox;',
    '  p.x += sin(uTime * 0.3 + a_s.w * 40.0) * 0.6; p.z += cos(uTime * 0.25 + a_s.w * 31.0) * 0.6; p.y += uBox.y * 0.32;',
    '  vec4 c = proj(p); gl_Position = c; gl_PointSize = clamp(uFocal * 0.07 * (0.4 + a_s.w) / max(c.w, 0.5), 1.0, 7.0) * uDpr;',
    '  vA = (0.35 + 0.65 * sin(uTime * (0.6 + a_s.w) + a_s.w * 60.0)) * smoothstep(0.5, 3.0, c.w); }'
  ].join('\n');
  SRC.dustF = HEAD + 'in float vA; out vec4 o;\nvoid main() { vec2 c = gl_PointCoord - 0.5; float f = max(1.0 - dot(c, c) * 4.0, 0.0); o = vec4(vec3(0.45, 0.75, 1.0) * f * f * max(vA, 0.0) * 0.5, 1.0); }';

  SRC.postV = HEAD + 'out vec2 vUv;\nvoid main() { vec2 p = vec2(float((gl_VertexID << 1) & 2), float(gl_VertexID & 2)); vUv = p; gl_Position = vec4(p * 2.0 - 1.0, 0.0, 1.0); }';
  SRC.downF = HEAD + [
    'uniform sampler2D uT; uniform vec2 uTexel; uniform float uThresh; in vec2 vUv; out vec4 o;',
    'void main() { vec3 c = texture(uT, vUv).rgb * 4.0;',
    '  c += texture(uT, vUv + uTexel * vec2(-1.0, -1.0)).rgb + texture(uT, vUv + uTexel * vec2(1.0, -1.0)).rgb',
    '     + texture(uT, vUv + uTexel * vec2(-1.0, 1.0)).rgb + texture(uT, vUv + uTexel * vec2(1.0, 1.0)).rgb; c /= 8.0;',
    '  if (uThresh > 0.0) { float l = max(c.r, max(c.g, c.b)); c *= max(l - uThresh, 0.0) / max(l, 1e-4); }',
    '  o = vec4(min(c, vec3(24.0)), 1.0); }'
  ].join('\n');
  SRC.upF = HEAD + [
    'uniform sampler2D uT; uniform vec2 uTexel; in vec2 vUv; out vec4 o;',
    'void main() { vec3 c = texture(uT, vUv + uTexel * vec2(-2.0, 0.0)).rgb + texture(uT, vUv + uTexel * vec2(2.0, 0.0)).rgb',
    '  + texture(uT, vUv + uTexel * vec2(0.0, -2.0)).rgb + texture(uT, vUv + uTexel * vec2(0.0, 2.0)).rgb;',
    '  c += 2.0 * (texture(uT, vUv + uTexel * vec2(-1.0, -1.0)).rgb + texture(uT, vUv + uTexel * vec2(1.0, -1.0)).rgb',
    '  + texture(uT, vUv + uTexel * vec2(-1.0, 1.0)).rgb + texture(uT, vUv + uTexel * vec2(1.0, 1.0)).rgb);',
    '  o = vec4(c / 12.0, 1.0); }'
  ].join('\n');
  SRC.finalF = HEAD + [
    'uniform sampler2D uT, uB; uniform float uBloom, uTime; in vec2 vUv; out vec4 o;',
    'void main() { vec3 c = texture(uT, vUv).rgb + texture(uB, vUv).rgb * uBloom;',
    // bright things roll off instead of clipping to flat white
    '  c = c / (1.0 + max(c - 0.82, 0.0) * 0.55);',
    '  vec2 v = vUv - 0.5; c *= 1.0 - 0.42 * pow(length(v) * 1.28, 2.6);',
    '  c += (fract(sin(dot(gl_FragCoord.xy + uTime, vec2(12.9898, 78.233))) * 43758.5453) - 0.5) * 0.012;',
    '  o = vec4(c, 1.0); }'
  ].join('\n');

  function make(canvas) {
    var gl = canvas.getContext('webgl2', { antialias: false, alpha: false, depth: false, powerPreference: 'high-performance' });
    if (!gl) return null;
    var hdr = !!gl.getExtension('EXT_color_buffer_float');
    var ok = true;

    function shader(type, src, name) {
      var s = gl.createShader(type); gl.shaderSource(s, src); gl.compileShader(s);
      if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) {
        ok = false; console.error('cluster3d: the ' + name + ' shader did not compile: ' + gl.getShaderInfoLog(s));
      }
      return s;
    }
    function program(v, f, name) {
      var p = gl.createProgram();
      gl.attachShader(p, shader(gl.VERTEX_SHADER, SRC[v], name + ' vertex'));
      gl.attachShader(p, shader(gl.FRAGMENT_SHADER, SRC[f], name + ' fragment'));
      gl.linkProgram(p);
      if (!gl.getProgramParameter(p, gl.LINK_STATUS)) { ok = false; console.error('cluster3d: the ' + name + ' program did not link: ' + gl.getProgramInfoLog(p)); }
      var u = {}, n = gl.getProgramParameter(p, gl.ACTIVE_UNIFORMS) || 0;
      for (var i = 0; i < n; i++) { var info = gl.getActiveUniform(p, i), nm = info.name.replace('[0]', ''); u[nm] = gl.getUniformLocation(p, info.name); }
      return { p: p, u: u };
    }
    var P = {
      sky: program('skyV', 'skyF', 'sky'), box: program('boxV', 'boxF', 'box'), orb: program('orbV', 'orbF', 'orb'),
      bub: program('orbV', 'bubF', 'bubble'), spr: program('sprV', 'sprF', 'sprite'), glow: program('glowV', 'glowF', 'glow'),
      beam: program('beamV', 'beamF', 'beam'), sh: program('shV', 'shF', 'shadow'), dust: program('dustV', 'dustF', 'dust'),
      down: program('postV', 'downF', 'bloom down'), up: program('postV', 'upF', 'bloom up'), fin: program('postV', 'finalF', 'final')
    };
    if (!ok) return null;

    // one shape per kind of thing, repeated per instance from a buffer cluster3d.js fills
    function staticBuf(data) { var b = gl.createBuffer(); gl.bindBuffer(gl.ARRAY_BUFFER, b); gl.bufferData(gl.ARRAY_BUFFER, new Float32Array(data), gl.STATIC_DRAW); return b; }
    var quad = staticBuf([-1, -1, 1, -1, -1, 1, 1, 1]), strip = staticBuf([0, -1, 0, 1, 1, -1, 1, 1]);
    var cube = (function () {
      var out = [], faces = [[1, 0, 0], [-1, 0, 0], [0, 1, 0], [0, -1, 0], [0, 0, 1], [0, 0, -1]];
      faces.forEach(function (n) {
        var a = [n[1], n[2], n[0]], b = [n[1] * a[2] - n[2] * a[1], n[2] * a[0] - n[0] * a[2], n[0] * a[1] - n[1] * a[0]];
        [[-1, -1], [1, -1], [1, 1], [-1, -1], [1, 1], [-1, 1]].forEach(function (c) {
          for (var k = 0; k < 3; k++) out.push((n[k] + a[k] * c[0] + b[k] * c[1]) * 0.5);
          out.push(n[0], n[1], n[2]);
        });
      });
      return staticBuf(out);
    })();
    /* Round shapes for the figures: a ball, and a block with its edges
       rounded off. Both are one unit across, like the cube, so a size makes an
       arm of a ball and a chest of a block. `e` below 1 squares a ball up. */
    function round(e) {
      var out = [], U = 16, V = 12, i, j;
      function at(u, v) {
        var a = u / U * Math.PI * 2, b = v / V * Math.PI, x = Math.sin(b) * Math.cos(a), y = Math.cos(b), z = Math.sin(b) * Math.sin(a);
        function sq(q, k) { return (q < 0 ? -1 : 1) * Math.pow(Math.abs(q), k); }
        // the surface, and its normal: for this family the normal is the same point taken to the other power
        var k = 2 - e, nx = sq(x, k), ny = sq(y, k), nz = sq(z, k), nl = Math.hypot(nx, ny, nz) || 1;
        return [sq(x, e) * 0.5, sq(y, e) * 0.5, sq(z, e) * 0.5, nx / nl, ny / nl, nz / nl];
      }
      for (j = 0; j < V; j++) for (i = 0; i < U; i++) {
        [[i, j], [i + 1, j], [i + 1, j + 1], [i, j], [i + 1, j + 1], [i, j + 1]].forEach(function (c) { Array.prototype.push.apply(out, at(c[0], c[1])); });
      }
      return { buf: staticBuf(out), n: out.length / 6 };
    }
    var ball = round(1), soft = round(0.42);
    function shape(base, baseLayout, stride, layout) {
      var vao = gl.createVertexArray(), buf = gl.createBuffer(), off = 0, bs = 0;
      gl.bindVertexArray(vao); gl.bindBuffer(gl.ARRAY_BUFFER, base);
      baseLayout.forEach(function (n) { bs += n; });
      baseLayout.forEach(function (n, i) { gl.enableVertexAttribArray(i); gl.vertexAttribPointer(i, n, gl.FLOAT, false, bs * 4, off * 4); off += n; });
      gl.bindBuffer(gl.ARRAY_BUFFER, buf); off = 0;
      layout.forEach(function (n, i) {
        var loc = baseLayout.length + i; gl.enableVertexAttribArray(loc);
        gl.vertexAttribPointer(loc, n, gl.FLOAT, false, stride * 4, off * 4); gl.vertexAttribDivisor(loc, 1); off += n;
      });
      gl.bindVertexArray(null);
      return { vao: vao, buf: buf, stride: stride };
    }
    var S = {
      box: shape(cube, [3, 3], 14, [3, 3, 4, 4]), ball: shape(ball.buf, [3, 3], 14, [3, 3, 4, 4]), soft: shape(soft.buf, [3, 3], 14, [3, 3, 4, 4]),
      orb: shape(quad, [2], 16, [4, 4, 4, 4]), spr: shape(quad, [2], 8, [4, 4]),
      glow: shape(quad, [2], 8, [4, 4]), beam: shape(strip, [2], 16, [3, 3, 4, 4, 2]), sh: shape(quad, [2], 4, [4])
    };
    var dust = (function () {
      var n = 900, d = []; for (var i = 0; i < n * 4; i++) d.push(Math.random());
      var vao = gl.createVertexArray(); gl.bindVertexArray(vao); gl.bindBuffer(gl.ARRAY_BUFFER, staticBuf(d));
      gl.enableVertexAttribArray(0); gl.vertexAttribPointer(0, 4, gl.FLOAT, false, 0, 0); gl.bindVertexArray(null);
      return { vao: vao, n: n };
    })();
    var empty = gl.createVertexArray();

    // the emoji marks, drawn once into a sheet the shaders cut from
    var COLS = 8, atlasTex = gl.createTexture(), marks = {}, markN = 0, sheet = document.createElement('canvas');
    sheet.width = sheet.height = 1024;
    // An entry is a character, or {key, draw} for a mark that is drawn rather
    // than typed: draw(ctx, cx, cy, r) paints it into its own cell.
    function atlas(list) {
      var k = sheet.getContext('2d'), fresh = false;
      list.forEach(function (ch) {
        var name = ch.key || ch;
        if (marks[name] != null || markN >= COLS * COLS) return;
        var i = markN++, cx = (i % COLS) * 128 + 64, cy = Math.floor(i / COLS) * 128 + 64; marks[name] = i; fresh = true;
        if (ch.draw) { k.save(); ch.draw(k, cx, cy, 54); k.restore(); return; }
        k.font = '96px "Apple Color Emoji","Segoe UI Emoji","Noto Color Emoji",sans-serif';
        k.textAlign = 'center'; k.textBaseline = 'middle'; k.fillText(ch, cx, cy + 6);
      });
      if (fresh) {
        gl.bindTexture(gl.TEXTURE_2D, atlasTex);
        gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, sheet);
        gl.generateMipmap(gl.TEXTURE_2D);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR_MIPMAP_LINEAR);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
      }
      return marks;
    }
    atlas(['❔']);

    // where the picture is drawn before the glow is added to it
    var W = 1, H = 1, pxW = 1, pxH = 1, dpr = 1, scene = null, ms = null, mips = [];
    var IFMT = hdr ? gl.RGBA16F : gl.RGBA8, TYPE = hdr ? gl.HALF_FLOAT : gl.UNSIGNED_BYTE;
    function target(w, h, depth) {
      var t = gl.createTexture(), f = gl.createFramebuffer(), rb = null;
      gl.bindTexture(gl.TEXTURE_2D, t); gl.texImage2D(gl.TEXTURE_2D, 0, IFMT, w, h, 0, gl.RGBA, TYPE, null);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR); gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE); gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
      gl.bindFramebuffer(gl.FRAMEBUFFER, f); gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, t, 0);
      if (depth) {
        rb = gl.createRenderbuffer(); gl.bindRenderbuffer(gl.RENDERBUFFER, rb);
        gl.renderbufferStorage(gl.RENDERBUFFER, gl.DEPTH_COMPONENT24, w, h);
        gl.framebufferRenderbuffer(gl.FRAMEBUFFER, gl.DEPTH_ATTACHMENT, gl.RENDERBUFFER, rb);
      }
      return { f: f, t: t, rb: rb, w: w, h: h };
    }
    function smooth(w, h) {      // four samples a pixel, when this GPU will give them
      var f = gl.createFramebuffer(), c = gl.createRenderbuffer(), d = gl.createRenderbuffer();
      var n = Math.min(4, gl.getParameter(gl.MAX_SAMPLES) || 0); if (n < 2) return null;
      gl.bindFramebuffer(gl.FRAMEBUFFER, f);
      gl.bindRenderbuffer(gl.RENDERBUFFER, c); gl.renderbufferStorageMultisample(gl.RENDERBUFFER, n, IFMT, w, h);
      gl.framebufferRenderbuffer(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.RENDERBUFFER, c);
      gl.bindRenderbuffer(gl.RENDERBUFFER, d); gl.renderbufferStorageMultisample(gl.RENDERBUFFER, n, gl.DEPTH_COMPONENT24, w, h);
      gl.framebufferRenderbuffer(gl.FRAMEBUFFER, gl.DEPTH_ATTACHMENT, gl.RENDERBUFFER, d);
      if (gl.checkFramebufferStatus(gl.FRAMEBUFFER) !== gl.FRAMEBUFFER_COMPLETE) { gl.deleteFramebuffer(f); return null; }
      return { f: f, c: c, d: d };
    }
    function drop(t) { if (!t) return; gl.deleteFramebuffer(t.f); if (t.t) gl.deleteTexture(t.t); if (t.rb) gl.deleteRenderbuffer(t.rb); if (t.c) gl.deleteRenderbuffer(t.c); if (t.d) gl.deleteRenderbuffer(t.d); }
    function resize(w, h, ratio) {
      W = w; H = h; dpr = ratio; pxW = Math.max(2, Math.round(w * ratio)); pxH = Math.max(2, Math.round(h * ratio));
      canvas.width = pxW; canvas.height = pxH;
      drop(scene); drop(ms); mips.forEach(drop); mips = [];
      scene = target(pxW, pxH, true); ms = smooth(pxW, pxH);
      for (var i = 1; i <= 5; i++) mips.push(target(Math.max(2, pxW >> i), Math.max(2, pxH >> i), false));
      gl.bindFramebuffer(gl.FRAMEBUFFER, null);
    }

    function cam(pr, f) {
      gl.useProgram(pr.p); var u = pr.u;
      if (u.uEye) gl.uniform3fv(u.uEye, f.eye); if (u.uR) gl.uniform3fv(u.uR, f.right);
      if (u.uU) gl.uniform3fv(u.uU, f.up); if (u.uF) gl.uniform3fv(u.uF, f.fwd);
      if (u.uRes) gl.uniform2f(u.uRes, W, H); if (u.uFocal) gl.uniform1f(u.uFocal, f.focal);
      if (u.uTime) gl.uniform1f(u.uTime, f.time);
      if (u.uFog) gl.uniform1f(u.uFog, 0.2 / f.span); if (u.uFogCol) gl.uniform3fv(u.uFogCol, f.fogCol);
      if (u.uAtlas) { gl.activeTexture(gl.TEXTURE0); gl.bindTexture(gl.TEXTURE_2D, atlasTex); gl.uniform1i(u.uAtlas, 0); }
      if (u.uCols) gl.uniform1f(u.uCols, COLS);
      return u;
    }
    function inst(s, arr, n, verts, mode) {
      if (!n) return;
      gl.bindVertexArray(s.vao); gl.bindBuffer(gl.ARRAY_BUFFER, s.buf);
      gl.bufferData(gl.ARRAY_BUFFER, arr.subarray(0, n * s.stride), gl.DYNAMIC_DRAW);
      gl.drawArraysInstanced(mode, 0, verts, n);
    }
    function pass(pr, src, dst, texel, thresh) {
      gl.bindFramebuffer(gl.FRAMEBUFFER, dst.f); gl.viewport(0, 0, dst.w, dst.h);
      gl.useProgram(pr.p); gl.activeTexture(gl.TEXTURE0); gl.bindTexture(gl.TEXTURE_2D, src.t); gl.uniform1i(pr.u.uT, 0);
      gl.uniform2f(pr.u.uTexel, texel / src.w, texel / src.h);
      if (pr.u.uThresh) gl.uniform1f(pr.u.uThresh, thresh);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
    }

    function draw(f) {
      var u, TS = gl.TRIANGLE_STRIP;
      gl.bindFramebuffer(gl.FRAMEBUFFER, ms ? ms.f : scene.f); gl.viewport(0, 0, pxW, pxH);
      gl.disable(gl.BLEND); gl.disable(gl.DEPTH_TEST); gl.depthMask(true); gl.clearDepth(1); gl.clear(gl.DEPTH_BUFFER_BIT);
      gl.bindVertexArray(empty);
      u = cam(P.sky, f); gl.uniform2f(u.uPx, pxW, pxH); gl.uniform1f(u.uMood, f.mood); gl.uniform1f(u.uPulse, f.pulse);
      gl.uniform1f(u.uGridY, f.gridY); gl.uniform1f(u.uSpan, f.span); gl.uniform1i(u.uIsles, f.nIsles);
      if (f.nIsles) { gl.uniform4fv(u.uIsle, f.isles.subarray(0, f.nIsles * 4)); gl.uniform3fv(u.uIsleCol, f.isleCols.subarray(0, f.nIsles * 3)); }
      gl.drawArrays(gl.TRIANGLES, 0, 3);

      gl.enable(gl.DEPTH_TEST); gl.depthFunc(gl.LEQUAL);
      u = cam(P.box, f); gl.uniform1f(u.uPass, 0); inst(S.box, f.boxes, f.nBoxes, 36, gl.TRIANGLES);
      // the round shapes are painted solids like any other: same program, another mesh
      inst(S.ball, f.balls, f.nBalls || 0, ball.n, gl.TRIANGLES); inst(S.soft, f.softs, f.nSofts || 0, soft.n, gl.TRIANGLES);
      u = cam(P.orb, f); gl.uniform1f(u.uGrow, 1); inst(S.orb, f.orbs, f.nOrbs, 4, TS);

      gl.depthMask(false); gl.enable(gl.BLEND);
      gl.enable(gl.POLYGON_OFFSET_FILL); gl.polygonOffset(-2, -2);
      gl.blendFunc(gl.ZERO, gl.ONE_MINUS_SRC_ALPHA);
      cam(P.sh, f); inst(S.sh, f.shadows, f.nShadows, 4, TS);
      gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);
      u = cam(P.box, f); gl.uniform1f(u.uPass, 1); inst(S.box, f.boxes, f.nBoxes, 36, gl.TRIANGLES);
      gl.disable(gl.POLYGON_OFFSET_FILL);

      gl.blendFunc(gl.ONE, gl.ONE);
      cam(P.glow, f); inst(S.glow, f.glows, f.nGlows, 4, TS);
      cam(P.beam, f); inst(S.beam, f.beams, f.nBeams, 4, TS);
      u = cam(P.bub, f); gl.uniform1f(u.uGrow, 1.42); inst(S.orb, f.orbs, f.nOrbs, 4, TS);
      u = cam(P.dust, f); gl.uniform1f(u.uDpr, dpr); gl.uniform3f(u.uBox, f.span * 2.4, f.span * 0.7, f.span * 2.4);
      gl.bindVertexArray(dust.vao); gl.drawArrays(gl.POINTS, 0, dust.n);
      gl.blendFunc(gl.ONE, gl.ONE_MINUS_SRC_ALPHA);
      cam(P.spr, f); inst(S.spr, f.sprites, f.nSprites, 4, TS);
      gl.disable(gl.BLEND); gl.disable(gl.DEPTH_TEST); gl.depthMask(true);

      if (ms) {
        gl.bindFramebuffer(gl.READ_FRAMEBUFFER, ms.f); gl.bindFramebuffer(gl.DRAW_FRAMEBUFFER, scene.f);
        gl.blitFramebuffer(0, 0, pxW, pxH, 0, 0, pxW, pxH, gl.COLOR_BUFFER_BIT, gl.NEAREST);
      }
      // the glow: keep what is bright, shrink it five times, and add it back on the way up
      gl.bindVertexArray(empty);
      pass(P.down, scene, mips[0], 1, hdr ? 1.0 : 0.82);
      for (var i = 1; i < mips.length; i++) pass(P.down, mips[i - 1], mips[i], 1, 0);
      gl.enable(gl.BLEND); gl.blendFunc(gl.ONE, gl.ONE);
      for (i = mips.length - 1; i > 0; i--) pass(P.up, mips[i], mips[i - 1], 1, 0);
      gl.disable(gl.BLEND);
      gl.bindFramebuffer(gl.FRAMEBUFFER, null); gl.viewport(0, 0, pxW, pxH);
      gl.useProgram(P.fin.p); gl.activeTexture(gl.TEXTURE0); gl.bindTexture(gl.TEXTURE_2D, scene.t); gl.uniform1i(P.fin.u.uT, 0);
      gl.activeTexture(gl.TEXTURE1); gl.bindTexture(gl.TEXTURE_2D, mips[0].t); gl.uniform1i(P.fin.u.uB, 1);
      gl.uniform1f(P.fin.u.uBloom, f.bloom); gl.uniform1f(P.fin.u.uTime, f.time);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
      gl.activeTexture(gl.TEXTURE0);
    }
    return { resize: resize, draw: draw, atlas: atlas, hdr: hdr };
  }
  window.C3DGL = make;
})();
