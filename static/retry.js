// WHAT YOU TYPED SURVIVES A REFUSED SAVE, on every form in the portal.
//
// A sweep of the routes found FORTY-ONE places where a POST that failed
// validation answered 303 -- so the form re-read its values from the database
// and everything the person had entered was gone, with an error at the top
// about a page they were sometimes no longer on. The worst held a playbook
// body, a twenty-field target, a pasted list of hosts.
//
// Fixing forty-one handlers by hand is forty-one chances to miss one, and it
// does nothing for the forty-second somebody writes next month. This does it
// once, for every form, in the one place a submission still exists after a
// redirect: the browser that sent it. The server-side rule still stands and is
// the better fix where a handler is being touched anyway -- see CLAUDE.md --
// but this is the floor, and the floor should not be "your work is gone".
//
// WHAT IS DELIBERATELY NOT KEPT: password fields, file inputs, and anything
// carrying `data-nosave`. A pasted private key or an API token must not be
// left in storage to make a form more convenient; those fields come back empty
// and the person pastes again, which is the one thing here worth retyping.
// Marked on the field rather than guessed from its name, so it is a decision
// somebody made rather than a regex that will be wrong once.
(function () {
  var KEY = 'envmap.retry.';
  var SKIP = new Set(['password', 'file', 'hidden', 'submit', 'button', 'reset']);

  function idOf(form) {
    // The action decides it, so the values come back to the form that sent
    // them and not to a different form that happens to be on the page.
    var a = form.getAttribute('action') || location.pathname;
    return KEY + (form.id || '') + '|' + a;
  }
  function sensitive(el) {
    if (SKIP.has((el.type || '').toLowerCase())) return true;
    if (el.hasAttribute('data-nosave')) return true;
    // A textarea holding a key is not typed `password`, so the template says
    // so with `data-nosave`. Belt and braces on the two names this portal
    // actually uses for pasted secrets.
    var n = (el.name || '').toLowerCase();
    return n === 'secret' || n === 'secret_key' || n === 'key';
  }
  function snapshot(form) {
    var out = {};
    var els = form.querySelectorAll('input[name], textarea[name], select[name]');
    for (var i = 0; i < els.length; i++) {
      var el = els[i];
      if (!el.name || el.disabled || sensitive(el)) continue;
      if (el.type === 'checkbox' || el.type === 'radio') {
        if (el.checked) (out[el.name] = out[el.name] || []).push(el.value || 'on');
      } else if (el.multiple && el.selectedOptions) {
        out[el.name] = [].map.call(el.selectedOptions, function (o) { return o.value; });
      } else {
        out[el.name] = [el.value];
      }
    }
    return out;
  }
  document.addEventListener('submit', function (e) {
    var form = e.target;
    if (!form || form.tagName !== 'FORM') return;
    if ((form.getAttribute('method') || 'get').toLowerCase() !== 'post') return;
    if (form.hasAttribute('data-noretry')) return;
    try {
      sessionStorage.setItem(idOf(form), JSON.stringify(snapshot(form)));
    } catch (x) { /* private mode, quota: a convenience, never a blocker */ }
  }, true);

  // RESTORED ONLY WHEN SOMETHING WAS REFUSED. Putting values back on an
  // ordinary visit would fight somebody who opened the form to start again.
  function restore() {
    var bad = document.querySelector('.flash.err');
    var good = document.querySelector('.flash.ok');
    var forms = document.querySelectorAll('form[method="post"], form[method="POST"]');
    var claimed = {};
    for (var i = 0; i < forms.length; i++) {
      var form = forms[i], k = idOf(form), raw = null;
      claimed[k] = true;
      try { raw = sessionStorage.getItem(k); } catch (x) { return; }
      if (!raw) continue;
      // A success clears it: the submission landed, so the copy is stale and
      // would come back the next time this form refused anything.
      if (!bad || good) { try { sessionStorage.removeItem(k); } catch (x) {} continue; }
      var data = null;
      try { data = JSON.parse(raw); } catch (x) { data = null; }
      try { sessionStorage.removeItem(k); } catch (x) {}
      if (!data) continue;
      var els = form.querySelectorAll('input[name], textarea[name], select[name]');
      for (var j = 0; j < els.length; j++) {
        var el = els[j];
        if (!el.name || el.disabled || sensitive(el)) continue;
        var vals = data[el.name];
        if (el.type === 'checkbox' || el.type === 'radio') {
          el.checked = !!vals && vals.indexOf(el.value || 'on') >= 0;
        } else if (vals && vals.length) {
          if (el.multiple && el.options) {
            for (var o = 0; o < el.options.length; o++)
              el.options[o].selected = vals.indexOf(el.options[o].value) >= 0;
          } else {
            el.value = vals[0];
          }
        }
      }
      form.setAttribute('data-restored', '1');
    }
    sweep(claimed);
  }

  // A SNAPSHOT LIVES EXACTLY ONE NAVIGATION. Everything above can only ever
  // delete a key whose form is on THIS page -- so a submission that lands
  // anywhere else left its copy in storage for the life of the tab, and past
  // sign-out, which only clears the server session. Three shapes did that,
  // and all three were the shapes worth caring about:
  //
  //   * a form fetched into a dialog after this function has already run
  //     (the cluster form, the GitOps resource editor) -- never restorable,
  //     so the copy was pure cost;
  //   * a SUCCESS that redirects to a page not carrying the form (a new
  //     certificate goes to the order it just made) -- so the leak happened
  //     precisely when nothing had gone wrong;
  //   * a refusal that redirects somewhere else entirely.
  //
  // A key nothing claimed on this load can never be restored by a later one
  // either -- restore only matches forms in the document -- so dropping it
  // costs nothing and is the only thing that bounds how long a value stays.
  // Defence in depth, not the control: `sensitive()` and the `data-nosave`
  // marks are what keep a private key out of storage in the first place.
  function sweep(claimed) {
    var kill = [];
    try {
      for (var i = 0; i < sessionStorage.length; i++) {
        var k = sessionStorage.key(i);
        if (k && k.indexOf(KEY) === 0 && !claimed[k]) kill.push(k);
      }
      for (var j = 0; j < kill.length; j++) sessionStorage.removeItem(kill[j]);
    } catch (x) { /* private mode: nothing was stored to clear */ }
  }
  if (document.readyState === 'loading')
    document.addEventListener('DOMContentLoaded', restore);
  else restore();
})();
