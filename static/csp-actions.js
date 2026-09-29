/* THE INLINE-HANDLER REPLACEMENT. The Content-Security-Policy carries a nonce
   and no 'unsafe-inline', so the browser refuses every on* attribute in this
   product — an attribute has nowhere to put a nonce, which is exactly the
   property that makes an injected onmouseover= inert. 112 handlers used to be
   written inline; they are data attributes now and this is the one listener
   that runs them.

   A name is LOOKED UP on window, never evaluated. That is the whole security
   difference: data-call="removePicked" can only reach a function that already
   exists, where the old attribute was a place to put arbitrary source. */
(function () {
  function named(n) { return n && typeof window[n] === 'function' ? window[n] : null; }
  function args(el, e) {
    if (el.hasAttribute('data-arg-event')) return [e];
    if (el.hasAttribute('data-arg-self')) return [el];
    if (el.hasAttribute('data-arg')) return [el.getAttribute('data-arg')];
    return [];
  }

  document.addEventListener('click', function (e) {
    var el = e.target.closest && e.target.closest(
      '[data-dlg-open],[data-dlg-close],[data-dlg-close-self],[data-call],[data-stop],[data-noop]');
    if (!el) return;
    var id, d;
    if ((id = el.getAttribute('data-dlg-open')) && (d = document.getElementById(id))) d.showModal();
    if ((id = el.getAttribute('data-dlg-close')) && (d = document.getElementById(id))) d.close();
    if (el.hasAttribute('data-dlg-close-self') && (d = el.closest('dialog'))) d.close();
    var ask = el.getAttribute('data-confirm');
    if (ask && !confirm(ask.replace(/\\n/g, '\n'))) { e.preventDefault(); e.stopPropagation(); return; }
    if (el.hasAttribute('data-stop')) e.stopPropagation();
    if (el.hasAttribute('data-noop')) e.preventDefault();
    var f = named(el.getAttribute('data-call'));
    /* `return false` in an attribute meant "do not follow this link". A
       listener's return value is ignored, so the old contract is honoured by
       hand or every converted anchor would start navigating. */
    if (f && f.apply(el, args(el, e)) === false) e.preventDefault();
  });

  document.addEventListener('change', function (e) {
    var el = e.target;
    if (!el.getAttribute) return;
    if (el.hasAttribute('data-submit') && el.form) { el.form.submit(); return; }
    var f = named(el.getAttribute('data-call-change'));
    if (f) f.call(el, el.value);
  });

  document.addEventListener('input', function (e) {
    var el = e.target;
    if (!el.getAttribute) return;
    var f = named(el.getAttribute('data-call-input'));
    if (f) f.call(el, el.value);
  });

  /* Bubble phase, deliberately. The typed-Delete interceptor above is capture
     phase and re-submits with form.submit(), which fires no submit event at
     all — so a form cannot be asked to confirm twice. */
  document.addEventListener('submit', function (e) {
    var form = e.target, msg = form.getAttribute && form.getAttribute('data-confirm');
    /* An HTML attribute holds a backslash and an n as two characters, where
       the JS string literal these came from held one newline. */
    if (msg && !confirm(msg.replace(/\\n/g, '\n'))) { e.preventDefault(); return; }
    var f = named(form.getAttribute && form.getAttribute('data-call-submit'));
    /* A submit handler was written as onsubmit="return fn(this)", so the
       form is what it expects; data-arg overrides for the few that want a
       string instead. */
    if (f) {
      var a = args(form, e);
      if (f.apply(form, a.length ? a : [form]) === false) e.preventDefault();
    }
  });

  /* A row with tabindex=0 that acts as a button: Enter must do what a click
     does, and routing it through .click() keeps one definition of "what this
     row does" rather than a second copy in a keydown branch. */
  document.addEventListener('keydown', function (e) {
    if (e.key !== 'Enter') return;
    var el = e.target;
    if (el.hasAttribute && el.hasAttribute('data-enter')) { e.preventDefault(); el.click(); }
  });

  /* focus does not bubble. */
  document.addEventListener('focus', function (e) {
    if (e.target.hasAttribute && e.target.hasAttribute('data-selectall')) e.target.select();
  }, true);
})();
