/*
 * Client behaviour.
 *
 * Alpine is loaded as the **CSP build**, which cannot evaluate expressions
 * embedded in HTML attributes — there is no `new Function()` anywhere, which
 * is what lets the app ship `script-src 'self'` with no `unsafe-eval`.
 *
 * The rule that follows: every `x-*` attribute in a template may only name a
 * property or method that a component registered here exposes.
 *
 *   allowed:  x-data="flash"  x-on:click="dismiss"  x-show="visible"
 *   rejected: x-on:click="open = !open"  x-text="a + b"
 *
 * If you need logic, add a component below.
 */

document.addEventListener("alpine:init", () => {
  /* A transient confirmation, e.g. the "Saved" flash on the item status card.
   * Auto-dismisses so it does not linger next to a value the user has since
   * changed again. */
  Alpine.data("flash", () => ({
    visible: true,

    init() {
      this.timer = setTimeout(() => {
        this.visible = false;
      }, 4000);
    },

    destroy() {
      clearTimeout(this.timer);
    },

    dismiss() {
      this.visible = false;
    },
  }));

  /* Copy-to-clipboard for one-time secrets. Falls back silently on browsers
   * that refuse clipboard access. */
  Alpine.data("copyable", () => ({
    copied: false,

    async copy() {
      const source = this.$refs.value;
      if (!source) return;
      try {
        await navigator.clipboard.writeText(source.textContent.trim());
        this.copied = true;
        setTimeout(() => {
          this.copied = false;
        }, 2000);
      } catch {
        /* Clipboard blocked — the value is on screen to copy by hand. */
      }
    },
  }));
});

/* --- CSRF ----------------------------------------------------------------
 *
 * The server sets `app_csrf` as a *readable* cookie and expects the same value
 * back in the X-CSRF-Token header (signed double-submit). Plain forms carry it
 * in a hidden field; htmx requests get it from here, so no template has to
 * remember to add one to a `hx-post`.
 */

const CSRF_COOKIE = "app_csrf";
const CSRF_HEADER = "X-CSRF-Token";

function readCookie(name) {
  const prefix = `${name}=`;
  for (const part of document.cookie.split("; ")) {
    if (part.startsWith(prefix)) {
      return decodeURIComponent(part.slice(prefix.length));
    }
  }
  return null;
}

document.addEventListener("htmx:configRequest", (event) => {
  const token = readCookie(CSRF_COOKIE);
  if (token) event.detail.headers[CSRF_HEADER] = token;
});

/* Surface unexpected htmx failures instead of leaving the page looking frozen.
 * 4xx/5xx responses that carry an error fragment are swapped in by the server,
 * so this only fires for transport-level problems. */
document.addEventListener("htmx:sendError", () => {
  const banner = document.getElementById("connection-error");
  if (banner) banner.hidden = false;
});

document.addEventListener("htmx:afterRequest", (event) => {
  if (event.detail.successful) {
    const banner = document.getElementById("connection-error");
    if (banner) banner.hidden = true;
  }
});
