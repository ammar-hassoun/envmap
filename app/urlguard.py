"""One check every outbound request passes before it is made.

WHY
    Almost every page here fetches something from an address somebody typed
    into a settings form: an Argo CD, a DefectDojo, a BMC, a VPN portal. The
    URL is configuration, so it is trusted — but urllib will fetch whatever
    scheme it is handed, and "file:///etc/passwd" is a URL.

    That was not theoretical. A VPN portal whose base URL was
    file:///tmp/probe.txt returned the file's contents through the portal's own
    error path, and the security scanner's fetch read it too. Anybody able to
    add a connection could read files inside the container that way, including
    /proc/self/environ, which carries the sealing key and every variable the
    deployment sets.

WHAT IS ALLOWED
    http and https, and nothing else. There is no legitimate use for any other
    scheme in this application, so an allow-list costs nothing and closes the
    whole family — file, ftp, gopher, data, and whatever the next one is.

WHAT IS BLOCKED BEYOND THAT
    The cloud metadata address, 169.254.169.254 and its IPv6 equivalent. The
    portal is meant to reach private addresses — an Argo CD on 10.x is the
    normal case, so blocking private ranges would break the product. But the
    metadata service is not a thing anybody configures deliberately, and on a
    cloud host it hands out credentials for the asking.

WHAT THIS IS NOT
    It is not a full SSRF defence. A hostname that resolves to the metadata
    address, or DNS that answers differently the second time, will get through:
    stopping that needs resolution and connection to happen together, which
    urllib does not offer. This raises the floor; it does not claim the ceiling.
"""
from __future__ import annotations

import ipaddress
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_SCHEMES = ("http", "https")

# Link-local addresses that serve credentials on every major cloud.
METADATA_HOSTS = {
    "169.254.169.254",          # AWS, Azure, GCP, Alibaba, DigitalOcean
    "fd00:ec2::254",            # AWS IPv6
    "metadata.google.internal",
    "metadata.goog",
}


class BlockedURL(ValueError):
    """Raised instead of making the request."""


def check(url: str) -> str:
    """Return the URL, or raise BlockedURL saying why not."""
    raw = (url or "").strip()
    if not raw:
        raise BlockedURL("no address was given")
    try:
        bits = urllib.parse.urlsplit(raw)
    except ValueError as e:
        raise BlockedURL(f"that is not a usable address: {e}") from e

    scheme = (bits.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise BlockedURL(
            f"{scheme or 'that'}: addresses are not fetched — only http and "
            f"https. A URL is configuration here, and configuration should not "
            f"be able to read the portal's own filesystem")

    host = (bits.hostname or "").lower()
    if not host:
        raise BlockedURL("that address has no host in it")
    if host in METADATA_HOSTS:
        raise BlockedURL("that is the cloud metadata address, which hands out "
                         "credentials — the portal will not fetch it")
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_link_local:
            raise BlockedURL("link-local addresses are not fetched")
    except BlockedURL:
        raise
    except ValueError:
        pass                    # a name, not an address: nothing more to check
    return raw


# Headers a redirect to ANOTHER host keeps. Everything else — Authorization,
# Cookie, PRIVATE-TOKEN, X-Api-Key, whatever an integration authenticates
# with — stays behind: urllib copies every header onto the redirected request,
# so "302 to elsewhere" handed elsewhere the token, past the check made on the
# first address. A signed download link (a CI log, a release asset) needs
# none of them.
_KEEP_ACROSS = {"accept", "accept-encoding", "accept-language", "user-agent"}


class _Redirects(urllib.request.HTTPRedirectHandler):
    """Every hop is checked like the first address. Within the same host
    (same scheme and port, or http upgraded to https) a redirect is followed
    as before. To another host: `refuse` raises, `strip` follows it without
    the credentials."""

    def __init__(self, cross_host: str):
        super().__init__()
        self.cross_host = cross_host

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old = urllib.parse.urlsplit(req.full_url)
        new = urllib.parse.urlsplit(urllib.parse.urljoin(req.full_url, newurl))
        check(new.geturl())
        same = (new.hostname or "").lower() == (old.hostname or "").lower() and (
            (new.scheme, new.port) == (old.scheme, old.port)
            or (old.scheme == "http" and new.scheme == "https"))
        if not same and self.cross_host == "refuse":
            raise urllib.error.HTTPError(
                req.full_url, code, f"redirected to {new.hostname or 'another host'}, "
                "which is not followed", headers, fp)
        out = super().redirect_request(req, fp, code, msg, headers, newurl)
        if out is not None and not same:
            for k in list(out.headers):
                if k.lower() not in _KEEP_ACROSS:
                    del out.headers[k]
            for k in list(out.unredirected_hdrs):
                if k.lower() not in _KEEP_ACROSS:
                    del out.unredirected_hdrs[k]
        return out


_openers: dict = {}


def urlopen(req, timeout: float | None = None, context=None, cross_host: str = "strip"):
    """urllib.request.urlopen with every redirect checked (see _Redirects).
    `cross_host="refuse"` for a device whose credentials must never leave
    it: a BMC, a hypervisor.

    Without a context the opener is built once, as urllib's own is: building
    one makes a fresh default TLS context, a few milliseconds of loading the
    CA store on every request otherwise."""
    if context is None:
        opener = _openers.get(cross_host)
        if opener is None:
            opener = _openers[cross_host] = urllib.request.build_opener(_Redirects(cross_host))
    else:
        opener = urllib.request.build_opener(
            _Redirects(cross_host), urllib.request.HTTPSHandler(context=context))
    return opener.open(req, timeout=timeout) if timeout is not None else opener.open(req)
