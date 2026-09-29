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
import urllib.parse

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
