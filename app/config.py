"""Display helpers only — nothing here knows about any particular organisation.

How a team names its environments and services is that team's configuration, so
it lives in the project's settings, never as a rule in this file. See store.py:
env_aliases, hidden_services, hidden_key_prefixes, strip_suffixes.
"""
import re

# Unicode composes every national flag from two regional-indicator letters, so
# an ISO 3166-1 alpha-2 code converts arithmetically. A hand-written country
# list would be both incomplete and biased toward wherever the author works.
_REGIONAL_INDICATOR_A = 0x1F1E6
_ASCII_A = ord("A")


def flag_for(name: str, explicit: str = "") -> str:
    """Flag for a region.

    An explicitly configured flag always wins. Otherwise a two-letter name is
    read as a country code and converted. Longer names ("Kenya", "UAE") are not
    guessed — that would need a country database — so they get a globe, and the
    region's optional flag field exists to override it.
    """
    if explicit:
        return explicit
    code = re.sub(r"[^A-Za-z]", "", name or "").upper()
    if len(code) != 2:
        return "🌐"
    return "".join(chr(_REGIONAL_INDICATOR_A + ord(ch) - _ASCII_A) for ch in code)


def resolve_env(env: str, aliases=None) -> str:
    """Display name for an environment folder.

    Teams name these folders however they like, and some name production
    something else entirely. That mapping is per-project configuration
    (env_aliases), not a rule here.
    """
    return (aliases or {}).get(env, env) or env


def is_prod_env(env: str, aliases=None) -> bool:
    return resolve_env(env, aliases).strip().lower() in ("prod", "production")


# Generic software-lifecycle vocabulary, not any one team's naming — and only
# used to pick a decorative icon. An unrecognised name gets the default.
# The values name a line icon in app/logodata.py rather than an emoji: an emoji
# is drawn by whichever font the reader's machine happens to have, which is why
# the same page looked different on every desktop and cheap on most of them.
_ENV_ICONS = (
    (("prod", "production", "live"), "rocket"),
    (("preprod", "pre-prod", "staging", "stage", "uat"), "flask-conical"),
    (("dr", "failover"), "life-buoy"),
    (("test", "qa", "sit"), "test-tube"),
)


def env_glyph(env: str, aliases=None) -> str:
    e = resolve_env(env, aliases).strip().lower()
    for names, icon in _ENV_ICONS:              # whole name first, so
        if e in names:                          # "pre-prod" is not read as "prod"
            return icon
    # then whole words only. Substring matching looked reasonable until
    # "landing-site" matched "sit" and came out as a test environment.
    words = {w for w in re.split(r"[^a-z0-9]+", e) if w}
    for names, icon in _ENV_ICONS:
        if words & set(names):
            return icon
    return "wrench"
