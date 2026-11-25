"""How many wrong guesses a sign-in will take before it stops listening.

WHY THIS EXISTS
    Nothing limited them. A wrong password, a wrong authenticator code and a
    reset request were each answered as fast as they arrived, for ever -- so a
    password learned anywhere was one script away from the six-digit code
    behind it: three codes are valid at any moment (the clock skew either
    side), which is about 330,000 tries on average, an hour or so against a
    portal that answers in milliseconds. In a product that holds other
    people's kubeconfigs, git tokens and brokered root credentials, the second
    factor has to be a factor.

WHAT IS COUNTED, AND AGAINST WHAT
    Failures only; a success clears its own account's count. Each check names
    several keys and refuses when ANY is over its limit:

      * the account and the address together -- the ordinary case, a person
        mistyping, or one machine guessing one account;
      * the account alone, higher -- the same account guessed from many
        addresses, which a per-address limit cannot see;
      * the address alone, higher still -- one machine trying many accounts.

    The account key is the email as SUBMITTED, so an address with no account
    behind it is limited exactly like one that has, and the answer says the
    same either way: a different refusal for a real account would turn this
    into a way to find out who has one.

    Refused means refused: while a key is over its limit the right password
    and the right code are turned away too, or the limit would only slow down
    the wrong guesses.

THE TRADE, STATED
    Somebody who knows an address can keep its owner out for the window by
    guessing wrong from many machines. That is the cost of a limit on the
    account at all, it ends by itself, it is audited, and an administrator
    is never stuck behind it for longer than the window. The alternative --
    no account limit -- is the hour-long brute force above.

    The counts live in this process. A restart forgets them, which costs an
    attacker a restart they cannot cause from outside; the chart runs one
    replica, so there is no second process to keep in step.
"""
from __future__ import annotations

import threading
import time

WINDOW = 15 * 60          # seconds a failure counts for

# name -> how many failures a key of that kind may collect inside WINDOW
LIMITS = {
    "login": 5,           # (account, address)
    "login_account": 20,  # account, from anywhere
    "login_ip": 50,       # address, any account
    "mfa": 5,             # the account's second factor
    "mfa_ip": 50,
    "reset": 3,           # reset links asked for one address
    "reset_ip": 10,
}

# Bounded, because the keys come from strangers: every distinct email a script
# invents is a key. Past this many the oldest are dropped, which can only ever
# forget a count early -- never block somebody who did nothing.
MAX_KEYS = 20000

_lock = threading.Lock()
_fails: dict[tuple[str, str], list[float]] = {}


def _live(key: tuple[str, str], now: float) -> list[float]:
    stamps = [t for t in _fails.get(key, ()) if now - t < WINDOW]
    if stamps:
        _fails[key] = stamps
    else:
        _fails.pop(key, None)
    return stamps


def wait(*keys: tuple[str, str]) -> int:
    """Seconds until every key named is under its limit again; 0 = go ahead."""
    now = time.time()
    longest = 0
    with _lock:
        for kind, who in keys:
            if not who:
                continue
            stamps = _live((kind, who), now)
            if len(stamps) >= LIMITS[kind]:
                # the oldest failure that still counts is the one that leaves
                longest = max(longest, int(WINDOW - (now - stamps[0])) + 1)
    return longest


def fail(*keys: tuple[str, str]) -> None:
    now = time.time()
    with _lock:
        if len(_fails) >= MAX_KEYS:
            for k in sorted(_fails, key=lambda k: _fails[k][-1])[:MAX_KEYS // 10]:
                _fails.pop(k, None)
        for kind, who in keys:
            if who:
                _live((kind, who), now)
                _fails.setdefault((kind, who), []).append(now)


def clear(*keys: tuple[str, str]) -> None:
    with _lock:
        for k in keys:
            _fails.pop(k, None)


def words(seconds: int) -> str:
    minutes = max(1, (seconds + 59) // 60)
    return f"{minutes} minute" + ("s" if minutes != 1 else "")


def reset() -> None:
    """Forget every count -- for tests."""
    with _lock:
        _fails.clear()
