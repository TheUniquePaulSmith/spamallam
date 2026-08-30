"""What to do with a message when a security control could not run.

Every control here is one an attacker would like to switch off: exhaust the LLM
provider, flood rspamd, keep clamd busy. If the answer to "the scanner is
unavailable" is always "deliver anyway", then making a control unavailable IS
the bypass, and no amount of hardening elsewhere changes that. So the policy is
the admin's to choose, per control, and it is stated in the UI and in
docs/FAILURE-POLICY.md rather than buried in code.
"""
from __future__ import annotations

from typing import Any, Iterable

# Deliver, but tag the message so the failure is visible downstream.
DELIVER_TAGGED = "deliver_tagged"
# 451 to postfix: the sender's own MTA retries later. Not loss-free forever --
# main.cf's maximal_queue_lifetime returns mail to the sender after a day.
DEFER = "defer"
# Accept, store in quarantine, deliver nothing. An admin reviews and releases.
QUARANTINE = "quarantine"

VALID = (DELIVER_TAGGED, DEFER, QUARANTINE)
CONTROLS = ("ai", "rspamd", "antivirus")

# When several controls fail at once with different policies, the strictest wins.
# defer outranks quarantine because it keeps the message out of our storage as
# well as out of the mailbox, and a retry may well succeed with full scanning.
_SEVERITY = {DELIVER_TAGGED: 0, QUARANTINE: 1, DEFER: 2}


def resolve(cfg: dict[str, Any], control: str) -> str:
    """The configured policy for `control`.

    A missing/None value for "ai" inherits the legacy ai.failure_mode setting,
    resolved on read rather than by rewriting settings.yml at boot -- so an
    existing deployment keeps behaving exactly as it did, with no migration to
    run and nothing to clobber.
    """
    value = (cfg.get("failure_policy") or {}).get(control)
    if value in VALID:
        return value
    if control == "ai":
        legacy = (cfg.get("ai") or {}).get("failure_mode")
        return DEFER if legacy == "tempfail" else DELIVER_TAGGED
    return DELIVER_TAGGED


def strictest(policies: Iterable[str]) -> str:
    return max(policies, key=lambda p: _SEVERITY.get(p, 0), default=DELIVER_TAGGED)
