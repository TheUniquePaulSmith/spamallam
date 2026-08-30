# Failure policy

What happens to a message when a security control **cannot run**. Configured per
control at **Settings → Failure policy** (`/settings/failure`).

## Why this is a security setting, not an availability setting

An attacker who cannot get past the filters has a second option: make the
filters unavailable. Expensive messages, floods of concurrent mail, malformed
content that is slow to parse, provider throttling, a wedged clamd.

If the answer to "the scanner is unavailable" is always "deliver anyway", then
**making a control unavailable is the bypass** — and it is a much easier attack
than defeating the control itself. That is why this is a deliberate choice
rather than a hardcoded default, and why the UI states what an attacker gains
from each option.

The counter-pressure is real too: a mail gateway that refuses mail during an
outage is its own kind of failure. There is no universally right answer here,
which is exactly why it is yours to make.

## The three policies

| Policy | Sender sees | Recipient sees | Attacker gains | Costs you |
|---|---|---|---|---|
| **Deliver, tagged** | `250` accepted | The message, plus `X-SpamAllam-Control-Failure` | **Unfiltered delivery.** Take the control down, mail flows unscanned. | Nothing operationally. |
| **Quarantine** | `250` accepted | Nothing until an admin releases it | Nothing directly. Can flood your quarantine to bury a real message. | Someone must work the backlog; storage grows. |
| **Defer (451)** | `451`, their MTA retries | Nothing until controls recover | Nothing directly. A sustained outage becomes a mail-delivery denial of service. | Delayed mail, and see the loss note below. |

> **Defer is not loss-free forever.** postfix returns mail to the sender after
> `maximal_queue_lifetime` (1 day) and starts warning at `bounce_queue_lifetime`
> (1 hour) — see `postfix/templates/main.cf.tmpl`. Many senders give up sooner.
> A defer that outlasts those windows is a bounce, not a delay.

When several controls fail at once with different policies, **the strictest
wins**: `defer` > `quarantine` > `deliver_tagged`. Defer outranks quarantine
because it keeps the message out of your storage as well as out of the mailbox,
and a retry may succeed with full scanning.

## The controls

### AI analysis unavailable
The LLM provider errored, timed out, or the tool loop did not converge. Only
counted when AI analysis is enabled. rspamd's own scoring still ran.

### rspamd unavailable
rspamd could not be reached. **This also means the antivirus behind it did not
run**, so both `rspamd` and `antivirus` are counted as failed — one root cause,
reported honestly as two controls that did not execute.

### Antivirus scan failed
rspamd answered, but ClamAV reported it could not scan (`CLAM_VIRUS_FAIL`).

This one is worth dwelling on. A failed antivirus scan scores **0.0** — exactly
like a clean one. It changes neither the score nor the action, so before this
setting existed a clamd outage meant malware was delivered and *nothing anywhere
recorded that nothing had been scanned*. It was the quietest failure in the
stack.

**Known gap:** rspamd emits no "scanned clean" symbol. So "scanned, and clean"
and "the antivirus module was never in the path at all" are indistinguishable
from the outside. This detects scanner **errors**, not scanner **absence** — if
you misconfigure the antivirus module out of the pipeline, nothing here notices.
Verify the module is live after any rspamd config change:

```bash
docker compose stop clamav
```

then send a test message and confirm `CLAM_VIRUS_FAIL` appears in the trace at
`/logs`. Start clamav again afterwards.

### Every control unavailable
Applied when nothing inspected the message at all. It can only make the outcome
**stricter** than the per-control settings, never weaker — so setting
`rspamd: defer` still defers even when rspamd happens to be the last control
standing.

It defaults to `deliver_tagged` purely to preserve behaviour on upgrade.
**`defer` is the right value for most deployments**: this is the one state in
which a message reaches a mailbox with zero inspection of any kind.

## What is not covered

- **Whitelisted mail is exempt.** A whitelist hit already means "deliver
  regardless", consistent with how it suppresses the AI drop and the rspamd
  reject. Note that a sender-domain whitelist now requires DMARC/SPF
  authentication before it is honoured (Settings → Overrides), so this is no
  longer a lever an arbitrary sender can pull.
- **Detections beat failures.** If the message was going to be dropped anyway
  (high-confidence AI verdict, or an rspamd reject), that happens first and no
  failure policy is consulted.
- **The header is not signed.** `X-SpamAllam-Control-Failure` is informational,
  deliberately outside the HMAC canonical string — the same treatment as
  `X-SpamAllam-Labels`. Downstream rules may file on it; nothing may trust it.

## Upgrading

Existing deployments keep their current behaviour with no migration. The legacy
`ai.failure_mode` setting is still read as the fallback for the AI control
(`tempfail` → defer, `fail_open` → deliver tagged) until you save the new page
once. rspamd and antivirus default to `deliver_tagged`, which is what the code
did unconditionally before.
