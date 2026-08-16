/* Reference data for the rspamd symbols table on the Test message page.
 *
 * Sourced from rspamd's own default configuration (not hand-guessed):
 *   - conf/scores.d/*.conf     (group, default weight, description)
 *   - conf/composites.conf     (derived/composite symbols)
 *   - rules/*.lua, src/plugins/lua/*.lua  (built-in Lua rule registrations)
 *   at https://github.com/rspamd/rspamd (master, fetched 2026-08-16)
 *
 * `weight` is rspamd's STOCK default — this deployment's actual score for a
 * symbol can differ if scores.d is overridden (see rspamd/ in this repo).
 * `group` is rspamd's own grouping, used here as the "module" column.
 *
 * Not exhaustive: rspamd ships hundreds of symbols across optional modules
 * (antivirus, ASN, external services, neural, etc.) not enabled by default.
 * Unlisted symbols still render in the table with a generic "no reference
 * available" note rather than being dropped.
 *
 * A few entries are marked (inferred) below where the exact upstream
 * description couldn't be located and the description is a best-effort
 * reading of the symbol name/context instead of sourced text.
 */
"use strict";

const RSPAMD_SYMBOLS = {
  // ---- this deployment's own custom scoring (rspamd/lua/rspamd.local.lua) ----
  SPAMALLAM_SPAM: { group: "spamallam", weight: null, description: "AI analysis classified message as spam (dynamic weight = AI confidence)" },
  SPAMALLAM_PHISH: { group: "spamallam", weight: null, description: "AI analysis classified message as phishing (dynamic weight = AI confidence)" },
  SPAMALLAM_MALICIOUS: { group: "spamallam", weight: null, description: "AI analysis classified message as malicious (dynamic weight = AI confidence)" },
  SPAMALLAM_HAM: { group: "spamallam", weight: null, description: "AI analysis classified message as ham (dynamic negative weight = AI confidence)" },
  SPAMALLAM_WHITELIST: { group: "spamallam", weight: 0.0, description: "Admin whitelist override — forces delivery as ham" },
  SPAMALLAM_SIG_INVALID: { group: "spamallam", weight: 1.0, description: "X-SpamAllam headers present but the HMAC signature is invalid/stale (possible spoofing)" },
  SPAMALLAM_SKIPPED: { group: "spamallam", weight: 0.0, description: "AI analysis was skipped (disabled) or errored" },

  // ---- content (PDF) ----
  PDF_ENCRYPTED: { group: "content", weight: 0.3, description: "There is an encrypted PDF in the message" },
  PDF_JAVASCRIPT: { group: "content", weight: 0.1, description: "There is a PDF with JavaScript in the message" },
  PDF_SUSPICIOUS: { group: "content", weight: 4.5, description: "There is a PDF with suspicious properties in the message" },
  PDF_LONG_TRAILER: { group: "content", weight: 0.2, description: "There is a PDF with a long trailer in the message" },
  PDF_MANY_OBJECTS: { group: "content", weight: 0.0, description: "There is a PDF with too many objects in the message" },
  PDF_TIMEOUT: { group: "content", weight: 0.0, description: "There is a PDF in the message that caused a timeout in processing" },

  // ---- fuzzy hashes (bl.rspamd.com) ----
  FUZZY_UNKNOWN: { group: "fuzzy", weight: 5.0, description: "Generic fuzzy hash match, bl.rspamd.com" },
  FUZZY_DENIED: { group: "fuzzy", weight: 12.0, description: "Denied fuzzy hash, bl.rspamd.com" },
  FUZZY_PROB: { group: "fuzzy", weight: 5.0, description: "Probable fuzzy hash, bl.rspamd.com" },
  FUZZY_WHITE: { group: "fuzzy", weight: -2.1, description: "Whitelisted fuzzy hash, bl.rspamd.com" },

  // ---- headers ----
  FORGED_SENDER: { group: "headers", weight: 0.3, description: "Sender is forged (From: header differs from the SMTP MAIL FROM: address)" },
  R_MIXED_CHARSET: { group: "headers", weight: 5.0, description: "Mixed character sets in the message" },
  R_MIXED_CHARSET_URL: { group: "headers", weight: 7.0, description: "Mixed character sets in a URL inside the message" },
  FORGED_RECIPIENTS: { group: "headers", weight: 2.0, description: "Recipients differ from the SMTP RCPT TO: addresses" },
  FORGED_RECIPIENTS_MAILLIST: { group: "headers", weight: 0.0, description: "Recipients differ from RCPT TO:, but the message is from a mailing list" },
  FORGED_SENDER_MAILLIST: { group: "headers", weight: 0.0, description: "Sender differs from MAIL FROM:, but the message is from a mailing list" },
  ONCE_RECEIVED: { group: "headers", weight: 0.1, description: "Only one Received header in the message" },
  ONCE_RECEIVED_STRICT: { group: "headers", weight: 4.0, description: "One Received header with suspicious patterns inside" },
  DIRECT_TO_MX: { group: "headers", weight: 0.0, description: "Message was delivered directly from the sending MUA to this MX" },
  MAILLIST: { group: "headers", weight: -0.2, description: "Message appears to be from a mailing list" },
  BOUNCE: { group: "headers", weight: -0.1, description: "(Non-)Delivery Status Notification" },
  FROM_HAS_DN: { group: "headers", weight: 0.0, description: "From header has a display name" },
  FROM_NEQ_ENVFROM: { group: "headers", weight: 0.0, description: "From header address differs from the envelope sender" },
  TO_EQ_FROM: { group: "headers", weight: 0.0, description: "To address matches the From address" },
  TO_DN_ALL: { group: "headers", weight: 0.0, description: "All recipients have display names" },
  RCPT_COUNT_ONE: { group: "headers", weight: 0.0, description: "Message has exactly one recipient" },
  RCVD_COUNT_THREE: { group: "headers", weight: 0.0, description: "Message has 3-5 Received headers" },
  DATE_IN_PAST: { group: "headers", weight: 1.0, description: "Message Date header is in the past (more than ~2 hours behind arrival time)" },
  DATE_IN_FUTURE: { group: "headers", weight: 4.0, description: "Message Date header is in the future" },
  MISSING_XM_UA: { group: "headers", weight: null, description: "(inferred) Message is missing both X-Mailer and User-Agent headers" },

  // ---- forwarding ----
  FORWARDED: { group: "forwarding", weight: 0.0, description: "Message shows signs of having been forwarded" },
  FWD_GOOGLE: { group: "forwarding", weight: 0.0, description: "Message was forwarded by Google (Gmail auto-forwarding)" },
  FWD_YANDEX: { group: "forwarding", weight: 0.0, description: "Message was forwarded by Yandex" },
  FWD_MAILRU: { group: "forwarding", weight: 0.0, description: "Message was forwarded by Mail.ru" },
  FWD_SRS: { group: "forwarding", weight: 0.0, description: "Message was forwarded using the Sender Rewriting Scheme (SRS)" },
  FWD_SIEVE: { group: "forwarding", weight: 0.0, description: "Message was forwarded via a Sieve mail filter rule" },
  FWD_CPANEL: { group: "forwarding", weight: 0.0, description: "Message was forwarded via cPanel's forwarding feature" },
  FORGED_SENDER_FORWARDING: { group: "composite", weight: 0.0, description: "FORGED_SENDER fired, but the message looks forwarded — its weight is removed to avoid a false positive" },
  SPF_FAIL_FORWARDING: { group: "composite", weight: 0.0, description: "SPF failed, but the message looks forwarded — the SPF-fail weight is removed to avoid a false positive" },

  // ---- SMTP envelope / connection (hfilter) ----
  HFILTER_HELO_BAREIP: { group: "hfilter", weight: 3.0, description: "HELO hostname is a bare IP address" },
  HFILTER_HELO_BADIP: { group: "hfilter", weight: 4.5, description: "HELO hostname is a very suspicious/bad IP" },
  HFILTER_HELO_1: { group: "hfilter", weight: 0.5, description: "HELO host checks (very low severity)" },
  HFILTER_HELO_2: { group: "hfilter", weight: 1.0, description: "HELO host checks (low severity)" },
  HFILTER_HELO_3: { group: "hfilter", weight: 2.0, description: "HELO host checks (medium severity)" },
  HFILTER_HELO_4: { group: "hfilter", weight: 2.5, description: "HELO host checks (hard severity)" },
  HFILTER_HELO_5: { group: "hfilter", weight: 3.0, description: "HELO host checks (very hard severity)" },
  HFILTER_HOSTNAME_1: { group: "hfilter", weight: 0.5, description: "Hostname checks (very low severity)" },
  HFILTER_HOSTNAME_2: { group: "hfilter", weight: 1.0, description: "Hostname checks (low severity)" },
  HFILTER_HOSTNAME_3: { group: "hfilter", weight: 2.0, description: "Hostname checks (medium severity)" },
  HFILTER_HOSTNAME_4: { group: "hfilter", weight: 2.5, description: "Hostname checks (hard severity)" },
  HFILTER_HOSTNAME_5: { group: "hfilter", weight: 3.0, description: "Hostname checks (very hard severity)" },
  HFILTER_HELO_NORESOLVE_MX: { group: "hfilter", weight: 0.2, description: "MX found in HELO hostname but it doesn't resolve" },
  HFILTER_HELO_NORES_A_OR_MX: { group: "hfilter", weight: 0.3, description: "HELO hostname doesn't resolve to an A or MX record" },
  HFILTER_HELO_IP_A: { group: "hfilter", weight: 1.0, description: "HELO hostname's A record IP doesn't match the connecting IP" },
  HFILTER_HELO_NOT_FQDN: { group: "hfilter", weight: 2.0, description: "HELO hostname is not a fully-qualified domain name" },
  HFILTER_FROMHOST_NORESOLVE_MX: { group: "hfilter", weight: 0.5, description: "MX found in the From: hostname but it doesn't resolve" },
  HFILTER_FROMHOST_NORES_A_OR_MX: { group: "hfilter", weight: 1.5, description: "From: hostname doesn't resolve to an A or MX record" },
  HFILTER_FROMHOST_NOT_FQDN: { group: "hfilter", weight: 3.0, description: "From: hostname is not a fully-qualified domain name" },
  HFILTER_FROM_BOUNCE: { group: "hfilter", weight: 0.0, description: "Bounce message (empty envelope sender)" },
  HFILTER_HOSTNAME_UNKNOWN: { group: "hfilter", weight: 2.5, description: "Unknown client hostname — reverse DNS (PTR) or forward-confirmed rDNS (FCrDNS) verification failed" },
  HFILTER_RCPT_BOUNCEMOREONE: { group: "hfilter", weight: 1.5, description: "Bounce message with more than one recipient" },
  HFILTER_URL_ONLY: { group: "hfilter", weight: 2.2, description: "Message body contains only a URL" },
  HFILTER_URL_ONELINE: { group: "hfilter", weight: 2.5, description: "Message body is one line containing a URL and little else" },
  RDNS_NONE: { group: "hfilter", weight: 2.0, description: "Cannot resolve reverse DNS (PTR) for the sender's IP" },
  RDNS_DNSFAIL: { group: "hfilter", weight: 0.0, description: "DNS error while verifying the PTR record" },

  // ---- MIME / attachments ----
  MIME_GOOD: { group: "mime_types", weight: -0.1, description: "Known/expected content-type" },
  MIME_BAD: { group: "mime_types", weight: 1.0, description: "Known bad/risky content-type" },
  MIME_UNKNOWN: { group: "mime_types", weight: 0.1, description: "Missing or unrecognized content-type" },
  MIME_BAD_ATTACHMENT: { group: "mime_types", weight: 4.0, description: "Invalid/disallowed attachment MIME type" },
  MIME_ENCRYPTED_ARCHIVE: { group: "mime_types", weight: 2.0, description: "Encrypted archive attached to the message" },
  MIME_OBFUSCATED_ARCHIVE: { group: "mime_types", weight: 2.0, description: "Archive contains files with clear obfuscation signs" },
  MIME_EXE_IN_GEN_SPLIT_RAR: { group: "mime_types", weight: 5.0, description: "Executable inside a RAR archive using a generic split extension (e.g. .001)" },
  MIME_ARCHIVE_IN_ARCHIVE: { group: "mime_types", weight: 5.0, description: "An archive nested inside another archive" },
  MIME_DOUBLE_BAD_EXTENSION: { group: "mime_types", weight: 3.0, description: "Attachment uses double-extension cloaking (e.g. invoice.pdf.exe); can scale up to 4.0" },
  MIME_BAD_EXTENSION: { group: "mime_types", weight: 2.0, description: "Attachment uses a risky file extension; can scale up to 4.0" },
  MIME_BAD_UNICODE: { group: "mime_types", weight: 2.0, description: "Attachment filename uses obscuring Unicode characters" },
  MIME_BASE64_TEXT: { group: "mime", weight: 0.1, description: "Message has a text part encoded as base64 (unusual for plain text)" },
  MIME_BASE64_TEXT_BOGUS: { group: "mime", weight: 1.0, description: "Base64-encoded text part that contains no 8-bit characters (no reason to be base64-encoded)" },
  MIME_TRACE: { group: "mime", weight: 0.0, description: "Internal bookkeeping symbol used by the bad-extension checks; not a scoring signal itself" },
  ZERO_FONT: { group: "html", weight: 1.0, description: "Message uses zero-sized font, typically to hide text from the reader while keeping it for filters" },
  MANY_INVISIBLE_PARTS: { group: "html", weight: 1.0, description: "Many parts of the HTML are visually hidden (display:none, etc.) — a common obfuscation/cloaking technique" },

  // ---- MUA ----
  FORGED_MUA_MAILLIST: { group: "mua", weight: 0.0, description: "Suppresses FORGED_MUA_* false positives for mailing-list mail" },

  // ---- phishing ----
  PHISHING: { group: "phishing", weight: 4.0, description: "A URL in the message matches a known phished URL" },
  PHISHED_EXCLUDED: { group: "phishing", weight: 0.0, description: "Matched phished URL is in the exclusions list" },
  PHISHED_OPENPHISH: { group: "phishing", weight: 7.0, description: "URL found in the openphish.com feed" },
  PHISHED_PHISHTANK: { group: "phishing", weight: 7.0, description: "URL found in the phishtank.com feed" },
  PHISHED_GENERIC_SERVICE: { group: "phishing", weight: 0.0, description: "Phished URL found via a generic phishing feed" },
  HACKED_WP_PHISHING: { group: "phishing", weight: 4.5, description: "Phishing message sent from a compromised WordPress instance" },
  REDIRECTOR_FALSE: { group: "phishing", weight: 0.0, description: "Exclusion for known/trusted URL redirectors" },
  URL_REDIRECTOR_NESTED: { group: "phishing", weight: 1.0, description: "URL redirector chain exceeded the nesting limit" },
  PHISHED_WHITELISTED: { group: "phishing", weight: 0.0, description: "Exclusion for known-safe phishing-list exceptions" },

  // ---- SPF ----
  R_SPF_FAIL: { group: "spf", weight: 1.0, description: "SPF verification failed — the sending IP is not authorized by the domain's SPF record" },
  R_SPF_SOFTFAIL: { group: "spf", weight: 0.0, description: "SPF policy soft-failed (~all)" },
  R_SPF_NEUTRAL: { group: "spf", weight: 0.0, description: "SPF policy is neutral (?all)" },
  R_SPF_ALLOW: { group: "spf", weight: -0.2, description: "SPF verification passed — sending IP is authorized" },
  R_SPF_DNSFAIL: { group: "spf", weight: 0.0, description: "DNS error while checking SPF" },
  R_SPF_NA: { group: "spf", weight: 0.0, description: "Domain has no SPF record" },
  R_SPF_PERMFAIL: { group: "spf", weight: 0.0, description: "SPF record is malformed, or a permanent DNS error occurred" },
  R_SPF_PLUSALL: { group: "spf", weight: 4.0, description: "SPF record uses +all, allowing any IP to send as this domain (misconfiguration)" },
  VIOLATED_DIRECT_SPF: { group: "composite", weight: 3.5, description: "No Received headers (or none from a trusted relay) AND SPF failed/soft-failed — mail claiming to be direct-from-sender but failing SPF" },
  WHITELIST_SPF: { group: "whitelist", weight: -1.0, description: "Sender is admin-whitelisted and has a valid SPF policy" },
  BLACKLIST_SPF: { group: "whitelist", weight: 1.0, description: "Sender is admin-blacklisted and has no valid SPF policy" },

  // ---- DKIM ----
  R_DKIM_REJECT: { group: "dkim", weight: 1.0, description: "DKIM signature verification failed" },
  R_DKIM_TEMPFAIL: { group: "dkim", weight: 0.0, description: "DKIM verification temporarily failed (e.g. DNS timeout)" },
  R_DKIM_PERMFAIL: { group: "dkim", weight: 0.0, description: "DKIM signature is invalid/malformed (permanent failure)" },
  R_DKIM_ALLOW: { group: "dkim", weight: -0.2, description: "DKIM signature verified successfully" },
  R_DKIM_NA: { group: "dkim", weight: 0.0, description: "Message has no DKIM signature" },
  WHITELIST_DKIM: { group: "whitelist", weight: -1.0, description: "Sender is admin-whitelisted and has a valid DKIM signature" },
  BLACKLIST_DKIM: { group: "whitelist", weight: 2.0, description: "Sender is admin-blacklisted and has an invalid DKIM signature" },
  WHITELIST_SPF_DKIM: { group: "whitelist", weight: -3.0, description: "Sender is admin-whitelisted with valid SPF and DKIM" },
  BLACKLIST_SPF_DKIM: { group: "whitelist", weight: 3.0, description: "Sender is admin-blacklisted with invalid SPF or DKIM" },

  // ---- DMARC ----
  DMARC_POLICY_ALLOW: { group: "dmarc", weight: -0.5, description: "DMARC policy allows delivery (aligned SPF/DKIM)" },
  DMARC_POLICY_ALLOW_WITH_FAILURES: { group: "dmarc", weight: -0.5, description: "DMARC allows delivery despite an SPF/DKIM failure elsewhere" },
  DMARC_POLICY_REJECT: { group: "dmarc", weight: 2.0, description: "Message fails DMARC and the domain's policy is p=reject" },
  DMARC_POLICY_QUARANTINE: { group: "dmarc", weight: 1.5, description: "Message fails DMARC and the domain's policy is p=quarantine" },
  DMARC_POLICY_SOFTFAIL: { group: "dmarc", weight: 0.1, description: "Message fails DMARC alignment" },
  DMARC_NA: { group: "dmarc", weight: 0.0, description: "Domain publishes no DMARC record" },
  WHITELIST_DMARC: { group: "whitelist", weight: -7.0, description: "Sender is admin-whitelisted with valid DMARC, SPF, and DKIM" },
  BLACKLIST_DMARC: { group: "whitelist", weight: 6.0, description: "Sender is admin-blacklisted and fails DMARC and DKIM" },

  // ---- ARC ----
  ARC_ALLOW: { group: "arc", weight: -1.0, description: "ARC chain validated successfully (message was legitimately forwarded through an ARC-aware relay)" },
  ARC_REJECT: { group: "arc", weight: 1.0, description: "ARC chain validation failed" },
  ARC_INVALID: { group: "arc", weight: 0.5, description: "ARC chain structure is invalid" },
  ARC_DNSFAIL: { group: "arc", weight: 0.0, description: "DNS error while validating the ARC chain" },
  ARC_NA: { group: "arc", weight: 0.0, description: "No ARC signature present" },

  // ---- IP DNS blocklists / RBL (dnswl.org) ----
  DNSWL_BLOCKED: { group: "rbl", weight: 0.0, description: "dnswl.org: this resolver has been blocked for excessive queries — result not usable" },
  RCVD_IN_DNSWL: { group: "rbl", weight: 0.0, description: "Unrecognized result from dnswl.org" },
  RCVD_IN_DNSWL_NONE: { group: "rbl", weight: 0.0, description: "Sender IP is listed at dnswl.org, but with no trust level assigned" },
  RCVD_IN_DNSWL_LOW: { group: "rbl", weight: -0.1, description: "Sender IP is listed at dnswl.org with low trust" },
  RCVD_IN_DNSWL_MED: { group: "rbl", weight: -0.2, description: "Sender IP is listed at dnswl.org with medium trust" },
  RCVD_IN_DNSWL_HI: { group: "rbl", weight: -0.5, description: "Sender IP is listed at dnswl.org with high trust" },
  DWL_DNSWL_BLOCKED: { group: "rbl", weight: 0.0, description: "dnswl.org (domain list): this resolver has been blocked for excessive queries" },
  DWL_DNSWL: { group: "rbl", weight: 0.0, description: "Unrecognized result from dnswl.org's domain list" },
  DWL_DNSWL_NONE: { group: "rbl", weight: 0.0, description: "Valid DKIM signature from a domain listed at dnswl.org, no trust level" },
  DWL_DNSWL_LOW: { group: "rbl", weight: -1.0, description: "Valid DKIM signature from a domain listed at dnswl.org, low trust" },
  DWL_DNSWL_MED: { group: "rbl", weight: -2.0, description: "Valid DKIM signature from a domain listed at dnswl.org, medium trust" },
  DWL_DNSWL_HI: { group: "rbl", weight: -3.5, description: "Valid DKIM signature from a domain listed at dnswl.org, high trust" },

  // ---- Spamhaus ZEN (rbl group) ----
  RBL_SPAMHAUS: { group: "rbl", weight: 0.0, description: "Unrecognized result from Spamhaus ZEN" },
  RBL_SPAMHAUS_SBL: { group: "rbl", weight: 4.0, description: "Sender IP listed in Spamhaus SBL (spam operations)" },
  RBL_SPAMHAUS_CSS: { group: "rbl", weight: 2.0, description: "Sender IP listed in Spamhaus CSS (compromised/snowshoe)" },
  RBL_SPAMHAUS_XBL: { group: "rbl", weight: 4.0, description: "Sender IP listed in Spamhaus XBL (exploited/infected hosts)" },
  RBL_SPAMHAUS_PBL: { group: "rbl", weight: 2.0, description: "Sender IP listed in Spamhaus PBL (policy block list — should not be sending mail directly)" },
  RBL_SPAMHAUS_DROP: { group: "rbl", weight: 7.0, description: "Sender IP listed in Spamhaus DROP (hijacked/criminal netblocks)" },
  RBL_SPAMHAUS_BLOCKED_OPENRESOLVER: { group: "rbl", weight: 0.0, description: "Spamhaus query blocked — you are querying from an open DNS resolver" },
  RBL_SPAMHAUS_BLOCKED: { group: "rbl", weight: 0.0, description: "Spamhaus query blocked — query volume limit exceeded" },
  RECEIVED_SPAMHAUS_SBL: { group: "rbl", weight: 3.0, description: "A Received-header IP is listed in Spamhaus SBL" },
  RECEIVED_SPAMHAUS_CSS: { group: "rbl", weight: 1.0, description: "A Received-header IP is listed in Spamhaus CSS" },
  RECEIVED_SPAMHAUS_XBL: { group: "rbl", weight: 1.0, description: "A Received-header IP is listed in Spamhaus XBL" },
  RECEIVED_SPAMHAUS_PBL: { group: "rbl", weight: 0.0, description: "A Received-header IP is listed in Spamhaus PBL" },
  RECEIVED_SPAMHAUS_DROP: { group: "rbl", weight: 6.0, description: "A Received-header IP is listed in Spamhaus DROP" },
  RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER: { group: "rbl", weight: 0.0, description: "Spamhaus query blocked — querying from an open DNS resolver" },
  RECEIVED_SPAMHAUS_BLOCKED: { group: "rbl", weight: 0.0, description: "Spamhaus query blocked — query volume limit exceeded" },

  // ---- SenderScore ----
  RBL_SENDERSCORE_UNKNOWN: { group: "rbl", weight: 0.0, description: "Unrecognized result from SenderScore RPBL" },
  RBL_SENDERSCORE_BOT: { group: "rbl", weight: 2.0, description: "Sender IP listed in SenderScore RPBL as botnet" },
  RBL_SENDERSCORE_NA: { group: "rbl", weight: 0.0, description: "Sender IP listed in SenderScore RPBL as unauthenticated" },
  RBL_SENDERSCORE_NA_BOT: { group: "rbl", weight: 1.0, description: "Sender IP listed in SenderScore RPBL as unauthenticated + botnet" },
  RBL_SENDERSCORE_PRST: { group: "rbl", weight: 2.0, description: "Sender IP listed in SenderScore RPBL as pristine (never seen before)" },
  RBL_SENDERSCORE_PRST_BOT: { group: "rbl", weight: 3.0, description: "Sender IP listed in SenderScore RPBL as pristine + botnet" },
  RBL_SENDERSCORE_PRST_NA: { group: "rbl", weight: 2.0, description: "Sender IP listed in SenderScore RPBL as pristine + unauthenticated" },
  RBL_SENDERSCORE_PRST_NA_BOT: { group: "rbl", weight: 3.0, description: "Sender IP listed in SenderScore RPBL as pristine + unauthenticated + botnet" },
  RBL_SENDERSCORE_SUS_ATT: { group: "rbl", weight: 1.0, description: "Sender IP listed in SenderScore RPBL as sending suspect attachments" },
  RBL_SENDERSCORE_SUS_ATT_NA: { group: "rbl", weight: 1.0, description: "SenderScore: suspect attachments + unauthenticated" },
  RBL_SENDERSCORE_SUS_ATT_NA_BOT: { group: "rbl", weight: 1.5, description: "SenderScore: suspect attachments + unauthenticated + botnet" },
  RBL_SENDERSCORE_SUS_ATT_PRST_NA: { group: "rbl", weight: 3.0, description: "SenderScore: suspect attachments + pristine + unauthenticated" },
  RBL_SENDERSCORE_SUS_ATT_PRST_NA_BOT: { group: "rbl", weight: 3.5, description: "SenderScore: suspect attachments + pristine + unauthenticated + botnet" },
  RBL_SENDERSCORE_SCORE: { group: "rbl", weight: 2.0, description: "Sender IP flagged by SenderScore's sender_score signal" },
  RBL_SENDERSCORE_SCORE_NA: { group: "rbl", weight: 2.0, description: "SenderScore: sender_score + unauthenticated" },
  RBL_SENDERSCORE_SCORE_PRST: { group: "rbl", weight: 4.0, description: "SenderScore: sender_score + pristine" },
  RBL_SENDERSCORE_SCORE_PRST_NA: { group: "rbl", weight: 4.0, description: "SenderScore: sender_score + pristine + unauthenticated" },
  RBL_SENDERSCORE_SCORE_SUS_ATT_NA: { group: "rbl", weight: 3.0, description: "SenderScore: sender_score + suspect attachments + unauthenticated" },
  RBL_SENDERSCORE_BLOCKED: { group: "rbl", weight: 0.0, description: "SenderScore query blocked — query volume limit exceeded" },
  RBL_SENDERSCORE_REPUT_UNKNOWN: { group: "rbl", weight: 0.0, description: "Unrecognized result from SenderScore's Reputation list" },
  RBL_SENDERSCORE_REPUT_0: { group: "rbl", weight: 4.0, description: "SenderScore reputation: very bad (0-9)" },
  RBL_SENDERSCORE_REPUT_1: { group: "rbl", weight: 3.5, description: "SenderScore reputation: bad (10-19)" },
  RBL_SENDERSCORE_REPUT_2: { group: "rbl", weight: 3.0, description: "SenderScore reputation: bad (20-29)" },
  RBL_SENDERSCORE_REPUT_3: { group: "rbl", weight: 2.5, description: "SenderScore reputation: bad (30-39)" },
  RBL_SENDERSCORE_REPUT_4: { group: "rbl", weight: 2.0, description: "SenderScore reputation: bad (40-49)" },
  RBL_SENDERSCORE_REPUT_5: { group: "rbl", weight: 1.5, description: "SenderScore reputation: bad (50-59)" },
  RBL_SENDERSCORE_REPUT_6: { group: "rbl", weight: 1.0, description: "SenderScore reputation: bad (60-69)" },
  RBL_SENDERSCORE_REPUT_7: { group: "rbl", weight: 0.5, description: "SenderScore reputation: bad (70-79)" },
  RBL_SENDERSCORE_REPUT_8: { group: "rbl", weight: 0.0, description: "SenderScore reputation: neutral (80-89)" },
  RBL_SENDERSCORE_REPUT_9: { group: "rbl", weight: -1.0, description: "SenderScore reputation: good (90-100)" },
  RBL_SENDERSCORE_REPUT_BLOCKED: { group: "rbl", weight: 0.0, description: "SenderScore query blocked — query volume limit exceeded" },

  // ---- Mailspike / other RBLs ----
  MAILSPIKE: { group: "rbl", weight: 0.0, description: "Unrecognized result from Mailspike" },
  RWL_MAILSPIKE_NEUTRAL: { group: "rbl", weight: 0.0, description: "Neutral result from Mailspike" },
  RBL_MAILSPIKE_WORST: { group: "rbl", weight: 2.0, description: "Sender IP listed in Mailspike RBL — worst reputation tier" },
  RBL_MAILSPIKE_VERYBAD: { group: "rbl", weight: 1.5, description: "Sender IP listed in Mailspike RBL — very bad reputation" },
  RBL_MAILSPIKE_BAD: { group: "rbl", weight: 1.0, description: "Sender IP listed in Mailspike RBL — bad reputation" },
  RWL_MAILSPIKE_POSSIBLE: { group: "rbl", weight: 0.0, description: "Sender IP listed in Mailspike RWL — possibly legitimate" },
  RWL_MAILSPIKE_GOOD: { group: "rbl", weight: -0.1, description: "Sender IP listed in Mailspike RWL — good reputation" },
  RWL_MAILSPIKE_VERYGOOD: { group: "rbl", weight: -0.2, description: "Sender IP listed in Mailspike RWL — very good reputation" },
  RWL_MAILSPIKE_EXCELLENT: { group: "rbl", weight: -0.4, description: "Sender IP listed in Mailspike RWL — excellent reputation" },
  RBL_SEM: { group: "rbl", weight: 1.0, description: "Sender IP listed in Spameatingmonkey RBL" },
  RBL_SEM_IPV6: { group: "rbl", weight: 1.0, description: "Sender IP listed in Spameatingmonkey RBL (IPv6)" },
  RBL_VIRUSFREE_BOTNET: { group: "rbl", weight: 2.0, description: "Sender IP listed in virusfree.cz botnet list" },
  RBL_BLOCKLISTDE: { group: "rbl", weight: 4.0, description: "Sender IP listed at blocklist.de" },
  RECEIVED_BLOCKLISTDE: { group: "rbl", weight: 3.0, description: "A Received-header IP is listed at blocklist.de" },

  // ---- Bayes / statistics ----
  BAYES_SPAM: { group: "statistics", weight: 5.1, description: "Bayesian classifier thinks this message is probably spam (weight scales with the learned probability)" },
  BAYES_HAM: { group: "statistics", weight: -3.0, description: "Bayesian classifier thinks this message is probably ham (weight scales with the learned probability)" },

  // ---- greylisting ----
  GREYLIST: { group: "greylist", weight: 0.0, description: "Message was greylisted — temporarily deferred so a legitimate sender's retry can be verified" },

  // ---- SURBL / URIBL (URL-based DNS lists) ----
  SURBL_BLOCKED: { group: "surbl", weight: 0.0, description: "SURBL query blocked — policy/overusage limit exceeded" },
  PH_SURBL_MULTI: { group: "surbl", weight: 7.5, description: "A URL's domain is listed in SURBL as phishing" },
  MW_SURBL_MULTI: { group: "surbl", weight: 7.5, description: "A URL's domain is listed in SURBL as malware" },
  ABUSE_SURBL: { group: "surbl", weight: 5.0, description: "A URL's domain is listed in SURBL as abused" },
  CRACKED_SURBL: { group: "surbl", weight: 5.0, description: "A URL's domain is listed in SURBL as a cracked/compromised site" },
  CT_SURBL: { group: "surbl", weight: 0.0, description: "A URL's domain is listed in SURBL as a click tracker" },
  DM_SURBL: { group: "surbl", weight: 0.0, description: "A URL's domain is listed in SURBL as a disposable-email service" },
  RSPAMD_URIBL: { group: "surbl", weight: 4.5, description: "A URL's domain is listed in rspamd's own URIBL (bl.rspamd.com)" },
  RSPAMD_EMAILBL: { group: "surbl", weight: 2.5, description: "A message address is listed in rspamd's own email blocklist (bl.rspamd.com)" },
  MSBL_EBL: { group: "surbl", weight: 7.5, description: "A message address is listed in MSBL's email blocklist (msbl.org)" },
  MSBL_EBL_GREY: { group: "surbl", weight: 0.5, description: "A message address is on MSBL's email greylist" },
  SEM_URIBL_UNKNOWN: { group: "surbl", weight: 0.0, description: "Unrecognized result from Spameatingmonkey URIBL" },
  SEM_URIBL: { group: "surbl", weight: 3.5, description: "A URL's domain is listed in Spameatingmonkey URIBL" },
  SEM_URIBL_FRESH15_UNKNOWN: { group: "surbl", weight: 0.0, description: "Unrecognized result from Spameatingmonkey Fresh15 URIBL" },
  SEM_URIBL_FRESH15: { group: "surbl", weight: 3.0, description: "A URL's domain was registered in the last 15 days (Spameatingmonkey Fresh15)" },
  DBL: { group: "surbl", weight: 0.0, description: "Unrecognized result from Spamhaus DBL" },
  DBL_SPAM: { group: "surbl", weight: 6.5, description: "A URL's domain is listed in Spamhaus DBL as spam" },
  DBL_PHISH: { group: "surbl", weight: 7.5, description: "A URL's domain is listed in Spamhaus DBL as phishing" },
  DBL_MALWARE: { group: "surbl", weight: 7.5, description: "A URL's domain is listed in Spamhaus DBL as malware" },
  DBL_BOTNET: { group: "surbl", weight: 7.5, description: "A URL's domain is listed in Spamhaus DBL as botnet C&C" },
  DBL_ABUSE: { group: "surbl", weight: 5.0, description: "A URL's domain is listed in Spamhaus DBL as abused legitimate infrastructure (spam)" },
  DBL_ABUSE_REDIR: { group: "surbl", weight: 5.0, description: "A URL's domain is listed in Spamhaus DBL as an abused redirector" },
  DBL_ABUSE_PHISH: { group: "surbl", weight: 6.5, description: "A URL's domain is listed in Spamhaus DBL as abused legitimate infrastructure (phishing)" },
  DBL_ABUSE_MALWARE: { group: "surbl", weight: 6.5, description: "A URL's domain is listed in Spamhaus DBL as abused legitimate infrastructure (malware)" },
  DBL_ABUSE_BOTNET: { group: "surbl", weight: 6.5, description: "A URL's domain is listed in Spamhaus DBL as abused legitimate infrastructure (botnet C&C)" },
  DBL_PROHIBIT: { group: "surbl", weight: 0.0, description: "Spamhaus DBL: IP-based queries are prohibited" },
  DBL_BLOCKED_OPENRESOLVER: { group: "surbl", weight: 0.0, description: "Spamhaus DBL query blocked — querying from an open DNS resolver" },
  DBL_BLOCKED: { group: "surbl", weight: 0.0, description: "Spamhaus DBL query blocked — query volume limit exceeded" },
  URIBL_MULTI: { group: "surbl", weight: 0.0, description: "Unrecognized result from URIBL.com" },
  URIBL_BLOCKED: { group: "surbl", weight: 0.0, description: "URIBL.com query refused — likely policy/overusage" },
  URIBL_BLACK: { group: "surbl", weight: 7.5, description: "A URL's domain is on URIBL.com's black list" },
  URIBL_RED: { group: "surbl", weight: 0.5, description: "A URL's domain is on URIBL.com's red list" },
  URIBL_GREY: { group: "surbl", weight: 2.5, description: "A URL's domain is on URIBL.com's grey list" },
  SPAMHAUS_ZEN_URIBL: { group: "surbl", weight: 0.0, description: "Unrecognized result from Spamhaus ZEN URIBL" },
  URIBL_SBL: { group: "surbl", weight: 6.5, description: "A URL's domain resolves to an IP listed in Spamhaus SBL" },
  URIBL_SBL_CSS: { group: "surbl", weight: 5.0, description: "A URL's domain resolves to an IP listed in Spamhaus CSS" },
  URIBL_XBL: { group: "surbl", weight: 3.0, description: "A URL's domain resolves to an IP listed in Spamhaus XBL" },
  URIBL_PBL: { group: "surbl", weight: 0.01, description: "A URL's domain resolves to an IP listed in Spamhaus PBL" },
  URIBL_DROP: { group: "surbl", weight: 5.0, description: "A URL's domain resolves to an IP listed in Spamhaus DROP" },

  // ---- suspicious URL structure ----
  URL_USER_PASSWORD: { group: "url_suspect", weight: 2.0, description: "URL contains a user/password field (e.g. http://user:pass@host)" },
  URL_USER_LONG: { group: "url_suspect", weight: 3.0, description: "URL's user field is unusually long (>128 chars)" },
  URL_USER_VERY_LONG: { group: "url_suspect", weight: 5.0, description: "URL's user field is very long (>256 chars) — often used to disguise the real host" },
  URL_NUMERIC_IP: { group: "url_suspect", weight: 1.5, description: "URL uses a raw numeric IP address instead of a hostname" },
  URL_NUMERIC_IP_USER: { group: "url_suspect", weight: 4.0, description: "URL uses a numeric IP combined with a user field (common phishing disguise)" },
  URL_NUMERIC_PRIVATE_IP: { group: "url_suspect", weight: 0.5, description: "URL points at a private/internal IP range" },
  URL_NO_TLD: { group: "url_suspect", weight: 2.0, description: "URL's hostname has no top-level domain" },
  URL_SUSPICIOUS_TLD: { group: "url_suspect", weight: 3.0, description: "URL uses a TLD commonly abused for spam/phishing" },
  URL_BAD_UNICODE: { group: "url_suspect", weight: 3.0, description: "URL contains invalid/malformed Unicode" },
  URL_HOMOGRAPH_ATTACK: { group: "url_suspect", weight: 5.0, description: "URL mixes character scripts to visually impersonate another domain (homograph/IDN attack)" },
  URL_RTL_OVERRIDE: { group: "url_suspect", weight: 6.0, description: "URL uses a right-to-left override character to disguise its real extension/host" },
  URL_ZERO_WIDTH_SPACES: { group: "url_suspect", weight: 7.0, description: "URL contains zero-width space characters (obfuscation)" },
  URL_MULTIPLE_AT_SIGNS: { group: "url_suspect", weight: 3.0, description: "URL contains multiple @ signs (classic \"fake host before the real one\" trick)" },
  URL_BACKSLASH_PATH: { group: "url_suspect", weight: 2.0, description: "URL uses backslashes in its path (browser-parsing quirk abuse)" },
  URL_EXCESSIVE_DOTS: { group: "url_suspect", weight: 2.0, description: "URL hostname has an excessive number of dots/subdomains" },
  URL_VERY_LONG: { group: "url_suspect", weight: 1.5, description: "URL is unusually long" },
  URL_QUERY_MULTIPLE_URLS: { group: "url_suspect", weight: 2.0, description: "URL's query string embeds another full URL (open-redirect style)" },
  URI_COUNT_ODD: { group: "url", weight: 1.0, description: "multipart/alternative message has an odd number of URLs across its parts — a sign the HTML and text parts were generated independently (as spam tools often do)" },
};
