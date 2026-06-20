```
 ███████╗████████╗██████╗ ██╗   ██╗██╗  ██╗███████╗
 ██╔════╝╚══██╔══╝██╔══██╗╚██╗ ██╔╝██║ ██╔╝██╔════╝
 ███████╗   ██║   ██████╔╝ ╚████╔╝ █████╔╝ █████╗
 ╚════██║   ██║   ██╔══██╗  ╚██╔╝  ██╔═██╗ ██╔══╝
 ███████║   ██║   ██║  ██║   ██║   ██║  ██╗███████╗
 ╚══════╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝
                   [ e m a i l ]
```

[![CI](https://github.com/MenkeTechnologies/stryke-email/actions/workflows/ci.yml/badge.svg)](https://github.com/MenkeTechnologies/stryke-email/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![stryke](https://img.shields.io/badge/stryke-package-cyan.svg)](https://github.com/MenkeTechnologies/strykelang)

### `[EMAIL + CAMPAIGN CLIENT FOR STRYKE // SMTP SEND + MASS MAILING + TEMPLATES + UNSUBSCRIBE + SUPPRESSION]`

> *"Send the newsletter, not the spam — through your own SMTP, with the unsubscribe baked in."*

Transactional and campaign email for stryke. Single send, personalized mass
mailing, `{{merge}}` templates, List-Unsubscribe headers, suppression lists,
and rate limiting — all over **your own authenticated SMTP** (`lettre`, rustls,
no tokio). Opt-in package tier.

### [`strykelang`](https://github.com/MenkeTechnologies/strykelang) &middot; [`MenkeTechnologiesMeta`](https://github.com/MenkeTechnologies/MenkeTechnologiesMeta) · [`stryke-mongo`](https://github.com/MenkeTechnologies/stryke-mongo) · [`stryke-redis`](https://github.com/MenkeTechnologies/stryke-redis)

---

## Table of Contents

- [\[0x00\] Install](#0x00-install)
- [\[0x01\] Send one message](#0x01-send-one-message)
- [\[0x02\] Mass mailing](#0x02-mass-mailing)
- [\[0x03\] Connecting](#0x03-connecting)
- [\[0x04\] Compliance](#0x04-compliance)
- [\[0x05\] API reference](#0x05-api-reference)
- [\[0x06\] Build & test](#0x06-build--test)
- [\[0x07\] License](#0x07-license)

---

## \[0x00\] Install

```sh
s add github.com/MenkeTechnologies/stryke-email
```

On first `use Email`, stryke dlopens the cdylib in-process and registers every
`email__*` export. A pooled `SmtpTransport` is cached per `(host, port, tls,
user)` for the life of the process.

---

## \[0x01\] Send one message

```perl
use Email

var %conn = ( host => "smtp.example.com", username => "me", password => $ENV{SMTP_PASS} )

Email::send(
    {
        from    => "Me <me@example.com>",
        to      => "customer@example.com",
        subject => "Your license key",
        text    => "Thanks for your purchase. Key: ABC-123",
        html    => "<p>Thanks for your purchase. Key: <code>ABC-123</code></p>",
    },
    %conn,
)
```

---

## \[0x02\] Mass mailing

Personalized, suppression-aware, rate-limited, with the unsubscribe header
injected automatically:

```perl
val $res = Email::send_bulk(
    { subject => "Hi {{name}}, {{product}} v2 is out",
      html    => "<p>Hi {{name}}, your {{product}} update is ready.</p>" },
    [
        { email => "ada@example.com",  name => "Ada",  vars => { product => "Audio-Haxor" } },
        { email => "alan@example.com", name => "Alan", vars => { product => "traderview" } },
    ],
    from             => "Me <me@example.com>",
    suppression      => Email::suppress_filter([], $unsub_list)->{removed},  # your opt-outs
    rate             => { per_minute => 120 },
    list_unsubscribe => { url => "https://example.com/u?e={{email}}", mailto => "unsub@example.com" },
    %conn,
)

p $res->{sent}      # 2
p $res->{failed}    # 0
p $res->{results}   # [ { email, ok, error? }, ... ]
```

Each recipient's template is merged with their `vars` (plus `email`/`name`), the
`list_unsubscribe` URL can itself use `{{email}}` for a per-recipient link, and
sends are throttled by `rate`.

---

## \[0x03\] Connecting

`%conn` (or `$SMTP_HOST` / `$SMTP_USER` / `$SMTP_PASS` as a fallback):

| Key        | Default        | Notes                                            |
| ---------- | -------------- | ------------------------------------------------ |
| `host`     | — (required)   | SMTP server hostname                             |
| `tls`      | `starttls`     | `starttls` (587), `tls` (465), or `none` (25)    |
| `port`     | by `tls`       | Override the TLS-implied default                 |
| `username` | —              | SMTP auth user                                   |
| `password` | —              | SMTP auth password                               |

---

## \[0x04\] Compliance

This package is for sending to **your own opted-in recipients** through your own
SMTP — newsletters, transactional mail, product announcements. It ships the
mechanisms that keep that legitimate:

- **List-Unsubscribe** (RFC 2369 / 8058 one-click) auto-added to every
  `send_bulk` message when you pass `list_unsubscribe`.
- **Suppression lists** — `Email::suppress_filter` and `send_bulk`'s
  `suppression` honor opt-outs and bounces.
- **Rate limiting** — `rate => { per_minute }` / `{ delay_ms }` for
  deliverability and to stay within your provider's limits.
- **Address validation** before sending.

Obtaining consent and honoring unsubscribes (CAN-SPAM, GDPR, your provider's
ToS) is the sender's responsibility. The package gives you the tools, not a way
around them.

---

## \[0x05\] API reference

| Group   | Functions                                                                 |
| ------- | ------------------------------------------------------------------------- |
| Send    | `send`, `send_raw`, `send_bulk`, `verify_connection`                       |
| Templates | `render`, `merge`                                                       |
| Lists   | `validate`, `parse`, `unsubscribe_header`, `suppress_filter`               |
| Meta    | `version`                                                                  |

The template, address, and compliance helpers take no connection and are
unit-tested in-crate, so they validate in CI with no SMTP server.

---

## \[0x06\] Build & test

```sh
make debug       # cargo build
make test        # cargo test, then `s test t/` (live sends need $SMTP_HOST)
make install     # s pkg install -g .
```

`cargo test` runs the in-crate unit tests (merge, validation, parsing,
unsubscribe value, multipart build) with no server. Point `$SMTP_HOST` at a
local catch-all like MailHog (`tls => none`, port 1025) to exercise the send
path without emailing anyone real.

---

## \[0x07\] License

MIT &middot; MenkeTechnologies
