//! stryke-email — SMTP / email-campaign cdylib loaded in-process by stryke via
//! dlopen.
//!
//! Each `#[no_mangle] extern "C" fn email__*` is a JSON-string-in /
//! JSON-string-out wrapper. stryke's FFI bridge resolves these symbols at first
//! `use Email`, registers each as a stryke-callable function, passes a
//! JSON-encoded args dict per call, and copies the returned JSON into a stryke
//! string. `stryke_free_cstring` frees that allocation.
//!
//! Transport is blocking SMTP over `lettre` (rustls TLS, no tokio). A
//! `SmtpTransport` carries its own connection pool and is cached per
//! `(host, port, tls, user)` for the life of the stryke process, so a mass
//! mailing reuses one authenticated connection instead of reconnecting per
//! message.
//!
//! ## Campaign / mass mailing is built to be legitimate
//!
//! Mass mailing goes through the operator's **own authenticated SMTP**. The
//! package ships the machinery that separates marketing from spam:
//! **List-Unsubscribe** headers (`email__unsubscribe_header`, auto-injected by
//! `email__send_bulk`), **suppression lists** (`email__suppress_filter` +
//! `send_bulk`'s `suppression`), **rate limiting** for deliverability, and
//! address validation. Obtaining consent and honoring unsubscribes
//! (CAN-SPAM / GDPR) is the sender's responsibility; this package provides the
//! mechanisms, not a way around them.

use std::collections::HashMap;
use std::error::Error as StdError;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use lettre::address::Envelope;
use lettre::message::header::{Header, HeaderName, HeaderValue};
use lettre::message::{Mailbox, MultiPart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Address, Message, SmtpTransport, Transport};
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use serde_json::{json, Map, Value};

// ── List-Unsubscribe header (RFC 2369 / 8058) ───────────────────────────────

/// `List-Unsubscribe` — the compliance header every bulk message should carry.
#[derive(Clone)]
struct ListUnsubscribe(String);
impl Header for ListUnsubscribe {
    fn name() -> HeaderName {
        HeaderName::new_from_ascii_str("List-Unsubscribe")
    }
    fn parse(s: &str) -> std::result::Result<Self, Box<dyn StdError + Send + Sync>> {
        Ok(ListUnsubscribe(s.to_owned()))
    }
    fn display(&self) -> HeaderValue {
        HeaderValue::new(Self::name(), self.0.clone())
    }
}

/// `List-Unsubscribe-Post` — signals RFC 8058 one-click unsubscribe.
#[derive(Clone)]
struct ListUnsubscribePost(String);
impl Header for ListUnsubscribePost {
    fn name() -> HeaderName {
        HeaderName::new_from_ascii_str("List-Unsubscribe-Post")
    }
    fn parse(s: &str) -> std::result::Result<Self, Box<dyn StdError + Send + Sync>> {
        Ok(ListUnsubscribePost(s.to_owned()))
    }
    fn display(&self) -> HeaderValue {
        HeaderValue::new(Self::name(), self.0.clone())
    }
}

// ── transport cache ─────────────────────────────────────────────────────────

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct ConnKey {
    host: String,
    port: u16,
    tls: String,
    username: String,
    password: String,
}

static TRANSPORTS: OnceCell<Mutex<HashMap<ConnKey, Arc<SmtpTransport>>>> = OnceCell::new();

fn transports() -> &'static Mutex<HashMap<ConnKey, Arc<SmtpTransport>>> {
    TRANSPORTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn conn_key(opts: &Value) -> Result<ConnKey> {
    let host = opts
        .get("host")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("missing host"))?
        .to_string();
    let tls = opts
        .get("tls")
        .and_then(|v| v.as_str())
        .unwrap_or("starttls")
        .to_string();
    let default_port: u16 = match tls.as_str() {
        "tls" => 465,
        "none" => 25,
        _ => 587,
    };
    let port = opts
        .get("port")
        .and_then(|v| v.as_u64())
        .map(|p| p as u16)
        .unwrap_or(default_port);
    Ok(ConnKey {
        host,
        port,
        tls,
        username: opts
            .get("username")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        password: opts
            .get("password")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
    })
}

/// Build (or reuse the cached) `SmtpTransport` for these connection opts.
fn transport_for(opts: &Value) -> Result<Arc<SmtpTransport>> {
    let key = conn_key(opts)?;
    let mut map = transports().lock();
    if let Some(t) = map.get(&key) {
        return Ok(Arc::clone(t));
    }
    let mut builder = match key.tls.as_str() {
        "tls" => SmtpTransport::relay(&key.host).map_err(|e| anyhow!("relay {}: {e}", key.host))?,
        "none" => SmtpTransport::builder_dangerous(&key.host),
        _ => SmtpTransport::starttls_relay(&key.host)
            .map_err(|e| anyhow!("starttls {}: {e}", key.host))?,
    }
    .port(key.port)
    .timeout(Some(Duration::from_secs(30)));
    if !key.username.is_empty() {
        builder = builder.credentials(Credentials::new(key.username.clone(), key.password.clone()));
    }
    let t = Arc::new(builder.build());
    map.insert(key, Arc::clone(&t));
    Ok(t)
}

// ── FFI plumbing ────────────────────────────────────────────────────────────

fn ffi_call<F>(args: *const c_char, handler: F) -> *const c_char
where
    F: FnOnce(Value) -> Result<Value>,
{
    let input = if args.is_null() {
        Value::Null
    } else {
        let cs = unsafe { CStr::from_ptr(args) };
        serde_json::from_slice::<Value>(cs.to_bytes()).unwrap_or(Value::Null)
    };
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| handler(input)));
    let out = match result {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => json!({ "error": e.to_string() }),
        Err(_) => json!({ "error": "stryke-email handler panicked" }),
    };
    let s =
        serde_json::to_string(&out).unwrap_or_else(|_| String::from(r#"{"error":"serialize"}"#));
    match CString::new(s) {
        Ok(c) => c.into_raw() as *const c_char,
        Err(_) => std::ptr::null(),
    }
}

/// Free a C string allocated by any export from this cdylib.
///
/// # Safety
/// `p` must be a pointer previously returned by an export, or null.
#[no_mangle]
pub unsafe extern "C" fn stryke_free_cstring(p: *mut c_char) {
    if p.is_null() {
        return;
    }
    drop(CString::from_raw(p));
}

// ── pure engines (no network; unit-tested, run in CI) ───────────────────────

/// Substitute `{{ key }}` placeholders (optional inner whitespace) with values
/// from `vars`. Unknown keys render empty. No logic/conditionals — a deliberate
/// mustache-lite to keep templates injection-safe.
fn render_template(tmpl: &str, vars: &Map<String, Value>) -> String {
    let mut out = String::with_capacity(tmpl.len());
    let bytes = tmpl.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'{' && bytes[i + 1] == b'{' {
            if let Some(close) = tmpl[i + 2..].find("}}") {
                let key = tmpl[i + 2..i + 2 + close].trim();
                let val = vars.get(key).map(value_to_str).unwrap_or_default();
                out.push_str(&val);
                i = i + 2 + close + 2;
                continue;
            }
        }
        let ch = tmpl[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn value_to_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Conservative RFC 5322-ish address check: one `@`, non-empty local part, a
/// dotted domain with no spaces. Not a deliverability check (no MX lookup).
fn is_valid_address(addr: &str) -> bool {
    let a = addr.trim();
    let Some((local, domain)) = a.split_once('@') else {
        return false;
    };
    if local.is_empty() || domain.len() < 3 || a.contains(char::is_whitespace) {
        return false;
    }
    domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
}

/// Split `"Name <user@host>"` or `"user@host"` into (name, email).
fn split_address(addr: &str) -> (Option<String>, String) {
    let a = addr.trim();
    if let (Some(lt), Some(gt)) = (a.rfind('<'), a.rfind('>')) {
        if lt < gt {
            let name = a[..lt].trim().trim_matches('"').trim();
            let email = a[lt + 1..gt].trim().to_string();
            let name = (!name.is_empty()).then(|| name.to_string());
            return (name, email);
        }
    }
    (None, a.to_string())
}

/// Build a `List-Unsubscribe` header value from an optional URL and mailto.
fn unsubscribe_value(url: Option<&str>, mailto: Option<&str>) -> String {
    let mut parts = Vec::new();
    if let Some(u) = url {
        parts.push(format!("<{u}>"));
    }
    if let Some(m) = mailto {
        let m = if m.starts_with("mailto:") {
            m.to_string()
        } else {
            format!("mailto:{m}")
        };
        parts.push(format!("<{m}>"));
    }
    parts.join(", ")
}

/// Split a comma/semicolon-separated address-list into individual addresses,
/// honoring commas inside quoted names and `<...>` angle brackets.
fn split_address_list(s: &str) -> Vec<(Option<String>, String)> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    let mut in_angle = false;
    for ch in s.chars() {
        match ch {
            '"' => {
                in_quote = !in_quote;
                cur.push(ch);
            }
            '<' => {
                in_angle = true;
                cur.push(ch);
            }
            '>' => {
                in_angle = false;
                cur.push(ch);
            }
            ',' | ';' if !in_quote && !in_angle => {
                if !cur.trim().is_empty() {
                    parts.push(split_address(cur.trim()));
                }
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    if !cur.trim().is_empty() {
        parts.push(split_address(cur.trim()));
    }
    parts
}

/// Format `(name, email)` into an RFC 5322 address header value, quoting the
/// display-name when it contains special characters. The inverse of
/// `split_address`.
fn format_address(name: Option<&str>, email: &str) -> String {
    match name {
        Some(n) if !n.is_empty() => {
            let needs_quote = n.bytes().any(|b| {
                matches!(
                    b,
                    b'(' | b')'
                        | b'<'
                        | b'>'
                        | b'@'
                        | b','
                        | b';'
                        | b':'
                        | b'\\'
                        | b'"'
                        | b'.'
                        | b'['
                        | b']'
                )
            });
            if needs_quote {
                let escaped = n.replace('\\', "\\\\").replace('"', "\\\"");
                format!("\"{escaped}\" <{email}>")
            } else {
                format!("{n} <{email}>")
            }
        }
        _ => email.to_string(),
    }
}

/// Percent-encode a string for a URL query component (RFC 3986 unreserved set
/// passes through; everything else is `%XX`).
fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Parse an SMTP URI (`smtp://` or `smtps://`, optional `user:pass@`, optional
/// `:port`) into `{ scheme, host, port, tls, username, password }`. The TLS mode
/// (`smtps`→`tls`, else `starttls`) and default port (465/587) follow the scheme
/// unless an explicit port is given.
fn parse_smtp_url(url: &str) -> Result<Value> {
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (s.to_lowercase(), r),
        None => ("smtp".to_string(), url),
    };
    let tls = if scheme == "smtps" { "tls" } else { "starttls" };
    let default_port: u16 = if scheme == "smtps" { 465 } else { 587 };
    // strip any path/query — only the authority matters for SMTP
    let authority = rest.split(['/', '?']).next().unwrap_or(rest);
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, authority),
    };
    let (username, password) = match userinfo {
        Some(ui) => match ui.split_once(':') {
            Some((u, p)) => (Some(url_component_decode(u)), Some(url_component_decode(p))),
            None => (Some(url_component_decode(ui)), None),
        },
        None => (None, None),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().ok().unwrap_or(default_port)),
        None => (hostport.to_string(), default_port),
    };
    if host.is_empty() {
        return Err(anyhow!("missing host in url"));
    }
    Ok(json!({
        "scheme": scheme,
        "host": host,
        "port": port,
        "tls": tls,
        "username": username,
        "password": password,
    }))
}

/// Decode `%XX` escapes in a URL userinfo component (inverse of `pct_encode`).
fn url_component_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    let hex = |b: u8| -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    };
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Build an SMTP URI from components: `scheme` (default by `tls`), `host`
/// (required), optional `port`/`username`/`password`. Userinfo is percent-encoded.
fn build_smtp_url(v: &Value) -> Result<String> {
    let host = v
        .get("host")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("missing host"))?;
    let tls = v.get("tls").and_then(|x| x.as_str()).unwrap_or("starttls");
    let scheme = v
        .get("scheme")
        .and_then(|x| x.as_str())
        .map(String::from)
        .unwrap_or_else(|| if tls == "tls" { "smtps" } else { "smtp" }.to_string());
    let mut out = format!("{scheme}://");
    if let Some(user) = v.get("username").and_then(|x| x.as_str()) {
        out.push_str(&pct_encode(user));
        if let Some(pass) = v.get("password").and_then(|x| x.as_str()) {
            out.push(':');
            out.push_str(&pct_encode(pass));
        }
        out.push('@');
    }
    out.push_str(host);
    if let Some(port) = v.get("port").and_then(|x| x.as_u64()) {
        out.push_str(&format!(":{port}"));
    }
    Ok(out)
}

/// Replace the password in an SMTP URI with `***` for safe logging.
fn redact_smtp_url(url: &str) -> String {
    match url.split_once("://") {
        Some((scheme, rest)) => match rest.split_once('@') {
            Some((userinfo, host)) => {
                let user = userinfo.split_once(':').map(|(u, _)| u).unwrap_or(userinfo);
                format!("{scheme}://{user}:***@{host}")
            }
            None => url.to_string(),
        },
        None => url.to_string(),
    }
}

// ── message building ────────────────────────────────────────────────────────

fn mailboxes(v: &Value, key: &str) -> Result<Vec<Mailbox>> {
    let raw: Vec<String> = match v.get(key) {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|x| x.as_str().map(String::from))
            .collect(),
        _ => Vec::new(),
    };
    raw.iter()
        .map(|s| {
            s.parse::<Mailbox>()
                .map_err(|e| anyhow!("bad address {s:?}: {e}"))
        })
        .collect()
}

/// Build a lettre `Message` from a fields dict (`from`, `to`, `cc`, `bcc`,
/// `reply_to`, `subject`, `text`, `html`, `list_unsubscribe`).
fn build_message(v: &Value) -> Result<Message> {
    let from = v
        .get("from")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("missing from"))?
        .parse::<Mailbox>()
        .map_err(|e| anyhow!("bad from: {e}"))?;
    let mut b = Message::builder().from(from);
    for to in mailboxes(v, "to")? {
        b = b.to(to);
    }
    for cc in mailboxes(v, "cc")? {
        b = b.cc(cc);
    }
    for bcc in mailboxes(v, "bcc")? {
        b = b.bcc(bcc);
    }
    if let Some(rt) = v.get("reply_to").and_then(|x| x.as_str()) {
        b = b.reply_to(rt.parse().map_err(|e| anyhow!("bad reply_to: {e}"))?);
    }
    b = b.subject(v.get("subject").and_then(|x| x.as_str()).unwrap_or(""));

    if let Some(lu) = v.get("list_unsubscribe") {
        let url = lu.get("url").and_then(|x| x.as_str());
        let mailto = lu.get("mailto").and_then(|x| x.as_str());
        let value = unsubscribe_value(url, mailto);
        if !value.is_empty() {
            b = b.header(ListUnsubscribe(value));
            if url.is_some() {
                b = b.header(ListUnsubscribePost(
                    "List-Unsubscribe=One-Click".to_string(),
                ));
            }
        }
    }

    let text = v.get("text").and_then(|x| x.as_str());
    let html = v.get("html").and_then(|x| x.as_str());
    let msg = match (text, html) {
        (t, Some(h)) => b
            .multipart(MultiPart::alternative_plain_html(
                t.unwrap_or("").to_string(),
                h.to_string(),
            ))
            .map_err(|e| anyhow!("build html message: {e}"))?,
        (Some(t), None) => b
            .body(t.to_string())
            .map_err(|e| anyhow!("build message: {e}"))?,
        (None, None) => b
            .body(String::new())
            .map_err(|e| anyhow!("build message: {e}"))?,
    };
    Ok(msg)
}

// ── version + connection ────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn email__version(args: *const c_char) -> *const c_char {
    ffi_call(args, |_| Ok(json!({"version": env!("CARGO_PKG_VERSION")})))
}

#[no_mangle]
pub extern "C" fn email__verify_connection(args: *const c_char) -> *const c_char {
    ffi_call(args, |v| {
        let t = transport_for(&v)?;
        let ok = t.test_connection().map_err(|e| anyhow!("connect: {e}"))?;
        Ok(json!({ "ok": ok }))
    })
}

// ── send ────────────────────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn email__send(args: *const c_char) -> *const c_char {
    ffi_call(args, |v| {
        let msg = build_message(&v)?;
        let t = transport_for(&v)?;
        t.send(&msg).map_err(|e| anyhow!("send: {e}"))?;
        Ok(json!({ "ok": true }))
    })
}

#[no_mangle]
pub extern "C" fn email__send_raw(args: *const c_char) -> *const c_char {
    ffi_call(args, |v| {
        let raw = v
            .get("raw")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow!("missing raw"))?;
        let from = v
            .get("from")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow!("missing from"))?
            .parse::<Address>()
            .map_err(|e| anyhow!("bad from: {e}"))?;
        let to: Vec<Address> = match v.get("to") {
            Some(Value::String(s)) => vec![s.parse().map_err(|e| anyhow!("bad to: {e}"))?],
            Some(Value::Array(a)) => a
                .iter()
                .filter_map(|x| x.as_str())
                .map(|s| s.parse::<Address>().map_err(|e| anyhow!("bad to {s}: {e}")))
                .collect::<Result<_>>()?,
            _ => return Err(anyhow!("missing to")),
        };
        let envelope = Envelope::new(Some(from), to).map_err(|e| anyhow!("envelope: {e}"))?;
        let t = transport_for(&v)?;
        t.send_raw(&envelope, raw.as_bytes())
            .map_err(|e| anyhow!("send_raw: {e}"))?;
        Ok(json!({ "ok": true }))
    })
}

// ── mass mailing / campaign ─────────────────────────────────────────────────

/// Send a personalized campaign to a recipient list. Per recipient: skip if
/// suppressed, merge the template with the recipient's vars (+ `email`/`name`),
/// inject the List-Unsubscribe header, send, and record the outcome. Honors a
/// rate limit between sends. Returns per-recipient results so the caller can
/// retry failures and update their own suppression/bounce state.
#[no_mangle]
pub extern "C" fn email__send_bulk(args: *const c_char) -> *const c_char {
    ffi_call(args, |v| {
        let from = v
            .get("from")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow!("missing from"))?
            .to_string();
        let tmpl = v
            .get("template")
            .ok_or_else(|| anyhow!("missing template"))?;
        let subject_t = tmpl.get("subject").and_then(|x| x.as_str()).unwrap_or("");
        let text_t = tmpl.get("text").and_then(|x| x.as_str());
        let html_t = tmpl.get("html").and_then(|x| x.as_str());

        let recipients = v
            .get("recipients")
            .and_then(|x| x.as_array())
            .ok_or_else(|| anyhow!("missing recipients array"))?;

        let suppression: std::collections::HashSet<String> = v
            .get("suppression")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(|s| s.trim().to_lowercase()))
                    .collect()
            })
            .unwrap_or_default();

        // rate limit: explicit delay_ms, or derived from per_minute
        let delay_ms = v
            .get("rate")
            .and_then(|r| {
                r.get("delay_ms").and_then(|d| d.as_u64()).or_else(|| {
                    r.get("per_minute")
                        .and_then(|p| p.as_u64())
                        .filter(|p| *p > 0)
                        .map(|p| 60_000 / p)
                })
            })
            .unwrap_or(0);

        let lu = v.get("list_unsubscribe");
        let t = transport_for(&v)?;

        let mut results = Vec::with_capacity(recipients.len());
        let mut sent = 0u64;
        let mut failed = 0u64;
        let mut skipped = 0u64;

        for (idx, r) in recipients.iter().enumerate() {
            let email = r.get("email").and_then(|x| x.as_str()).unwrap_or("").trim();
            if email.is_empty() || !is_valid_address(email) {
                failed += 1;
                results.push(json!({"email": email, "ok": false, "error": "invalid address"}));
                continue;
            }
            if suppression.contains(&email.to_lowercase()) {
                skipped += 1;
                results.push(json!({"email": email, "ok": false, "skipped": "suppressed"}));
                continue;
            }

            // build the per-recipient merge context
            let mut vars: Map<String, Value> = r
                .get("vars")
                .and_then(|x| x.as_object())
                .cloned()
                .unwrap_or_default();
            vars.insert("email".into(), json!(email));
            if let Some(name) = r.get("name").and_then(|x| x.as_str()) {
                vars.insert("name".into(), json!(name));
            }

            let mut fields = Map::new();
            fields.insert("from".into(), json!(from));
            fields.insert("to".into(), json!(email));
            fields.insert("subject".into(), json!(render_template(subject_t, &vars)));
            if let Some(tt) = text_t {
                fields.insert("text".into(), json!(render_template(tt, &vars)));
            }
            if let Some(ht) = html_t {
                fields.insert("html".into(), json!(render_template(ht, &vars)));
            }
            if let Some(lu) = lu {
                // per-recipient unsubscribe links may themselves use {{email}}
                let url = lu
                    .get("url")
                    .and_then(|x| x.as_str())
                    .map(|u| render_template(u, &vars));
                let mailto = lu.get("mailto").and_then(|x| x.as_str()).map(String::from);
                let mut luo = Map::new();
                if let Some(u) = url {
                    luo.insert("url".into(), json!(u));
                }
                if let Some(m) = mailto {
                    luo.insert("mailto".into(), json!(m));
                }
                fields.insert("list_unsubscribe".into(), Value::Object(luo));
            }

            let outcome = build_message(&Value::Object(fields))
                .and_then(|m| t.send(&m).map_err(|e| anyhow!("{e}")));
            match outcome {
                Ok(_) => {
                    sent += 1;
                    results.push(json!({"email": email, "ok": true}));
                }
                Err(e) => {
                    failed += 1;
                    results.push(json!({"email": email, "ok": false, "error": e.to_string()}));
                }
            }

            // throttle (skip the wait after the final recipient)
            if delay_ms > 0 && idx + 1 < recipients.len() {
                std::thread::sleep(Duration::from_millis(delay_ms));
            }
        }

        Ok(json!({
            "sent": sent,
            "failed": failed,
            "skipped": skipped,
            "results": results,
        }))
    })
}

// ── pure helpers (exported) ─────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn email__render(args: *const c_char) -> *const c_char {
    ffi_call(args, |v| {
        let tmpl = v
            .get("template")
            .ok_or_else(|| anyhow!("missing template"))?;
        let empty = Map::new();
        let vars = v.get("vars").and_then(|x| x.as_object()).unwrap_or(&empty);
        let mut out = Map::new();
        for field in ["subject", "text", "html"] {
            if let Some(s) = tmpl.get(field).and_then(|x| x.as_str()) {
                out.insert(field.into(), json!(render_template(s, vars)));
            }
        }
        Ok(json!({ "value": Value::Object(out) }))
    })
}

#[no_mangle]
pub extern "C" fn email__merge(args: *const c_char) -> *const c_char {
    ffi_call(args, |v| {
        let tmpl = v
            .get("template")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow!("missing template string"))?;
        let empty = Map::new();
        let vars = v.get("vars").and_then(|x| x.as_object()).unwrap_or(&empty);
        Ok(json!({ "value": render_template(tmpl, vars) }))
    })
}

#[no_mangle]
pub extern "C" fn email__validate_address(args: *const c_char) -> *const c_char {
    ffi_call(args, |v| {
        let addr = v
            .get("address")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow!("missing address"))?;
        Ok(json!({ "valid": is_valid_address(addr) }))
    })
}

#[no_mangle]
pub extern "C" fn email__parse_address(args: *const c_char) -> *const c_char {
    ffi_call(args, |v| {
        let addr = v
            .get("address")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow!("missing address"))?;
        let (name, email) = split_address(addr);
        Ok(json!({ "name": name, "email": email }))
    })
}

#[no_mangle]
pub extern "C" fn email__unsubscribe_header(args: *const c_char) -> *const c_char {
    ffi_call(args, |v| {
        let url = v.get("url").and_then(|x| x.as_str());
        let mailto = v.get("mailto").and_then(|x| x.as_str());
        Ok(json!({ "value": unsubscribe_value(url, mailto) }))
    })
}

/// Split recipients into kept / removed by a suppression list (case-insensitive
/// on the `email` field). Run this before a campaign to honor opt-outs.
#[no_mangle]
pub extern "C" fn email__suppress_filter(args: *const c_char) -> *const c_char {
    ffi_call(args, |v| {
        let recipients = v
            .get("recipients")
            .and_then(|x| x.as_array())
            .ok_or_else(|| anyhow!("missing recipients array"))?;
        let suppression: std::collections::HashSet<String> = v
            .get("suppression")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(|s| s.trim().to_lowercase()))
                    .collect()
            })
            .unwrap_or_default();
        let (mut kept, mut removed) = (Vec::new(), Vec::new());
        for r in recipients {
            let email = r
                .get("email")
                .and_then(|x| x.as_str())
                .or_else(|| r.as_str())
                .unwrap_or("")
                .trim()
                .to_lowercase();
            if suppression.contains(&email) {
                removed.push(r.clone());
            } else {
                kept.push(r.clone());
            }
        }
        Ok(json!({ "kept": kept, "removed": removed }))
    })
}

/// Parse an address-list string into `[{ name, email }]`.
#[no_mangle]
pub extern "C" fn email__split_addresses(args: *const c_char) -> *const c_char {
    ffi_call(args, |v| {
        let list = v
            .get("list")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow!("missing list"))?;
        let out: Vec<Value> = split_address_list(list)
            .into_iter()
            .map(|(name, email)| json!({ "name": name, "email": email }))
            .collect();
        Ok(json!({ "addresses": out }))
    })
}

/// Validate a batch of addresses → `{ valid: [...], invalid: [...] }`.
#[no_mangle]
pub extern "C" fn email__validate_list(args: *const c_char) -> *const c_char {
    ffi_call(args, |v| {
        let addrs = v
            .get("addresses")
            .and_then(|x| x.as_array())
            .ok_or_else(|| anyhow!("missing addresses array"))?;
        let (mut valid, mut invalid) = (Vec::new(), Vec::new());
        for a in addrs {
            let Some(s) = a.as_str() else { continue };
            if is_valid_address(s) {
                valid.push(json!(s));
            } else {
                invalid.push(json!(s));
            }
        }
        Ok(json!({ "valid": valid, "invalid": invalid }))
    })
}

/// Domain part of a single address (after parsing off any display name).
#[no_mangle]
pub extern "C" fn email__address_domain(args: *const c_char) -> *const c_char {
    ffi_call(args, |v| {
        let addr = v
            .get("address")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow!("missing address"))?;
        let (_, email) = split_address(addr);
        let domain = email.split_once('@').map(|(_, d)| d.to_string());
        Ok(json!({ "domain": domain }))
    })
}

/// Render one template string across an array of var dicts → `{ values: [...] }`.
#[no_mangle]
pub extern "C" fn email__merge_many(args: *const c_char) -> *const c_char {
    ffi_call(args, |v| {
        let tmpl = v
            .get("template")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow!("missing template string"))?;
        let rows = v
            .get("rows")
            .and_then(|x| x.as_array())
            .ok_or_else(|| anyhow!("missing rows array"))?;
        let empty = Map::new();
        let values: Vec<Value> = rows
            .iter()
            .map(|r| {
                let vars = r.as_object().unwrap_or(&empty);
                json!(render_template(tmpl, vars))
            })
            .collect();
        Ok(json!({ "values": values }))
    })
}

/// Format `{ name?, email }` into an RFC 5322 address header value.
#[no_mangle]
pub extern "C" fn email__format_address(args: *const c_char) -> *const c_char {
    ffi_call(args, |v| {
        let email = v
            .get("email")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow!("missing email"))?;
        let name = v.get("name").and_then(|x| x.as_str());
        Ok(json!({ "value": format_address(name, email) }))
    })
}

/// Build a `mailto:` URL with optional `subject`, `body`, `cc`, `bcc` (all
/// percent-encoded).
#[no_mangle]
pub extern "C" fn email__mailto(args: *const c_char) -> *const c_char {
    ffi_call(args, |v| {
        let to = v
            .get("to")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow!("missing to"))?;
        let mut params = Vec::new();
        for key in ["subject", "body", "cc", "bcc"] {
            if let Some(val) = v.get(key).and_then(|x| x.as_str()) {
                params.push(format!("{key}={}", pct_encode(val)));
            }
        }
        let url = if params.is_empty() {
            format!("mailto:{to}")
        } else {
            format!("mailto:{to}?{}", params.join("&"))
        };
        Ok(json!({ "url": url }))
    })
}

/// Parse an SMTP URI into `{ scheme, host, port, tls, username, password }`.
#[no_mangle]
pub extern "C" fn email__parse_url(args: *const c_char) -> *const c_char {
    ffi_call(args, |v| {
        let url = v
            .get("url")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow!("missing url"))?;
        Ok(json!({ "parts": parse_smtp_url(url)? }))
    })
}

/// Build an SMTP URI from a components map (inverse of parse_url).
#[no_mangle]
pub extern "C" fn email__build_url(args: *const c_char) -> *const c_char {
    ffi_call(args, |v| {
        let parts = v
            .get("parts")
            .ok_or_else(|| anyhow!("missing parts object"))?;
        Ok(json!({ "value": build_smtp_url(parts)? }))
    })
}

/// Replace the password in an SMTP URI with `***` for safe logging.
#[no_mangle]
pub extern "C" fn email__redact_url(args: *const c_char) -> *const c_char {
    ffi_call(args, |v| {
        let url = v
            .get("url")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow!("missing url"))?;
        Ok(json!({ "value": redact_smtp_url(url) }))
    })
}

// ── unit tests (pure logic) ─────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> Map<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), json!(v)))
            .collect()
    }

    #[test]
    fn render_substitutes_and_trims() {
        let v = vars(&[("name", "Ada"), ("plan", "Pro")]);
        assert_eq!(
            render_template("Hi {{name}}, on {{ plan }}!", &v),
            "Hi Ada, on Pro!"
        );
    }

    #[test]
    fn render_unknown_key_is_empty_and_literal_braces_survive() {
        let v = vars(&[]);
        assert_eq!(render_template("x={{missing}}y", &v), "x=y");
        assert_eq!(render_template("no placeholder", &v), "no placeholder");
        assert_eq!(render_template("{ single }", &v), "{ single }");
    }

    #[test]
    fn address_validation() {
        assert!(is_valid_address("user@example.com"));
        assert!(is_valid_address("a.b+tag@sub.example.co.uk"));
        assert!(!is_valid_address("no-at-sign"));
        assert!(!is_valid_address("user@localhost"));
        assert!(!is_valid_address("user @example.com"));
        assert!(!is_valid_address("@example.com"));
    }

    #[test]
    fn parse_named_and_bare_addresses() {
        assert_eq!(
            split_address("Ada Lovelace <ada@example.com>"),
            (
                Some("Ada Lovelace".to_string()),
                "ada@example.com".to_string()
            )
        );
        assert_eq!(
            split_address("bare@example.com"),
            (None, "bare@example.com".to_string())
        );
        assert_eq!(
            split_address("\"Quoted Name\" <q@example.com>"),
            (Some("Quoted Name".to_string()), "q@example.com".to_string())
        );
    }

    #[test]
    fn unsubscribe_header_value() {
        assert_eq!(
            unsubscribe_value(Some("https://x.com/u?e=a@b.com"), Some("unsub@x.com")),
            "<https://x.com/u?e=a@b.com>, <mailto:unsub@x.com>"
        );
        assert_eq!(
            unsubscribe_value(None, Some("mailto:u@x.com")),
            "<mailto:u@x.com>"
        );
        assert_eq!(unsubscribe_value(None, None), "");
    }

    #[test]
    fn conn_key_default_ports_by_tls() {
        assert_eq!(conn_key(&json!({"host": "h"})).unwrap().port, 587); // starttls
        assert_eq!(
            conn_key(&json!({"host": "h", "tls": "tls"})).unwrap().port,
            465
        );
        assert_eq!(
            conn_key(&json!({"host": "h", "tls": "none"})).unwrap().port,
            25
        );
        assert_eq!(
            conn_key(&json!({"host": "h", "port": 2525})).unwrap().port,
            2525
        );
    }

    #[test]
    fn split_list_honors_quotes_and_angles() {
        let v = split_address_list(r#"Ada <a@x.com>, "Lovelace, Jr" <b@x.com>; c@x.com"#);
        assert_eq!(v.len(), 3);
        assert_eq!(v[0], (Some("Ada".to_string()), "a@x.com".to_string()));
        assert_eq!(
            v[1],
            (Some("Lovelace, Jr".to_string()), "b@x.com".to_string())
        );
        assert_eq!(v[2], (None, "c@x.com".to_string()));
    }

    #[test]
    fn format_address_quotes_specials_roundtrips() {
        assert_eq!(format_address(Some("Ada"), "a@x.com"), "Ada <a@x.com>");
        assert_eq!(
            format_address(Some("Lovelace, Jr"), "a@x.com"),
            "\"Lovelace, Jr\" <a@x.com>"
        );
        assert_eq!(format_address(None, "a@x.com"), "a@x.com");
        // round-trips through split_address for the simple case
        assert_eq!(
            split_address(&format_address(Some("Ada"), "a@x.com")).1,
            "a@x.com"
        );
    }

    #[test]
    fn pct_encode_query_component() {
        assert_eq!(pct_encode("hi there"), "hi%20there");
        assert_eq!(pct_encode("a&b=c"), "a%26b%3Dc");
        assert_eq!(pct_encode("plain-_.~"), "plain-_.~");
    }

    #[test]
    fn build_message_html_multipart() {
        let v = json!({
            "from": "Sender <s@example.com>",
            "to": "r@example.com",
            "subject": "Hi",
            "text": "plain",
            "html": "<b>rich</b>",
            "list_unsubscribe": {"url": "https://x.com/u", "mailto": "u@x.com"}
        });
        // building must succeed and produce a serializable message
        let msg = build_message(&v).unwrap();
        let formatted = String::from_utf8(msg.formatted()).unwrap();
        assert!(formatted.contains("List-Unsubscribe"));
        assert!(formatted.contains("multipart/alternative"));
    }

    #[test]
    fn parse_smtp_url_scheme_defaults() {
        let v = parse_smtp_url("smtp://user:pw@mail.example.com").unwrap();
        assert_eq!(v["host"], json!("mail.example.com"));
        assert_eq!(v["port"], json!(587));
        assert_eq!(v["tls"], json!("starttls"));
        assert_eq!(v["username"], json!("user"));
        assert_eq!(v["password"], json!("pw"));

        let s = parse_smtp_url("smtps://mail.example.com:2465").unwrap();
        assert_eq!(s["tls"], json!("tls"));
        assert_eq!(s["port"], json!(2465));
        assert_eq!(s["username"], Value::Null);
    }

    #[test]
    fn parse_smtp_url_decodes_userinfo() {
        let v = parse_smtp_url("smtp://me%40corp:p%40ss@host").unwrap();
        assert_eq!(v["username"], json!("me@corp"));
        assert_eq!(v["password"], json!("p@ss"));
    }

    #[test]
    fn build_smtp_url_roundtrips() {
        let parts =
            json!({"host": "h", "port": 587, "username": "u", "password": "p", "tls": "starttls"});
        assert_eq!(build_smtp_url(&parts).unwrap(), "smtp://u:p@h:587");
        let tls = json!({"host": "h", "tls": "tls"});
        assert_eq!(build_smtp_url(&tls).unwrap(), "smtps://h");
        // userinfo gets percent-encoded
        let enc = json!({"host": "h", "username": "a@b"});
        assert_eq!(build_smtp_url(&enc).unwrap(), "smtp://a%40b@h");
    }

    #[test]
    fn redact_smtp_url_masks_password() {
        assert_eq!(
            redact_smtp_url("smtps://user:secret@mail:465"),
            "smtps://user:***@mail:465"
        );
        assert_eq!(redact_smtp_url("smtp://mail:587"), "smtp://mail:587");
    }
}
