//! reCAPTCHA Enterprise token minter.
//!
//! Mounts the site's own reCAPTCHA script (`enterprise.js`) inside the shared
//! V8 realm and calls `grecaptcha.enterprise.execute(key, {action})`, exactly
//! as the page does. The realm runs the vendor JS itself, so the token carries
//! whatever signals the build emits; the host only serves the realm's network
//! through the same proxy/fingerprint the login will use, which keeps the token
//! bound to the minting IP the way the edge expects.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{Value, json};
use url::Url;

use wre_client::client::{Client, Registration};
use wre_client::context::{Call, Ctx, FetchRequest, HttpOptions, Jar};
use wre_client::error::{ClientError, ClientResult};
use wre_client::shape::{Shape, field};
use wre_client::spec::{Capabilities, ClientDescriptor, Concurrency, OpSpec};
use wre_live::realm::{RealmOptions, initialize};
use wre_sandbox::browser::{Answer, Browser, CookieStore, Hooks, Request, Transport, now_ms, open};
use wre_sandbox::page::Page;
use wre_sandbox::profile::Profile;

pub const ID: &str = "recaptcha";

const DEFAULT_PAGE_URL: &str = "https://capital.com/en-int";
const DEFAULT_SITEKEY: &str = "6LeUuLoZAAAAADHg_o02k1zHLlIwCKwmEpnOxnwb";
const DEFAULT_ACTION: &str = "login";
const DEFAULT_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

const NAV_ORDER: [&str; 12] = [
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "upgrade-insecure-requests",
    "user-agent",
    "accept",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-user",
    "sec-fetch-dest",
    "accept-encoding",
    "accept-language",
];

pub fn registration() -> Registration {
    Registration { id: ID, describe, build }
}

pub fn describe() -> ClientDescriptor {
    ClientDescriptor::new(ID, env!("CARGO_PKG_VERSION"))
        .summary("Mints a reCAPTCHA Enterprise token by running the site's own script in a V8 realm")
        .notes(
            "The token is single use and bound to the IP the session goes through; mint and \
             redeem must share one proxy.",
        )
        .capabilities(Capabilities {
            needs_v8: true,
            needs_chrome: false,
            needs_network: true,
            stateful: true,
            concurrency: Concurrency::PerSession,
            warmup_ms: 200,
        })
        .config(config_shape())
        .op(
            OpSpec::new(
                "mint",
                Shape::object(
                    "MintInput",
                    [
                        field("action", Shape::optional(Shape::Str))
                            .summary("Action name, defaults to the session config"),
                        field("sitekey", Shape::optional(Shape::Str))
                            .summary("Overrides the site key from the session config"),
                        field("timeout_ms", Shape::optional(Shape::Int))
                            .summary("Overrides how long to wait for the token"),
                    ],
                ),
                Shape::object(
                    "MintOutput",
                    [
                        field("token", Shape::Str),
                        field("len", Shape::Int),
                        field("action", Shape::Str),
                        field("sitekey", Shape::Str),
                        field("took_ms", Shape::Int),
                    ],
                ),
            )
            .summary("Run the mounted reCAPTCHA build and return the token it produces")
            .deadline_ms(120_000),
        )
        .op(
            OpSpec::new(
                "eval",
                Shape::object("EvalInput", [field("expression", Shape::Str)]),
                Shape::Json,
            )
            .summary("Evaluate an expression inside the realm the recaptcha script is running in")
            .deadline_ms(60_000),
        )
        .op(
            OpSpec::new(
                "cookies",
                Shape::object("CookiesInput", []),
                Shape::object(
                    "CookiesOutput",
                    [field("header", Shape::Str), field("count", Shape::Int)],
                ),
            )
            .summary("The cookie header the realm currently holds"),
        )
        .op(
            OpSpec::new(
                "pump",
                Shape::object(
                    "PumpInput",
                    [field("ms", Shape::optional(Shape::Float))
                        .summary("Milliseconds of timers/traffic to advance")],
                ),
                Shape::object("PumpOutput", [field("delivered", Shape::Int)]),
            )
            .summary("Advance the realm clock, drain traffic, deliver channel messages")
            .deadline_ms(60_000),
        )
        .op(
            OpSpec::new(
                "run",
                Shape::object(
                    "RunInput",
                    [
                        field("source", Shape::Str).summary("JavaScript to evaluate in the realm"),
                        field("name", Shape::optional(Shape::Str)).summary("Name shown in records"),
                    ],
                ),
                Shape::object("RunOutput", [field("error", Shape::Str)]),
            )
            .summary("Evaluate source in the realm, returning any error it threw")
            .deadline_ms(60_000),
        )
        .op(
            OpSpec::new(
                "requests",
                Shape::object("RequestsInput", []),
                Shape::object(
                    "RequestsOutput",
                    [
                        field("count", Shape::Int),
                        field("list", Shape::list(Shape::object(
                            "Seen",
                            [
                                field("method", Shape::Str),
                                field("url", Shape::Str),
                                field("status", Shape::Int),
                            ],
                        ))),
                    ],
                ),
            )
            .summary("Every request the realm made, in order"),
        )
        .op(
            OpSpec::new(
                "errors",
                Shape::object("ErrorsInput", []),
                Shape::object(
                    "ErrorsOutput",
                    [field("count", Shape::Int), field("list", Shape::list(Shape::Str))],
                ),
            )
            .summary("Script errors the realm recorded while running the vendor build"),
        )
        .op(
            OpSpec::new(
                "reset",
                Shape::object(
                    "ResetInput",
                    [field("cookies", Shape::optional(Shape::Bool))
                        .summary("Empty the jar too, off by default")],
                ),
                Shape::object("Reset", [field("open", Shape::Bool)]),
            )
            .summary("Drop the realm, and the cookies when asked"),
        )
}

fn config_shape() -> Shape {
    Shape::object(
        "RecaptchaConfig",
        [
            field("page_url", Shape::optional(Shape::Str))
                .summary("Page the realm is mounted against, sets the origin and referrer"),
            field("sitekey", Shape::optional(Shape::Str)).summary("reCAPTCHA site key"),
            field("action", Shape::optional(Shape::Str)).summary("Default action name"),
            field("profile", Shape::optional(Shape::Str))
                .summary("Sandbox profile id, from `wre sandbox list`"),
            field("proxy", Shape::optional(Shape::Str))
                .summary("Proxy url the realm and the mint both go through, http or socks5"),
            field("fingerprint", Shape::optional(Shape::Str))
                .summary("Transport fingerprint as profile[:platform]"),
            field("user_agent", Shape::optional(Shape::Str))
                .summary("Overrides the user agent the sandbox profile carries"),
            field("minimal_page", Shape::Bool)
                .summary("Mount a small page that only loads the recaptcha script, instead of \
                          fetching the live page")
                .with_default(json!(true)),
            field("timeout_ms", Shape::Int)
                .summary("Cap on one http request the session makes")
                .with_default(json!(45_000)),
            field("wait_ms", Shape::Int)
                .summary("Ceiling on the pump after execute, it ends as soon as a token lands")
                .with_default(json!(30_000)),
        ],
    )
}

#[derive(Debug, Clone, Deserialize)]
struct Config {
    #[serde(default)]
    page_url: Option<String>,
    #[serde(default)]
    sitekey: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    profile: Option<String>,
    #[serde(default)]
    proxy: Option<String>,
    #[serde(default)]
    fingerprint: Option<String>,
    #[serde(default)]
    user_agent: Option<String>,
    #[serde(default = "yes")]
    minimal_page: bool,
    #[serde(default = "default_timeout")]
    timeout_ms: u64,
    #[serde(default = "default_wait")]
    wait_ms: u64,
}

fn yes() -> bool {
    true
}

fn default_timeout() -> u64 {
    45_000
}

fn default_wait() -> u64 {
    30_000
}

fn build(ctx: Ctx, config: Value) -> ClientResult<Box<dyn Client>> {
    let config: Config = serde_json::from_value(config)
        .map_err(|error| ClientError::bad_input(format!("config rejected: {error}")))?;

    let page_url = config.page_url.clone().unwrap_or_else(|| DEFAULT_PAGE_URL.to_string());
    let sitekey = config.sitekey.clone().unwrap_or_else(|| DEFAULT_SITEKEY.to_string());
    let action = config.action.clone().unwrap_or_else(|| DEFAULT_ACTION.to_string());
    let user_agent = config.user_agent.clone().unwrap_or_else(|| DEFAULT_UA.to_string());

    ctx.fact("page_url", json!(page_url));
    ctx.fact("sitekey", json!(sitekey));

    Ok(Box::new(Recaptcha {
        ctx,
        config,
        page_url,
        sitekey,
        action,
        user_agent,
        jar: Jar::new(),
        session: None,
        realms: 0,
    }))
}

struct Recaptcha {
    ctx: Ctx,
    config: Config,
    page_url: String,
    sitekey: String,
    action: String,
    user_agent: String,
    jar: Jar,
    session: Option<Session>,
    realms: u64,
}

impl Recaptcha {
    fn session(&mut self) -> ClientResult<&mut Session> {
        if self.session.is_none() {
            let record = Record::builtin();
            let mut options = HttpOptions::with_proxy(self.config.proxy.as_deref());
            options.fingerprint = self.config.fingerprint.clone();
            options.user_agent = Some(self.user_agent.clone());
            options.timeout_secs = Some(self.config.timeout_ms.div_ceil(1000).max(1));
            options.jar = Some(self.jar.clone());

            let http = Arc::new(self.ctx.http_with(options)?);

            let session = Session {
                http,
                jar: self.jar.clone(),
                browser: None,
                page_url: self.page_url.clone(),
                origin: origin_of(&self.page_url),
                html: String::new(),
                sitekey: self.sitekey.clone(),
                user_agent: self.user_agent.clone(),
                proxy: self.config.proxy.clone(),
                minimal: self.config.minimal_page,
                timeout_ms: self.config.timeout_ms,
                wait_ms: self.config.wait_ms,
                seed: self.ctx.random_u64(),
                requests: Arc::new(Mutex::new(Vec::new())),
                sequence: Arc::new(AtomicU64::new(1)),
                held: Arc::new(HeldCookies::default()),
                last_profile: record.id.clone(),
                opens: 0,
            };

            self.session = Some(session);
        }

        Ok(self.session.as_mut().expect("session"))
    }
}

impl Client for Recaptcha {
    fn call(&mut self, op: &str, params: Value, call: &Call) -> ClientResult<Value> {
        call.check()?;
        let started = Instant::now();

        let default_action = self.action.clone();
        let default_sitekey = self.sitekey.clone();
        let default_wait = self.session.as_ref().map(|s| s.wait_ms).unwrap_or(self.config.wait_ms);

        let outcome = match op {
            "mint" => {
                let action = params
                    .get("action")
                    .and_then(Value::as_str)
                    .unwrap_or(&default_action)
                    .to_string();
                let sitekey = params
                    .get("sitekey")
                    .and_then(Value::as_str)
                    .unwrap_or(&default_sitekey)
                    .to_string();
                let timeout = params
                    .get("timeout_ms")
                    .and_then(Value::as_u64)
                    .unwrap_or(default_wait);

                let session = self.session()?;
                session.ensure_open()?;
                let token = session.mint(&action, &sitekey, timeout)?;

                Ok(json!({
                    "token": token,
                    "len": token.len(),
                    "action": action,
                    "sitekey": sitekey,
                    "took_ms": started.elapsed().as_millis() as u64,
                }))
            }

            "eval" => {
                let expression = params
                    .get("expression")
                    .and_then(Value::as_str)
                    .ok_or_else(|| ClientError::bad_input("expression is required"))?
                    .to_string();
                let session = self.session()?;
                session.ensure_open()?;
                session.browser_mut()?.eval(&expression).map_err(failed)
            }

            "cookies" => {
                let session = self.session()?;
                session.ensure_open()?;
                let header = session.cookie_header();
                let count = if header.is_empty() { 0 } else { header.split(';').count() };
                Ok(json!({ "header": header, "count": count }))
            }

            "requests" => {
                let session = self.session()?;
                let seen = session.seen();
                Ok(json!({ "count": seen.len(), "list": seen }))
            }

            "pump" => {
                let ms = params.get("ms").and_then(Value::as_f64).unwrap_or(250.0);
                let session = self.session()?;
                session.ensure_open()?;
                session.pump(ms)?;
                let delivered = self
                    .session()?
                    .browser_mut()?
                    .eval("(window.__mcPump && window.__mcPump()) || 0")
                    .map_err(failed)?;
                Ok(json!({ "delivered": delivered }))
            }

            "run" => {
                let source = params
                    .get("source")
                    .and_then(Value::as_str)
                    .ok_or_else(|| ClientError::bad_input("source is required"))?
                    .to_string();
                let name = params
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("recaptcha:run")
                    .to_string();
                let session = self.session()?;
                session.ensure_open()?;
                let wrapped = format!(
                    "window.__runError = null;\n(function () {{ try {{\n{}\n}} catch (e) {{ \
                     window.__runError = String((e && e.stack) || e); }} }})();",
                    source
                );
                session.browser_mut()?.run(&wrapped, &name).map_err(failed)?;
                let error = session
                    .browser_mut()?
                    .eval("window.__runError || '(no error)'")
                    .map_err(failed)?;
                Ok(json!({ "error": error }))
            }

            "errors" => {
                let session = self.session()?;
                let list = session.errors();
                Ok(json!({ "count": list.len(), "list": list }))
            }

            "reset" => {
                let wipe = params.get("cookies").and_then(Value::as_bool).unwrap_or(false);
                if let Some(mut session) = self.session.take() {
                    session.browser = None;
                }
                if wipe {
                    self.jar = Jar::new();
                }
                Ok(json!({ "open": false }))
            }

            other => Err(ClientError::unsupported(format!("{ID} has no op {other}"))),
        };

        self.ctx
            .metric(&format!("recaptcha.{op}.ms"), started.elapsed().as_millis() as f64);

        outcome.map_err(|error| error.with_op(op).with_target(ID))
    }

    fn warmup(&mut self, _call: &Call) -> ClientResult<()> {
        self.session()?.ensure_open()
    }

    fn health(&mut self) -> ClientResult<Value> {
        Ok(json!({
            "ok": self.session.as_ref().map(|s| s.browser.is_some()).unwrap_or(false),
            "target": ID,
            "detail": {
                "page_url": self.page_url,
                "sitekey": self.sitekey,
                "profile": self.session.as_ref().map(|s| s.last_profile.clone()),
                "opens": self.session.as_ref().map(|s| s.opens).unwrap_or(0),
            }
        }))
    }

    fn diagnostics(&mut self) -> Value {
        let seen = self.session.as_ref().map(|s| s.seen()).unwrap_or_default();
        json!({ "requests": seen.len() })
    }

    fn close(&mut self) -> ClientResult<()> {
        if let Some(mut session) = self.session.take() {
            session.browser = None;
        }
        Ok(())
    }
}

struct Record {
    id: String,
}

impl Record {
    fn builtin() -> Self {
        Self { id: "builtin-desktop-chrome".to_string() }
    }
}

// ---------------------------------------------------------------------------
// The realm + its network
// ---------------------------------------------------------------------------

struct Session {
    http: Arc<wre_client::context::Http>,
    jar: Jar,
    browser: Option<Browser>,
    page_url: String,
    origin: String,
    html: String,
    sitekey: String,
    user_agent: String,
    proxy: Option<String>,
    minimal: bool,
    timeout_ms: u64,
    wait_ms: u64,
    seed: u64,
    requests: Arc<Mutex<Vec<Seen>>>,
    sequence: Arc<AtomicU64>,
    held: Arc<HeldCookies>,
    last_profile: String,
    opens: u64,
}

#[derive(Debug, Clone)]
struct Seen {
    method: String,
    url: String,
    status: u16,
    req_body: String,
    resp_body: String,
}

impl Seen {
    fn to_json(&self) -> Value {
        json!({
            "method": self.method,
            "url": self.url,
            "status": self.status,
            "req_body": self.req_body,
            "resp_body": self.resp_body,
        })
    }
}

impl Session {
    fn browser_mut(&mut self) -> ClientResult<&mut Browser> {
        self.browser
            .as_mut()
            .ok_or_else(|| ClientError::bad_input("no realm is open, call mint first"))
    }

    fn errors(&mut self) -> Vec<String> {
        self.browser
            .as_mut()
            .map(|browser| browser.errors())
            .unwrap_or_default()
    }

    fn seen(&self) -> Vec<Value> {
        self.requests
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
            .map(Seen::to_json)
            .collect()
    }

    fn cookie_header(&self) -> String {
        let url = if self.page_url.is_empty() { "https://capital.com/" } else { &self.page_url };
        self.jar
            .matching(url)
            .into_iter()
            .map(|cookie| format!("{}={}", cookie.name, cookie.value))
            .collect::<Vec<_>>()
            .join("; ")
    }

    fn ensure_open(&mut self) -> ClientResult<()> {
        if self.browser.is_some() {
            return Ok(());
        }

        if self.minimal {
            self.html = minimal_html(&self.sitekey);
        } else {
            let request = FetchRequest::get(self.page_url.clone())
                .header("user-agent", self.user_agent.clone())
                .header(
                    "accept",
                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                )
                .header("accept-language", "en-US,en;q=0.9")
                .ordered(&NAV_ORDER);
            let response = self.http.fetch(request)?;
            self.page_url = response.url.clone();
            self.origin = origin_of(&self.page_url);
            self.html = response.text();
        }

        let transport = Arc::new(Live {
            http: Arc::clone(&self.http),
            jar: self.jar.clone(),
            page_url: self.page_url.clone(),
            origin: self.origin.clone(),
            user_agent: self.user_agent.clone(),
            requests: Arc::clone(&self.requests),
            sequence: Arc::clone(&self.sequence),
        });

        let hooks = Hooks {
            transport: Arc::clone(&transport) as Arc<dyn Transport>,
            cookies: Arc::clone(&self.held) as Arc<dyn CookieStore>,
        };

        let page = Page::read(&self.page_url, &self.html).with_epoch(now_ms());

        let options = RealmOptions {
            timeout: Duration::from_millis(self.timeout_ms.max(1000)),
            timers: false,
            codecs: true,
            clock_ms: None,
            random_seed: Some(self.seed),
            heap_limit_mb: Some(512),
        };

        initialize();
        let mut browser = open(&Profile::desktop_chrome(), &page, hooks, options)
            .map_err(|error| ClientError::internal(format!("the realm did not open: {error}")))?;

        // Let the page settle before anything is asked of it.
        let _ = browser.advance(1500.0);
        let _ = browser.settle(4);

        self.browser = Some(browser);
        self.opens += 1;
        Ok(())
    }

    fn mint(&mut self, action: &str, sitekey: &str, wait_ms: u64) -> ClientResult<String> {
        // The sandbox does not execute <script src> tags found in the initial
        // markup, so the vendor loader has to be fetched and run by hand. The
        // loader then inserts the real build, which the sandbox does fetch.
        self.install_polyfills()?;
        self.boot_client(sitekey)?;

        // The vendor build defers its bootstrap to the page lifecycle, so the
        // realm has to reach "complete" before execute() is installed.
        {
            let browser = self.browser_mut()?;
            let _ = browser.ready("interactive");
        }
        self.pump(300.0)?;
        {
            let browser = self.browser_mut()?;
            let _ = browser.ready("complete");
        }
        self.pump(800.0)?;

        let deadline = Instant::now() + Duration::from_millis(wait_ms.max(500));

        // Wait for grecaptcha.enterprise to be present before asking for a token.
        loop {
            self.pump(250.0)?;
            let ready = self
                .browser_mut()?
                .eval("(window.grecaptcha && window.grecaptcha.enterprise) ? 1 : 0")
                .map_err(failed)?;
            if ready.as_i64().unwrap_or(0) == 1 {
                break;
            }
            if Instant::now() >= deadline {
                return Err(ClientError::internal(format!(
                    "the recaptcha build never installed ({} requests seen)",
                    self.requests.lock().map(|list| list.len()).unwrap_or(0)
                )));
            }
            std::thread::sleep(Duration::from_millis(60));
        }

        // Warm up: the first execute on a fresh realm can miss, the next ones land.
        self.invoke(action, sitekey, deadline).ok();

        let mut last = String::new();
        loop {
            match self.invoke(action, sitekey, deadline) {
                Ok(token) if !token.is_empty() => return Ok(token),
                Ok(_) => last = "empty token".to_string(),
                Err(error) => last = error.to_string(),
            }
            if Instant::now() >= deadline {
                return Err(ClientError::internal(format!("no token: {last}")));
            }
            std::thread::sleep(Duration::from_millis(80));
        }
    }

    fn install_polyfills(&mut self) -> ClientResult<()> {
        let browser = self.browser_mut()?;
        browser.run(POLYFILLS, "recaptcha:polyfills").map_err(failed)?;
        Ok(())
    }

    /// Advance the realm clock, drain network/timers, then deliver any messages
    /// that queued on the MessageChannel shim. The vendor build posts work
    /// across that channel, so nothing progresses without this.
    fn pump(&mut self, ms: f64) -> ClientResult<()> {
        {
            let browser = self.browser_mut()?;
            let _ = browser.advance(ms);
            let _ = browser.settle(2);
        }
        let _ = self
            .browser_mut()?
            .eval("(window.__mcPump && window.__mcPump()) || 0")
            .map_err(failed)?;
        Ok(())
    }

    fn boot_client(&mut self, sitekey: &str) -> ClientResult<()> {
        let already = self
            .browser_mut()?
            .eval("(window.grecaptcha && window.grecaptcha.enterprise) ? 1 : 0")
            .map_err(failed)?;
        if already.as_i64().unwrap_or(0) == 1 {
            return Ok(());
        }

        let loader_url =
            format!("https://www.google.com/recaptcha/enterprise.js?render={sitekey}");
        let request = FetchRequest::get(loader_url)
            .header("user-agent", self.user_agent.clone())
            .header("accept", "*/*")
            .ordered(&NAV_ORDER);
        let response = self.http.fetch(request)?;
        let source = response.text();

        {
            let browser = self.browser_mut()?;
            browser.run(&source, "recaptcha:loader").map_err(failed)?;
        }

        // The loader inserts the real build as a <script src>; the sandbox
        // fetches such tags but never evaluates their body, so pull every new
        // external script down and run it by hand, a few rounds deep.
        let mut ran: Vec<String> = Vec::new();
        for round in 0..4 {
            let listed = self
                .browser_mut()?
                .eval(
                    "JSON.stringify(Array.prototype.map.call(\
                     document.getElementsByTagName('script'), function (s) { return s.src || ''; })\
                     .filter(function (u) { return u.indexOf('http') === 0; }))",
                )
                .map_err(failed)?;
            let urls: Vec<String> =
                serde_json::from_str(listed.as_str().unwrap_or("[]")).unwrap_or_default();

            let mut fetched_any = false;
            for url in urls {
                if ran.contains(&url) {
                    continue;
                }
                ran.push(url.clone());
                let request = FetchRequest::get(url.clone())
                    .header("user-agent", self.user_agent.clone())
                    .header("accept", "*/*")
                    .ordered(&NAV_ORDER);
                let Ok(response) = self.http.fetch(request) else {
                    continue;
                };
                let body = response.text();
                let name = format!("recaptcha:script:{round}");
                self.browser_mut()?.run(&body, &name).map_err(failed)?;
                fetched_any = true;
            }

            if !fetched_any {
                break;
            }
            self.pump(150.0)?;
        }

        Ok(())
    }

    fn invoke(&mut self, action: &str, sitekey: &str, deadline: Instant) -> ClientResult<String> {
        let call = format!(
            r#"window.__recapCall({}, {})"#,
            json!(sitekey),
            json!(action)
        );
        self.browser_mut()?.run(&call, "recaptcha:call").map_err(failed)?;

        let mut last = String::new();
        loop {
            self.pump(250.0)?;
            let state = self
                .browser_mut()?
                .eval("JSON.stringify(window.__recapState || null)")
                .map_err(failed)?;
            let text = state.as_str().unwrap_or("null").to_string();
            if text != "null" {
                let parsed: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                let status = parsed.get("status").and_then(Value::as_str).unwrap_or("");
                let token = parsed.get("token").and_then(Value::as_str).unwrap_or("");
                if !token.is_empty() {
                    return Ok(token.to_string());
                }
                if status == "err" {
                    last = parsed
                        .get("err")
                        .and_then(Value::as_str)
                        .unwrap_or("error")
                        .to_string();
                    return Err(ClientError::internal(last));
                }
                last = format!("status={status}");
            }
            if Instant::now() >= deadline {
                return Err(ClientError::internal(format!("no token: {last}")));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

fn origin_of(url: &str) -> String {
    Url::parse(url)
        .ok()
        .map(|parsed| format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or_default()))
        .unwrap_or_else(|| "https://capital.com".to_string())
}

fn failed(error: wre_core::error::Error) -> ClientError {
    ClientError::internal(format!("realm error: {error}"))
}

// ---------------------------------------------------------------------------
// Network: the realm's requests through the host http client
// ---------------------------------------------------------------------------

struct Live {
    http: Arc<wre_client::context::Http>,
    jar: Jar,
    page_url: String,
    origin: String,
    user_agent: String,
    requests: Arc<Mutex<Vec<Seen>>>,
    sequence: Arc<AtomicU64>,
}

impl Live {
    fn send(&self, request: &Request) -> Answer {
        let cross = !same_origin(&self.origin, &request.url);
        let method = request.method.to_uppercase();

        let mut headers: Vec<(String, String)> = Vec::new();
        headers.push(("accept".to_string(), "*/*".to_string()));
        headers.push(("accept-language".to_string(), "en-US,en;q=0.9".to_string()));
        headers.push((
            "sec-fetch-dest".to_string(),
            if request.source == "script" { "script".to_string() } else { "empty".to_string() },
        ));
        headers.push((
            "sec-fetch-mode".to_string(),
            if request.source == "script" { "no-cors".to_string() } else { "cors".to_string() },
        ));
        headers.push((
            "sec-fetch-site".to_string(),
            if cross { "cross-site".to_string() } else { "same-origin".to_string() },
        ));
        headers.push(("user-agent".to_string(), self.user_agent.clone()));

        if cross || method != "GET" {
            headers.push(("origin".to_string(), self.origin.clone()));
        }
        headers.push((
            "referer".to_string(),
            if cross { format!("{}/", self.origin) } else { self.page_url.clone() },
        ));

        for (name, value) in &request.headers {
            headers.retain(|(known, _)| !known.eq_ignore_ascii_case(name));
            headers.push((name.clone(), value.clone()));
        }

        let body = request.bytes();
        let mut outgoing = FetchRequest {
            url: request.url.clone(),
            method: method.clone(),
            headers,
            body,
            fingerprint: None,
            order: Vec::new(),
        };
        outgoing.order = NAV_ORDER.iter().map(|name| name.to_string()).collect();

        let answer = match self.http.fetch(outgoing) {
            Ok(response) => {
                for line in response.set_cookies() {
                    let _ = self.jar.add(&response.url, line);
                }
                Answer {
                    status: response.status,
                    body: response.text(),
                    headers: response
                        .headers
                        .iter()
                        .filter(|(name, _)| !name.eq_ignore_ascii_case("set-cookie"))
                        .cloned()
                        .collect(),
                    paced: 0.0,
                }
            }
            Err(_) => Answer { status: 0, body: String::new(), headers: Vec::new(), paced: 0.0 },
        };

        self.requests
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(Seen {
                method,
                url: request.url.clone(),
                status: answer.status,
                req_body: String::from_utf8_lossy(request.bytes().as_deref().unwrap_or(&[]))
                    .into_owned(),
                resp_body: answer.body.clone(),
            });

        answer
    }
}

impl Transport for Live {
    fn send(&self, request: &Request) -> Answer {
        Live::send(self, request)
    }

    fn start(&self, _request: &Request) -> Option<u64> {
        // Synchronous completion: the browser falls back to send() when no
        // answer is parked, so one blocking request path is enough.
        None
    }

    fn take(&self, _ticket: u64) -> Option<Answer> {
        // The browser falls back to the synchronous path when no answer is
        // parked, so returning None keeps a single, blocking request path.
        None
    }
}

fn same_origin(origin: &str, url: &str) -> bool {
    match (Url::parse(origin), Url::parse(url)) {
        (Ok(a), Ok(b)) => a.host_str() == b.host_str(),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Cookies
// ---------------------------------------------------------------------------

#[derive(Default)]
struct HeldCookies {
    values: Mutex<Vec<(String, String)>>,
}

impl CookieStore for HeldCookies {
    fn read(&self) -> String {
        self.values
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ")
    }

    fn write(&self, assignment: &str) {
        let head = assignment.split(';').next().unwrap_or_default().trim();
        let Some((name, value)) = head.split_once('=') else {
            return;
        };

        let mut values = self.values.lock().unwrap_or_else(|error| error.into_inner());
        match values.iter_mut().find(|(known, _)| known == name.trim()) {
            Some(entry) => entry.1 = value.to_string(),
            None => values.push((name.trim().to_string(), value.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// The page + the prelude the realm runs
// ---------------------------------------------------------------------------

fn minimal_html(sitekey: &str) -> String {
    format!(
        "<!doctype html><html><head><title>Capital.com</title>\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
<script>void 0;</script>\
</head><body><div id=\"root\"></div></body></html>"
    )
}

/// The vendor loader uses a handful of DOM calls the shim does not carry out of
/// the box. This is the smallest set that lets it run to the end of its IIFE,
/// where it inserts the real build as a script the sandbox will fetch.
const POLYFILLS: &str = r#"(function () {
  function prepend(node) {
    if (!node) throw new TypeError("prepend target is null");
    for (var index = arguments.length - 1; index >= 1; index -= 1) {
      var child = arguments[index];
      if (child && child.nodeType === 1) {
        this.insertBefore(child, this.firstChild || null);
      }
    }
  }
  if (!Node.prototype.prepend) Node.prototype.prepend = prepend;
  if (!Element.prototype.prepend) Element.prototype.prepend = prepend;
  if (!Document.prototype.prepend) Document.prototype.prepend = prepend;

  function append(node) {
    if (!node) throw new TypeError("append target is null");
    for (var index = 1; index < arguments.length; index += 1) {
      var child = arguments[index];
      if (child && child.nodeType === 1) this.appendChild(child);
      else if (typeof child === "string") this.appendChild(document.createTextNode(child));
    }
  }
  if (!Node.prototype.append) Node.prototype.append = append;
  if (!Element.prototype.append) Element.prototype.append = append;
  if (!Document.prototype.append) Document.prototype.append = append;

  if (!Node.prototype.before) Node.prototype.before = function () {};
  if (!Node.prototype.after) Node.prototype.after = function () {};
  if (!Node.prototype.replaceChildren) {
    Node.prototype.replaceChildren = function () {
      while (this.firstChild) this.removeChild(this.firstChild);
      for (var index = 0; index < arguments.length; index += 1) {
        if (arguments[index] && arguments[index].nodeType === 1) this.appendChild(arguments[index]);
      }
    };
  }

  try {
    if (!window.navigator.cookieDeprecationLabel) {
      Object.defineProperty(window.navigator, "cookieDeprecationLabel", {
        configurable: true,
        value: { getValue: function () { return Promise.resolve("none"); } },
      });
    }
  } catch (error) {}

  if (typeof window.MessageChannel === "undefined") {
    var _mcPorts = [];
    function _mcDeliver(port) {
      var queue = port._queue.slice();
      port._queue = [];
      for (var index = 0; index < queue.length; index += 1) {
        if (typeof port.onmessage === "function") {
          try { port.onmessage({ data: queue[index], target: port }); } catch (error) {}
        }
      }
    }
    function _mcPump() {
      for (var index = 0; index < _mcPorts.length; index += 1) _mcDeliver(_mcPorts[index]);
      return _mcPorts.length;
    }
    window.__mcPump = _mcPump;

    function _mcPort(name) {
      this._name = name;
      this._peer = null;
      this._queue = [];
      this._started = true;
      this.onmessage = null;
      _mcPorts.push(this);
    }
    _mcPort.prototype.postMessage = function (data) {
      var peer = this._peer;
      if (!peer) return;
      peer._queue.push(data);
    };
    _mcPort.prototype.start = function () { this._started = true; };
    _mcPort.prototype.close = function () {
      var index = _mcPorts.indexOf(this);
      if (index >= 0) _mcPorts.splice(index, 1);
    };
    _mcPort.prototype.addEventListener = function (type, handler) {
      if (type === "message") this.onmessage = handler;
    };
    _mcPort.prototype.removeEventListener = function (type) {
      if (type === "message") this.onmessage = null;
    };
    window.MessageChannel = function () {
      var a = new _mcPort("a");
      var b = new _mcPort("b");
      a._peer = b;
      b._peer = a;
      this.port1 = a;
      this.port2 = b;
    };
  }

  var state = { status: "idle", token: "", err: "", at: 0 };
  window.__recapState = state;

  window.__recapCall = function (sitekey, action) {
    state.status = "loading";
    state.token = "";
    state.err = "";
    state.at = Date.now();
    var enterprise = window.grecaptcha && window.grecaptcha.enterprise;
    if (!enterprise) {
      state.status = "err";
      state.err = "grecaptcha.enterprise is not installed";
      return;
    }
    enterprise.ready(function () {
      state.status = "ready";
      var pending;
      try {
        pending = enterprise.execute(sitekey, { action: action });
      } catch (error) {
        state.status = "err";
        state.err = String((error && error.message) || error);
        return;
      }
      Promise.resolve(pending).then(function (token) {
        state.token = token || "";
        state.status = state.token ? "done" : "empty";
        state.at = Date.now();
      })["catch"](function (error) {
        state.status = "err";
        state.err = String((error && error.message) || error);
      });
    });
  };
})();"#;
