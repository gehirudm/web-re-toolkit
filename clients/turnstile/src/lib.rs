pub mod session;

use std::sync::Arc;

use serde::Deserialize;
use serde_json::{Value, json};

use wre_client::client::{Client, Registration};
use wre_client::context::{Call, Ctx, HttpOptions, Jar};
use wre_client::error::{ClientError, ClientResult};
use wre_client::shape::{Shape, field};
use wre_client::spec::{Capabilities, ClientDescriptor, Concurrency, EventSpec, OpSpec};
use wre_sandbox::graph::{GraphLibrary, GraphProfile};

use session::{Session, Settings};

pub const ID: &str = "turnstile";

const DEFAULT_SITEKEY: &str = "0x4AAAAAAA__j7xDja6A1wAs";

const NOTES: &str = r#"## How a run works

`solve` fetches the widget document the loader would embed, mounts a graph
profile over it, runs the page's one inline script unmodified in the sandbox,
and hands the widget the same `extraParams` message the loader would post. The
widget then drives its own `/fo/` protocol through the session's transport and
posts the minted token up to the embedder, where it is captured.

The token is bound to the `action` you ask for and to the exit the requests left
from, so the mint must go through the same proxy your replay will use. Pass
`sitekey`, `action` and `page_url` to match the site you are minting for.

## What it is not

This does not implement Turnstile. It runs Cloudflare's own widget and harvests
what it produces. Cloudflare changes that script whenever it likes; when the
mint breaks, re-capture, do not fork the protocol.

## Sessions

One session is one jar, one realm and one transport fingerprint. Open one,
`solve`, then send your own request through the same session so the token, the
cookies and the fingerprint stay coherent."#;

pub fn registration() -> Registration {
    Registration {
        id: ID,
        describe,
        build,
    }
}

pub fn describe() -> ClientDescriptor {
    ClientDescriptor::new(ID, env!("CARGO_PKG_VERSION"))
        .summary("Runs a Cloudflare Turnstile widget headlessly and carries the token it mints")
        .primary("solve")
        .notes(NOTES)
        .capabilities(Capabilities {
            needs_v8: true,
            needs_chrome: false,
            needs_network: true,
            stateful: true,
            concurrency: Concurrency::PerSession,
            warmup_ms: 0,
        })
        .config(config_shape())
        .op(
            OpSpec::new(
                "info",
                Shape::object("InfoInput", []),
                Shape::object(
                    "Info",
                    [
                        field("target", Shape::Str),
                        field("version", Shape::Str),
                        field("profile", Shape::Str).summary("Graph profile this session mounts"),
                        field("profiles", Shape::list(Shape::Str))
                            .summary("Every graph profile id the workspace holds"),
                        field("sitekey", Shape::Str),
                        field("action", Shape::Str),
                        field("page_url", Shape::Str),
                        field("user_agent", Shape::Str),
                        field("fingerprint", Shape::Str)
                            .summary("Transport fingerprint, or where it is being derived from"),
                        field("open", Shape::Bool).summary("Whether a session is open"),
                    ],
                ),
            )
            .summary("What this build is carrying"),
        )
        .op(
            OpSpec::new(
                "solve",
                Shape::object(
                    "SolveInput",
                    [
                        field("sitekey", Shape::optional(Shape::Str))
                            .summary("Overrides sitekey from the config"),
                        field("action", Shape::optional(Shape::Str))
                            .summary("Turnstile action the token must be bound to"),
                        field("page_url", Shape::optional(Shape::Str))
                            .summary("Page the widget is embedded in, used as the referrer"),
                        field("wait_ms", Shape::optional(Shape::Int))
                            .summary("How long to let the widget run before giving up"),
                        field("console", Shape::Bool)
                            .summary("Include the widget's console and missed calls in the answer")
                            .with_default(json!(false)),
                        field("extra", Shape::optional(Shape::Json))
                            .summary("Fields merged over the generated extraParams payload"),
                    ],
                ),
                Shape::object(
                    "Solved",
                    [
                        field("token", Shape::optional(Shape::Str))
                            .summary("The minted turnstile token, if the widget produced one"),
                        field("has_token", Shape::Bool),
                        field("page", Shape::Json)
                            .summary("The widget document that was fetched"),
                        field("widget", Shape::Str).summary("Widget id this run generated"),
                        field("sitekey", Shape::Str),
                        field("action", Shape::Str),
                        field("script_bytes", Shape::Int),
                        field("messages", Shape::Json)
                            .summary("Everything the widget posted to the embedder"),
                        field("failed", Shape::Json)
                            .summary("The failure message, when the widget reported one"),
                        field("threw", Shape::Json).summary("What the inline script threw, if it did"),
                        field("sent", Shape::Json).summary("Every request the widget made"),
                        field("misses", Shape::list(Shape::Str))
                            .summary("Asked for and not answered by the graph"),
                        field("cookies", Shape::Json).summary("Jar after the mint"),
                        field("waited_ms", Shape::Int),
                        field("ms", Shape::Int),
                    ],
                ),
            )
            .summary("Mint a turnstile token for a sitekey and action")
            .deadline_ms(120_000),
        )
        .op(
            OpSpec::new(
                "reset",
                Shape::object(
                    "ResetInput",
                    [field("cookies", Shape::Bool)
                        .summary("Empty the jar as well")
                        .with_default(json!(false))],
                ),
                Shape::object("Reset", [field("ok", Shape::Bool)]),
            )
            .summary("Drop the realm and start a new session"),
        )
        .event(
            EventSpec::new(
                "progress",
                Shape::object(
                    "Progress",
                    [
                        field("done", Shape::Int),
                        field("total", Shape::Int),
                        field("note", Shape::Str),
                    ],
                ),
            )
            .summary("Where a solve has got to"),
        )
}

fn config_shape() -> Shape {
    Shape::object(
        "TurnstileConfig",
        [
            field("sitekey", Shape::Str)
                .summary("Turnstile sitekey to mint for")
                .with_default(json!(DEFAULT_SITEKEY)),
            field("action", Shape::Str)
                .summary("Turnstile action the token is bound to")
                .with_default(json!("login")),
            field("page_url", Shape::Str)
                .summary("Page the widget is embedded in, used as the referrer")
                .with_default(json!("https://spinquest.com/auth/login?mode=login")),
            field("proxy", Shape::optional(Shape::Str))
                .summary("Proxy url the session and the sandbox both go through, http or socks5"),
            field("profile", Shape::optional(Shape::Str))
                .summary("Sandbox profile id, from `wre sandbox list`"),
            field("random_profile", Shape::Bool)
                .summary("Pick a random captured profile instead of the named one")
                .with_default(json!(false)),
            field("fingerprint", Shape::optional(Shape::Str))
                .summary("Transport fingerprint as profile[:platform], defaults to the sandbox profile's user agent"),
            field("user_agent", Shape::optional(Shape::Str))
                .summary("Overrides the user agent the sandbox profile carries"),
            field("wait_ms", Shape::Int)
                .summary("How long to let the widget run before giving up on a token")
                .with_default(json!(25_000)),
            field("step_ms", Shape::Int)
                .summary("How often the timer queue is drained while the widget runs")
                .with_default(json!(100)),
            field("timeout_ms", Shape::Int)
                .summary("Cap on one http request the session makes")
                .with_default(json!(90_000)),
            field("frames", Shape::Int)
                .summary("Child realms opened up front for iframes the widget creates")
                .with_default(json!(4)),
            field("size", Shape::Str)
                .summary("Turnstile size, from the render params")
                .with_default(json!("flexible")),
            field("theme", Shape::Str)
                .summary("Turnstile theme, from the render params")
                .with_default(json!("auto")),
            field("lang", Shape::Str)
                .summary("Turnstile language, from the render params")
                .with_default(json!("auto")),
            field("seed", Shape::optional(Shape::Int)).summary("Seed the random source"),
        ],
    )
}

#[derive(Debug, Clone, Deserialize)]
struct Config {
    #[serde(default = "default_sitekey")]
    sitekey: String,
    #[serde(default = "default_action")]
    action: String,
    #[serde(default = "default_page")]
    page_url: String,
    #[serde(default)]
    proxy: Option<String>,
    #[serde(default)]
    profile: Option<String>,
    #[serde(default)]
    random_profile: bool,
    #[serde(default)]
    fingerprint: Option<String>,
    #[serde(default)]
    user_agent: Option<String>,
    #[serde(default = "default_wait")]
    wait_ms: u64,
    #[serde(default = "default_step")]
    step_ms: u64,
    #[serde(default = "default_timeout")]
    timeout_ms: u64,
    #[serde(default = "default_frames")]
    frames: usize,
    #[serde(default = "default_size")]
    size: String,
    #[serde(default = "default_theme")]
    theme: String,
    #[serde(default = "default_lang")]
    lang: String,
    #[serde(default)]
    seed: Option<u64>,
}

fn default_sitekey() -> String {
    DEFAULT_SITEKEY.to_string()
}

fn default_action() -> String {
    "login".to_string()
}

fn default_page() -> String {
    "https://spinquest.com/auth/login?mode=login".to_string()
}

fn default_wait() -> u64 {
    25_000
}

fn default_step() -> u64 {
    100
}

fn default_timeout() -> u64 {
    90_000
}

fn default_frames() -> usize {
    4
}

fn default_size() -> String {
    "flexible".to_string()
}

fn default_theme() -> String {
    "auto".to_string()
}

fn default_lang() -> String {
    "auto".to_string()
}

fn build(ctx: Ctx, config: Value) -> ClientResult<Box<dyn Client>> {
    let config: Config = serde_json::from_value(config)
        .map_err(|error| ClientError::bad_input(format!("config rejected: {error}")))?;

    let mut ctx = ctx;
    if let Some(seed) = config.seed {
        ctx = ctx.with_seed(seed);
    }

    ctx.fact("profile", json!(config.profile));
    ctx.fact("sitekey", json!(config.sitekey));
    ctx.fact("action", json!(config.action));

    Ok(Box::new(Turnstile {
        ctx,
        config,
        record: None,
        jar: Jar::new(),
        session: None,
    }))
}

fn resolve_profile(ctx: &Ctx, config: &Config) -> ClientResult<GraphProfile> {
    match ctx.workspace() {
        Some(workspace) => {
            let library = GraphLibrary::load(workspace.join("profiles").join("graph")).map_err(
                |error| ClientError::resource(format!("the profile library failed: {error}")),
            )?;

            library
                .resolve(config.profile.as_deref())
                .map_err(|error| ClientError::bad_input(error.to_string()))
        }
        None => GraphLibrary::default()
            .resolve(None)
            .map_err(|error| ClientError::bad_input(error.to_string())),
    }
}

struct Turnstile {
    ctx: Ctx,
    config: Config,
    record: Option<GraphProfile>,
    jar: Jar,
    session: Option<Session>,
}

impl Turnstile {
    fn record(&mut self) -> ClientResult<&GraphProfile> {
        if self.record.is_none() {
            let found = resolve_profile(&self.ctx, &self.config)?;
            self.ctx.fact("profile", json!(found.id));
            self.ctx.fact("user_agent", json!(found.user_agent));
            self.record = Some(found);
        }

        Ok(self.record.as_ref().expect("profile"))
    }

    fn user_agent(&self) -> String {
        self.config
            .user_agent
            .clone()
            .filter(|value| !value.is_empty())
            .or_else(|| self.record.as_ref().map(|found| found.user_agent.clone()))
            .unwrap_or_default()
    }

    fn profiles(&self) -> Vec<String> {
        match self.ctx.workspace() {
            Some(workspace) => GraphLibrary::load(workspace.join("profiles").join("graph"))
                .map(|library| library.ids())
                .unwrap_or_default(),
            None => Vec::new(),
        }
    }

    fn settings(&self) -> Settings {
        Settings {
            wait_ms: self.config.wait_ms,
            step_ms: self.config.step_ms,
            timeout_ms: self.config.timeout_ms,
            frames: self.config.frames,
            size: self.config.size.clone(),
            theme: self.config.theme.clone(),
            lang: self.config.lang.clone(),
        }
    }

    fn fresh(&mut self) -> ClientResult<Session> {
        if self.user_agent().is_empty() {
            self.record()?;
        }

        let profile = self.record.as_ref().map(|found| found.clone());
        let user_agent = self.user_agent();

        if user_agent.is_empty() {
            return Err(ClientError::bad_input(
                "the sandbox profile carries no user agent, set user_agent in the config",
            ));
        }

        let mut options = HttpOptions::with_proxy(self.config.proxy.as_deref());
        options.fingerprint = self.config.fingerprint.clone();
        options.user_agent = Some(user_agent.clone());
        options.timeout_secs = Some(self.config.timeout_ms.div_ceil(1000).max(1));
        options.jar = Some(self.jar.clone());

        let http = Arc::new(self.ctx.http_with(options)?);
        let id = self
            .record
            .as_ref()
            .map(|found| found.id.clone())
            .unwrap_or_default();

        Ok(Session::new(
            http,
            self.jar.clone(),
            profile,
            id,
            self.settings(),
            user_agent,
        ))
    }

    fn session(&mut self) -> ClientResult<&mut Session> {
        if self.session.is_none() {
            let session = self.fresh()?;
            self.session = Some(session);
        }

        Ok(self.session.as_mut().expect("session"))
    }

    fn input(&self, params: &Value) -> (String, String, String) {
        let sitekey = params
            .get("sitekey")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| self.config.sitekey.clone());

        let action = params
            .get("action")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| self.config.action.clone());

        let page_url = params
            .get("page_url")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| self.config.page_url.clone());

        (sitekey, action, page_url)
    }
}

impl Client for Turnstile {
    fn call(&mut self, op: &str, params: Value, call: &Call) -> ClientResult<Value> {
        call.check()?;

        match op {
            "info" => {
                let profiles = self.profiles();
                let chosen = self
                    .record
                    .as_ref()
                    .map(|found| found.id.clone())
                    .or_else(|| self.config.profile.clone())
                    .or_else(|| profiles.first().cloned())
                    .unwrap_or_default();

                Ok(json!({
                    "target": ID,
                    "version": env!("CARGO_PKG_VERSION"),
                    "profile": chosen,
                    "profiles": profiles,
                    "sitekey": self.config.sitekey,
                    "action": self.config.action,
                    "page_url": self.config.page_url,
                    "user_agent": self.user_agent(),
                    "fingerprint": self.config.fingerprint.clone().unwrap_or_else(|| "from user agent".to_string()),
                    "open": self.session.as_ref().map(Session::is_open).unwrap_or(false),
                }))
            }

            "solve" => {
                if let Some(wait) = params.get("wait_ms").and_then(Value::as_u64) {
                    self.config.wait_ms = wait;
                }

                let (sitekey, action, page_url) = self.input(&params);
                let widget_id = session::widget_id();

                call.progress(1, 4, "fetching the widget document");
                let mut session = self.fresh()?;

                if let Some(extra) = params.get("extra") {
                    session.set_extra(extra.clone());
                }

                let run = session.open(&sitekey, &action, &page_url, &widget_id);
                self.session = Some(session);
                let run = run?;
                call.progress(4, 4, "answered");

                let token = run
                    .get("token")
                    .and_then(Value::as_str)
                    .map(str::to_string);

                if token.is_none() {
                    let failed = run.get("failed").cloned().unwrap_or(Value::Null);
                    return Err(ClientError::blocked(
                        "the widget did not mint a token",
                    )
                    .with_detail(json!({ "run": run, "failed": failed })));
                }

                if params.get("console").and_then(Value::as_bool).unwrap_or(false) {
                    let session = self.session.as_mut().expect("session");
                    let console = session.console()?;
                    return Ok(json!({ "run": run, "console": console }));
                }

                Ok(run)
            }

            "reset" => {
                if let Some(session) = self.session.as_mut() {
                    session.close();
                }

                if params.get("cookies").and_then(Value::as_bool).unwrap_or(false) {
                    self.jar.clear();
                }

                self.session = None;
                Ok(json!({ "ok": true }))
            }

            other => Err(ClientError::unsupported(format!(
                "{ID} does not know the {other} op"
            ))),
        }
    }

    fn health(&mut self) -> ClientResult<Value> {
        Ok(json!({ "ok": true, "open": self.session.as_ref().map(Session::is_open).unwrap_or(false) }))
    }

    fn close(&mut self) -> ClientResult<()> {
        if let Some(session) = self.session.as_mut() {
            session.close();
        }

        self.session = None;
        Ok(())
    }
}
