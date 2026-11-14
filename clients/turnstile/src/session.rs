use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand::RngExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;

use wre_client::context::{FetchRequest, FetchResponse, Http, Jar};
use wre_client::error::{ClientError, ClientResult};
use wre_live::realm::RealmOptions;
use wre_sandbox::browser::{Answer, CookieStore, Hooks, Request, Transport};
use wre_sandbox::graph::{Graph, GraphPage, GraphProfile, open};

const CHALLENGE_HOST: &str = "challenges.cloudflare.com";
const LOADER_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";

const POOL_PROBE: &str = "(function(){var g=globalThis;var ks=[];try{for(var k in g){if(k.indexOf('__')===0||k.indexOf('wre')>=0)ks.push(k);}}catch(e){ks.push('ERR '+e.message);}return {pool:(g.__wreSparePool?g.__wreSparePool.length:-1),dbg:typeof g.__wrePoolDebug,count:typeof g.__wreFrameCount,view0:typeof g.__wreFrameView0,env:typeof g.__ENV,deliver:typeof g.__wreDeliver,page:typeof g.__wreGraphPage,pump:typeof g.__PUMP,keys:ks.slice(0,60)};})()";

const NAVIGATE: [(&str, &str); 7] = [
    ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"),
    ("accept-language", "en-US,en;q=0.9"),
    ("sec-fetch-dest", "document"),
    ("sec-fetch-mode", "navigate"),
    ("sec-fetch-site", "none"),
    ("sec-fetch-user", "?1"),
    ("upgrade-insecure-requests", "1"),
];

const CAPTURE: &str = r#"(function () {
  globalThis.__wreOut = [];
  globalThis.__wreSel = [];
  try {
    var record = function (message, targetOrigin) {
      try {
        var m = message || {};
        globalThis.__wreOut.push({
          event: m.event,
          token: typeof m.token === "string" ? m.token : undefined,
          widgetId: m.widgetId,
          source: m.source,
          trigger: m.trigger,
          origin: targetOrigin,
          raw: (function () { try { return JSON.stringify(m).slice(0, 900); } catch (e) { return null; } })()
        });
      } catch (e) {}
      return undefined;
    };
    globalThis.postMessage = record;
    try {
      if (globalThis.parent && globalThis.parent !== globalThis) {
        globalThis.parent.postMessage = record;
      }
    } catch (e) {}
  } catch (e) {}
  try {
    globalThis.__wreSel.push({ fn: "probe", arg: "tt=" + typeof globalThis.trustedTypes });
  } catch (e) {}
  try {
    var policy = function (name, rules) {
      rules = rules || {};
      var apply = function (kind, input) {
        var fn = rules[kind];
        try { return fn ? fn(String(input)) : String(input); } catch (e) { return String(input); }
      };
      return {
        name: String(name || ""),
        createHTML: function (input) { return apply("createHTML", input); },
        createScript: function (input) { return apply("createScript", input); },
        createScriptURL: function (input) { return apply("createScriptURL", input); },
        createURL: function (input) { return apply("createURL", input); }
      };
    };
    Object.defineProperty(globalThis, "trustedTypes", {
      value: {
        createPolicy: policy,
        getPolicyNames: function () { return []; },
        isHTML: function () { return true; },
        isScript: function () { return true; },
        isScriptURL: function () { return true; },
        isURL: function () { return true; }
      },
      writable: true,
      enumerable: true,
      configurable: true
    });
  } catch (e) {}
  try {
    if (!globalThis.self) {
      Object.defineProperty(globalThis, "self", { value: globalThis, writable: true, enumerable: true, configurable: true });
    }
  } catch (e) {}
  try {
    if (typeof globalThis.importScripts !== "function") {
      globalThis.importScripts = function () {};
    }
  } catch (e) {}
  try {
    var WorkerShim = function (url) {
      this.url = String(url || "");
      this.onmessage = null;
      this._listeners = [];
    };
    WorkerShim.prototype.addEventListener = function (type, handler) {
      if (type === "message") { this._listeners.push(handler); }
    };
    WorkerShim.prototype.removeEventListener = function () {};
    WorkerShim.prototype.terminate = function () {};
    WorkerShim.prototype.postMessage = function (data) {
      var worker = this;
      var deliver = function (payload) {
        var event = { data: payload, isTrusted: true, origin: "", source: null, lastEventId: "", ports: [] };
        try { if (typeof worker.onmessage === "function") { worker.onmessage(event); } } catch (e) {}
        for (var i = 0; i < worker._listeners.length; i += 1) { try { worker._listeners[i](event); } catch (e) {} }
      };
      try {
        var source = globalThis.__wreBlobs ? globalThis.__wreBlobs[worker.url] : null;
        if (typeof source === "string" && source) {
          var scope = { postMessage: deliver, eval: function (code) { return globalThis.eval(code); }, importScripts: function () {}, addEventListener: function () {}, location: globalThis.location };
          scope.self = scope;
          scope.globalThis = scope;
          var run = new Function("self", "with (self) { " + source + "\n }");
          run(scope);
        }
      } catch (e) {}
      deliver(data);
    };
    if (typeof globalThis.Worker !== "function") {
      globalThis.Worker = WorkerShim;
    }
  } catch (e) {}
  try {
    globalThis.__wreSel.push({
      fn: "typeof",
      arg: "self=" + typeof globalThis.self + " Worker=" + typeof globalThis.Worker + " selfEval=" + typeof (globalThis.self || {}).eval + " importScripts=" + typeof globalThis.importScripts
    });
  } catch (e) {}
  try {
    var wreFrame = document.createElement("iframe");
    try {
      Object.defineProperty(wreFrame, "contentWindow", { get: function () { return globalThis; }, configurable: true });
    } catch (e) {}
    Object.defineProperty(globalThis, "frameElement", { get: function () { return wreFrame; }, configurable: true });
  } catch (e) {}
  try {
    if (globalThis.URL && typeof globalThis.URL.createObjectURL === "function") {
      var realObjectUrl = globalThis.URL.createObjectURL;
      globalThis.URL.createObjectURL = function (blob) {
        var out;
        try {
          out = realObjectUrl.apply(this, arguments);
          var text = "";
          try { text = blob && typeof blob.__text === "string" ? blob.__text : ""; } catch (e) {}
          globalThis.__wreSel.push({ fn: "createObjectURL", arg: "->" + typeof out + " " + String(out).slice(0, 44) + " text=" + String(text).slice(0, 140) });
        } catch (e) {
          globalThis.__wreSel.push({ fn: "createObjectURL", arg: "ERR:" + (e && e.message) });
          out = undefined;
        }
        return out;
      };
    }
  } catch (e) {}
  try {
    var realCreateElement = document.createElement.bind(document);
    document.createElement = function (tag) {
      var name = String(tag).toLowerCase();
      if (name === "iframe" || name === "script" || name === "canvas" || name === "img" || name === "worker") {
        try { globalThis.__wreSel.push({ fn: "createElement", arg: name }); } catch (e) {}
      }
      return realCreateElement(tag);
    };
  } catch (e) {}
})()"#;

const INJECT_HEAD: &str = r#"(function () {
  var source = __SOURCE__;
  var head = document.head || document.getElementsByTagName("head")[0];
  if (!head) return "no head";
  var text = String(source || "");
  var paired = /<(style|title|script|textarea|noscript)\b([^>]*)>([\s\S]*?)<\/\1>/gi;
  var empty = /<(meta|link|base)\b([^>]*?)\/?>/gi;
  var attr = function (element, raw) {
    var re = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))/g;
    var found;
    while ((found = re.exec(raw || ""))) {
      var value = found[2] !== undefined ? found[2] : (found[3] !== undefined ? found[3] : found[4]);
      try { element.setAttribute(found[1], value); } catch (e) {}
    }
  };
  var made = 0;
  var match;
  while ((match = paired.exec(text))) {
    try {
      var element = document.createElement(match[1].toLowerCase());
      attr(element, match[2]);
      try { element.textContent = match[3]; } catch (e) {}
      try { element.innerText = match[3]; } catch (e) {}
      head.appendChild(element);
      made += 1;
    } catch (e) {}
  }
  while ((match = empty.exec(text))) {
    try {
      var node = document.createElement(match[1].toLowerCase());
      attr(node, match[2]);
      head.appendChild(node);
      made += 1;
    } catch (e) {}
  }
  return "made=" + made;
})()"#;

#[derive(Debug, Clone, Deserialize)]
pub struct Settings {
    #[serde(default = "default_wait")]
    pub wait_ms: u64,
    #[serde(default = "default_step")]
    pub step_ms: u64,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_frames")]
    pub frames: usize,
    #[serde(default = "default_size")]
    pub size: String,
    #[serde(default = "default_theme")]
    pub theme: String,
    #[serde(default = "default_lang")]
    pub lang: String,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            wait_ms: default_wait(),
            step_ms: default_step(),
            timeout_ms: default_timeout(),
            frames: default_frames(),
            size: default_size(),
            theme: default_theme(),
            lang: default_lang(),
        }
    }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sent {
    pub url: String,
    pub method: String,
    pub status: u16,
    pub bytes: usize,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reqbody: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resp: Option<String>,
}

struct Live {
    http: Arc<Http>,
    base: String,
    origin: String,
    referer: String,
    user_agent: String,
    per_url_origin: bool,
    sent: Mutex<Vec<Sent>>,
}

impl Live {
    fn absolute(&self, url: &str) -> Option<String> {
        let parsed = Url::parse(&self.base).ok()?;
        let joined = parsed.join(url).ok()?;
        match joined.scheme() {
            "http" | "https" => Some(joined.to_string()),
            _ => None,
        }
    }

    fn note(&self, sent: Sent) {
        if let Ok(mut log) = self.sent.lock() {
            log.push(sent);
        }
    }
}

impl Transport for Live {
    fn send(&self, request: &Request) -> Answer {
        let body = request.bytes();
        let Some(url) = self.absolute(&request.url) else {
            self.note(Sent {
                url: request.url.clone(),
                method: request.method.to_uppercase(),
                status: 0,
                bytes: body.as_ref().map(Vec::len).unwrap_or(0),
                source: request.source.clone(),
                blocked: Some("not an http url".to_string()),
                body: None,
                headers: None,
                reqbody: None,
                resp: None,
            });
            return Answer { status: 0, body: String::new(), headers: Vec::new(), paced: 0.0 };
        };

        let (origin, referer) = if self.per_url_origin {
            let host_origin = origin_of(&url);
            if host_origin.is_empty() {
                (self.origin.clone(), self.referer.clone())
            } else {
                let referer = format!("{host_origin}/");
                (host_origin, referer)
            }
        } else {
            (self.origin.clone(), self.referer.clone())
        };

        let mut headers: BTreeMap<String, String> = BTreeMap::new();
        headers.insert("accept".to_string(), "*/*".to_string());
        headers.insert("accept-language".to_string(), "en-US,en;q=0.9".to_string());
        headers.insert("origin".to_string(), origin);
        headers.insert("referer".to_string(), referer);
        headers.insert("sec-fetch-dest".to_string(), "empty".to_string());
        headers.insert("sec-fetch-mode".to_string(), "cors".to_string());
        headers.insert("sec-fetch-site".to_string(), "same-origin".to_string());
        headers.insert("user-agent".to_string(), self.user_agent.clone());
        if !std::env::var("SQ_NO_HINTS")
            .map(|v| v == "1" || v == "true")
            .unwrap_or(false)
        {
            for (name, value) in client_hints(&self.user_agent) {
                headers.insert(name, value);
            }
        }
        if body.is_some() {
            headers.insert("content-type".to_string(), "text/plain;charset=UTF-8".to_string());
        }
        for (name, value) in &request.headers {
            headers.insert(name.to_ascii_lowercase(), value.clone());
        }

        let reqbody_log = body
            .as_ref()
            .map(|bytes| String::from_utf8_lossy(bytes).chars().take(240).collect::<String>());

        let header_log = headers
            .iter()
            .map(|(name, value)| format!("{name}: {value}"))
            .collect::<Vec<_>>()
            .join(" | ");

        let outgoing = FetchRequest {
            url: url.clone(),
            method: request.method.to_uppercase(),
            headers: headers.into_iter().collect(),
            body: body.clone(),
            fingerprint: None,
            order: Vec::new(),
        };
        let answer = match self.http.fetch(outgoing) {
            Ok(response) => Answer {
                status: response.status,
                body: response.text(),
                headers: response
                    .headers
                    .iter()
                    .filter(|(name, _)| !name.eq_ignore_ascii_case("set-cookie"))
                    .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
                    .collect(),
                paced: 0.0,
            },
            Err(_) => Answer { status: 0, body: String::new(), headers: Vec::new(), paced: 0.0 },
        };

        if url.contains("/fo/") {
            let _ = std::fs::write("/tmp/wre_fo_resp.txt", &answer.body);
            let _ = std::fs::write("/tmp/wre_fo_url.txt", &url);
            static FO_N: std::sync::atomic::AtomicUsize =
                std::sync::atomic::AtomicUsize::new(0);
            let idx = FO_N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if let Some(b) = &body {
                let _ = std::fs::write(format!("/tmp/wre_fo_req_{idx}.txt"), b);
            }
            let _ = std::fs::write(format!("/tmp/wre_fo_resp_{idx}.txt"), &answer.body);
        }
        if url.contains("/rch/") {
            let _ = std::fs::write("/tmp/wre_rch.html", &answer.body);
            let _ = std::fs::write("/tmp/wre_rch_url.txt", &url);
        }
        if url.contains("/eb/") || url.contains("/ci/") {
            static EB_N: std::sync::atomic::AtomicUsize =
                std::sync::atomic::AtomicUsize::new(0);
            let idx = EB_N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if let Some(b) = &body {
                let _ = std::fs::write(format!("/tmp/wre_eb_{idx}.txt"), b);
            }
        }

        self.note(Sent {
            url,
            method: request.method.to_uppercase(),
            status: answer.status,
            bytes: answer.body.len(),
            source: request.source.clone(),
            blocked: None,
            body: if answer.status >= 400 {
                Some(answer.body.chars().take(400).collect())
            } else {
                None
            },
            headers: Some(header_log.chars().take(700).collect()),
            reqbody: reqbody_log,
            resp: if answer.status >= 400 {
                Some(
                    answer
                        .headers
                        .iter()
                        .map(|(name, value)| format!("{name}: {value}"))
                        .collect::<Vec<_>>()
                        .join(" | ")
                        .chars()
                        .take(700)
                        .collect(),
                )
            } else {
                None
            },
        });

        answer
    }
}

struct Cookies {
    jar: Jar,
    url: String,
}

impl CookieStore for Cookies {
    fn read(&self) -> String {
        self.jar.script_header(&self.url)
    }

    fn write(&self, assignment: &str) {
        let _ = self.jar.add(&self.url, assignment);
    }
}

pub fn client_hints(user_agent: &str) -> Vec<(String, String)> {
    let major = user_agent
        .split("Chrome/")
        .nth(1)
        .and_then(|rest| rest.split('.').next())
        .unwrap_or("151")
        .to_string();

    let platform = if user_agent.contains("Windows") {
        "Windows"
    } else if user_agent.contains("Android") {
        "Android"
    } else if user_agent.contains("Linux") {
        "Linux"
    } else {
        "macOS"
    };

    let mobile = if user_agent.contains("Mobile") { "?1" } else { "?0" };

    vec![
        (
            "sec-ch-ua".to_string(),
            format!("\"Not=A?Brand\";v=\"99\", \"Google Chrome\";v=\"{major}\", \"Chromium\";v=\"{major}\""),
        ),
        ("sec-ch-ua-mobile".to_string(), mobile.to_string()),
        ("sec-ch-ua-platform".to_string(), format!("\"{platform}\"")),
    ]
}

pub fn widget_id() -> String {
    const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut raw = [0u8; 5];
    rand::rng().fill(&mut raw[..]);
    raw.iter().map(|byte| ALPHABET[(*byte as usize) % ALPHABET.len()] as char).collect()
}

fn widget_url(widget_id: &str, sitekey: &str, settings: &Settings) -> String {
    format!(
        "https://{CHALLENGE_HOST}/cdn-cgi/challenge-platform/h/g/turnstile/f/av0/rch/{widget_id}/{sitekey}/{theme}/fbE/new/{size}?lang={lang}",
        theme = settings.theme,
        size = settings.size,
        lang = settings.lang
    )
}

pub struct Session {
    http: Arc<Http>,
    jar: Jar,
    profile: Option<GraphProfile>,
    profile_id: String,
    settings: Settings,
    user_agent: String,
    widget_url: String,
    page_url: String,
    html: String,
    status: u16,
    browser: Option<Graph>,
    transport: Option<Arc<Live>>,
    extra: Option<Value>,
    standalone: bool,
}

impl Session {
    pub fn new(
        http: Arc<Http>,
        jar: Jar,
        profile: Option<GraphProfile>,
        profile_id: String,
        settings: Settings,
        user_agent: String,
    ) -> Self {
        Session {
            http,
            jar,
            profile,
            profile_id,
            settings,
            user_agent,
            widget_url: String::new(),
            page_url: String::new(),
            html: String::new(),
            status: 0,
            browser: None,
            transport: None,
            extra: None,
            standalone: false,
        }
    }

    pub fn set_extra(&mut self, extra: Value) {
        self.extra = Some(extra);
    }

    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub fn is_open(&self) -> bool {
        self.browser.is_some()
    }

    pub fn jar(&self) -> &Jar {
        &self.jar
    }

    pub fn fetch(&self, request: FetchRequest) -> ClientResult<FetchResponse> {
        self.http.fetch(request)
    }

    fn fetch_widget(&mut self, widget_id: &str, sitekey: &str, page_url: &str) -> ClientResult<()> {
        let url = widget_url(widget_id, sitekey, &self.settings);
        let mut request = FetchRequest::get(&url).header("user-agent", self.user_agent.clone());
        request = request.header("referer", format!("{}/", origin_of(page_url)));
        for (name, value) in NAVIGATE {
            request = request.header(name, value);
        }
        for (name, value) in client_hints(&self.user_agent) {
            request = request.header(name, value);
        }

        let response = self.http.fetch(request)?;
        self.widget_url = if response.url.is_empty() { url } else { response.url.clone() };
        self.html = response.text();
        self.status = response.status;
        Ok(())
    }

    pub fn widget_html(&self) -> &str {
        &self.html
    }

    pub fn widget_response_url(&self) -> &str {
        &self.widget_url
    }

    pub fn page_url(&self) -> &str {
        &self.page_url
    }

    pub fn status(&self) -> u16 {
        self.status
    }

    fn widget_origin(&self) -> String {
        origin_of(&self.widget_url).if_empty(|| format!("https://{CHALLENGE_HOST}"))
    }

    fn extra_params(&self, action: &str, sitekey: &str, page_url: &str, widget_id: &str) -> Value {
        json!({
            "event": "extraParams",
            "source": "cloudflare-challenge",
            "widgetId": widget_id,
            "action": action,
            "sitekey": sitekey,
            "cData": Value::Null,
            "chlPageData": Value::Null,
            "cs": Value::Null,
            "scs": Value::Null,
            "ch": "4df4a60fa397",
            "appearance": "interaction-only",
            "execution": "execute",
            "language": self.settings.lang,
            "rcV": "",
            "url": page_url,
            "wPr": "",
            "retry": Value::Null,
            "expiry-interval": Value::Null,
            "refresh-expired": Value::Null,
            "refresh-timeout": Value::Null,
            "retry-interval": Value::Null,
            "timeExtraParamsMs": 12,
            "timeInitMs": 22,
            "timeParamsMs": 4,
            "timeRenderMs": 9,
            "timeLoadInitMs": 44,
            "timeTiefMs": 58,
            "upgradeAttempts": 0,
            "upgradeCompletedCount": 0,
            "apiJsMismatchReloadAttempts": 0,
            "apiJsMismatchReloadCompletedCount": 0
        })
    }

    fn mount(&mut self) -> ClientResult<()> {
        let origin = self.widget_origin();
        let transport = Arc::new(Live {
            http: Arc::clone(&self.http),
            base: self.widget_url.clone(),
            origin: origin.clone(),
            referer: format!("{origin}/"),
            user_agent: self.user_agent.clone(),
            per_url_origin: self.standalone,
            sent: Mutex::new(Vec::new()),
        });

        let hooks = Hooks {
            transport: Arc::clone(&transport) as Arc<dyn Transport>,
            cookies: Arc::new(Cookies { jar: self.jar.clone(), url: self.widget_url.clone() }),
        };

        let referrer = if self.standalone { String::new() } else { self.page_url.clone() };

        let page = GraphPage {
            url: self.widget_url.clone(),
            referrer,
            entries: self.timing_entries(),
            cookies: self.jar.script_header(&self.widget_url),
            frames: self.settings.frames,
            capture_cipher: false,
        };

        let options = RealmOptions {
            timeout: Duration::from_millis(self.settings.timeout_ms.max(1000)),
            timers: false,
            codecs: false,
            clock_ms: None,
            random_seed: None,
            heap_limit_mb: std::env::var("SQ_HEAP").ok().and_then(|value| value.parse::<usize>().ok()),
        };

        let profile = self
            .profile
            .as_ref()
            .ok_or_else(|| ClientError::resource("no graph profile is loaded, so there is nothing to mount"))?;

        let browser = open(profile, &page, hooks, options)
            .map_err(|error| ClientError::internal(format!("the sandbox did not open: {error}")))?;

        self.browser = Some(browser);
        self.transport = Some(transport);
        Ok(())
    }

    fn timing_entries(&self) -> Vec<Value> {
        vec![
            json!({
                "name": self.widget_url,
                "entryType": "navigation",
                "startTime": 0,
                "duration": 1,
                "transferSize": self.html.len() + 300,
                "encodedBodySize": self.html.len(),
                "decodedBodySize": self.html.len()
            }),
            json!({
                "name": "visibility-state",
                "entryType": "visibility-state",
                "startTime": 0,
                "duration": 0
            }),
        ]
    }

    fn browser_mut(&mut self) -> ClientResult<&mut Graph> {
        self.browser
            .as_mut()
            .ok_or_else(|| ClientError::internal("the sandbox is not mounted"))
    }

    fn inline_script(&self) -> ClientResult<String> {
        let html = &self.html;
        let open_tag = html
            .find("<script")
            .ok_or_else(|| ClientError::internal("the widget page carries no script"))?;
        let body_start = html[open_tag..]
            .find('>')
            .map(|offset| open_tag + offset + 1)
            .ok_or_else(|| ClientError::internal("the widget script tag is malformed"))?;
        let close_tag = html[body_start..]
            .find("</script>")
            .map(|offset| body_start + offset)
            .ok_or_else(|| ClientError::internal("the widget script is unterminated"))?;

        Ok(html[body_start..close_tag].trim().to_string())
    }

    fn head_markup(&self) -> String {
        let lower = self.html.to_ascii_lowercase();
        let Some(open) = lower.find("<head") else {
            return String::new();
        };
        let Some(start) = lower[open..].find('>').map(|offset| open + offset + 1) else {
            return String::new();
        };
        let Some(end) = lower[start..].find("</head>").map(|offset| start + offset) else {
            return String::new();
        };
        self.html[start..end].to_string()
    }

    fn inject_head(&mut self) -> ClientResult<()> {
        let markup = self.head_markup();
        if markup.is_empty() {
            return Ok(());
        }
        let encoded = serde_json::to_string(&markup).unwrap_or_else(|_| "\"\"".to_string());
        let js = INJECT_HEAD.replace("__SOURCE__", &encoded);
        let _ = self.eval_one(&js);
        Ok(())
    }

    fn fetch_asset(&self, url: &str, referer: &str) -> ClientResult<FetchResponse> {
        let mut request = FetchRequest::get(url).header("user-agent", self.user_agent.clone());
        request = request.header("referer", referer.to_string());
        for (name, value) in NAVIGATE {
            request = request.header(name, value);
        }
        for (name, value) in client_hints(&self.user_agent) {
            request = request.header(name, value);
        }
        self.http.fetch(request)
    }

    fn open_loader(
        &mut self,
        sitekey: &str,
        action: &str,
        page_url: &str,
        _widget_id: &str,
    ) -> ClientResult<Value> {
        let started = Instant::now();
        self.page_url = page_url.to_string();

        let api = self.fetch_asset(LOADER_URL, &format!("{}/", origin_of(page_url)))?;
        let api_url = if api.url.is_empty() { LOADER_URL.to_string() } else { api.url.clone() };
        let api_js = api.text();
        let api_bytes = api_js.len();
        let api_status = api.status;

        self.widget_url = page_url.to_string();
        self.html = String::new();
        self.status = 0;
        self.standalone = true;

        self.mount()?;

        let pool_before = self
            .browser_mut()
            .ok()
            .and_then(|b| b.read(POOL_PROBE).ok())
            .unwrap_or(Value::Null);

        self.browser_mut()?
            .eval(CAPTURE, "turnstile:capture")
            .map_err(|error| ClientError::internal(format!("the capture hook failed: {error}")))?;

        self.browser_mut()?.eval(
            "(function(){globalThis.__wreIn=[];try{globalThis.addEventListener('message',function(e){try{var d=e&&e.data;globalThis.__wreIn.push({event:d&&typeof d==='object'?d.event:null,source:d&&typeof d==='object'?d.source:null,widgetId:d&&typeof d==='object'?d.widgetId:null,kind:typeof d,origin:String(e&&e.origin),trusted:!!(e&&e.isTrusted)});}catch(x){}});}catch(x){}})();",
            "turnstile:inbox",
        )?;

        let name = api_url.clone();
        let threw = match self.browser_mut()?.run(&api_js, &name, false) {
            Ok(None) => Value::Null,
            Ok(Some(error)) => error,
            Err(error) => json!({ "message": error.to_string() }),
        };

        let setup = format!(
            r#"(function(){{
  var out = {{ turnstile: typeof globalThis.turnstile }};
  try {{
    var t = globalThis.turnstile;
    if (!t) {{ return out; }}
    out.keys = Object.keys(t).slice(0, 30);
    out.renderType = typeof t.render;
    var c = document.createElement('div');
    c.id = 'wre-cf';
    try {{ (document.body || document.documentElement).appendChild(c); }} catch (e) {{ out.appendErr = String(e && e.message); }}
    globalThis.__wreCb = {{ ok: 0, err: 0 }};
    try {{
      t.render(c, {{
        sitekey: {sitekey},
        action: {action},
        callback: function (tok) {{ globalThis.__wreCb.ok += 1; globalThis.__wreToken = tok; }},
        'error-callback': function (e) {{ globalThis.__wreCb.err += 1; globalThis.__wreErr = String(e); }}
      }});
    }} catch (e) {{ out.renderErr = String(e && e.message); }}
    try {{ out.iframes = document.getElementsByTagName('iframe').length; }} catch (e) {{}}
  }} catch (e) {{ out.err = String(e && e.message); }}
  return out;
}})()"#,
            sitekey = serde_json::to_string(sitekey).unwrap_or_else(|_| "\"\"".to_string()),
            action = serde_json::to_string(action).unwrap_or_else(|_| "\"\"".to_string()),
        );

        let setup_out = self
            .browser_mut()?
            .read(&setup)
            .unwrap_or(Value::Null);

        let deadline = Instant::now() + Duration::from_millis(self.settings.wait_ms as u64);
        while Instant::now() < deadline {
            let _ = self.pump();
            let done = self
                .browser_mut()
                .ok()
                .and_then(|b| b.read("(function(){return !!(globalThis.__wreToken|| (globalThis.__wreCb&&(globalThis.__wreCb.ok||globalThis.__wreCb.err)));})()").ok())
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if done {
                break;
            }
            std::thread::sleep(Duration::from_millis(self.settings.step_ms.max(1) as u64));
        }

        let probe = self
            .browser_mut()?
            .read(
                "(function(){var out={cb:globalThis.__wreCb||null,token:typeof globalThis.__wreToken,value:(typeof globalThis.__wreToken==='string'?globalThis.__wreToken.slice(0,24):null),err:globalThis.__wreErr||null,turnstile:typeof globalThis.turnstile};try{out.iframes=document.getElementsByTagName('iframe').length}catch(e){out.iframes=-1}try{out.elements=document.getElementsByTagName('script').length}catch(e){}return out;})()",
            )
            .unwrap_or(Value::Null);

        let pool = self
            .browser_mut()
            .ok()
            .and_then(|b| b.read(POOL_PROBE).ok())
            .unwrap_or(Value::Null);

        let token = self
            .browser_mut()
            .ok()
            .and_then(|b| b.read("(typeof globalThis.__wreToken==='string'?globalThis.__wreToken:'')").ok())
            .and_then(|v| v.as_str().map(str::to_string))
            .filter(|value| !value.is_empty());

        let inbox = self
            .browser_mut()
            .ok()
            .and_then(|b| b.read("JSON.stringify((globalThis.__wreIn||[]).slice(0,80))").ok())
            .and_then(|v| v.as_str().map(str::to_string));

        Ok(json!({
            "loader": true,
            "api": { "url": api_url, "status": api_status, "bytes": api_bytes },
            "profile": self.profile_id,
            "threw": threw,
            "setup": setup_out,
            "probe": probe,
            "pool_before": pool_before,
            "pool": pool,
            "inbox": inbox,
            "token": token,
            "ms": started.elapsed().as_millis() as u64,
            "log": self.log_all(),
            "log_len": self
                .browser_mut()
                .ok()
                .and_then(|b| b.read("(globalThis.__wreLOG||[]).length").ok()),
            "log2": self
                .browser_mut()
                .ok()
                .and_then(|b| b.read("JSON.stringify((globalThis.__wreLOG||[]).slice(-1200))").ok())
                .and_then(|v| v.as_str().map(str::to_string)),
            "misses": self.misses(),
            "sent": self.sent(),
        }))
    }

    pub fn open(
        &mut self,
        sitekey: &str,
        action: &str,
        page_url: &str,
        widget_id: &str,
    ) -> ClientResult<Value> {
        self.page_url = page_url.to_string();
        let started = Instant::now();

        if std::env::var("SQ_LOADER").map(|value| value == "1" || value == "true").unwrap_or(false) {
            return self.open_loader(sitekey, action, page_url, widget_id);
        }

        self.fetch_widget(widget_id, sitekey, page_url)?;
        let script = self.inline_script()?;
        let script_bytes = script.len();

        if let Ok(path) = std::env::var("SQ_DUMP") {
            let _ = std::fs::write(format!("{path}.html"), &self.html);
            let _ = std::fs::write(format!("{path}.script.js"), &script);
        }

        self.mount()?;

        self.browser_mut()?
            .eval(CAPTURE, "turnstile:capture")
            .map_err(|error| ClientError::internal(format!("the capture hook failed: {error}")))?;

        self.inject_head()?;

        let name = self.widget_url.clone();
        let threw = match self.browser_mut()?.run(&script, &name, true) {
            Ok(None) => Value::Null,
            Ok(Some(error)) => error,
            Err(error) => json!({ "message": error.to_string() }),
        };

        let post = self.eval_one(
            "(globalThis.__wreOut||[]).length + '|' + typeof globalThis._cf_chl_opt + '|' + (globalThis._cf_chl_opt?Object.keys(globalThis._cf_chl_opt).length:-1) + '|' + typeof document.currentScript + '|' + String(document.readyState) + '|' + String((function(){try{return document.body&&document.body.innerHTML.length}catch(e){return -1}})())",
        );

        let mut params = self.extra_params(action, sitekey, page_url, widget_id);
        if let (Some(Value::Object(over)), Value::Object(base)) = (&self.extra, &mut params) {
            for (key, value) in over {
                base.insert(key.clone(), value.clone());
            }
        }

        let waited = self.settle(&params, widget_id)?;
        let messages = self.messages()?;

        let token = messages
            .iter()
            .rev()
            .find(|message| message.get("event").and_then(Value::as_str) == Some("success"))
            .and_then(|message| message.get("token"))
            .and_then(Value::as_str)
            .map(str::to_string);

        let failed = messages
            .iter()
            .find(|message| message.get("event").and_then(Value::as_str) == Some("fail"))
            .cloned();

        Ok(json!({
            "page": { "url": self.widget_url, "status": self.status, "bytes": self.html.len() },
            "profile": self.profile_id,
            "widget": widget_id,
            "sitekey": sitekey,
            "action": action,
            "script_bytes": script_bytes,
            "post": post,
            "token": token,
            "failed": failed,
            "has_token": token.is_some(),
            "threw": threw,
            "waited_ms": waited,
            "ms": started.elapsed().as_millis() as u64,
            "messages": messages,
            "log": self.log_all(),
            "sent": self.sent(),
            "misses": self.misses(),
            "selectors": self.selectors(),
            "cookies": self.cookie_pairs(),
        }))
    }

    fn settle(&mut self, params: &Value, widget_id: &str) -> ClientResult<u64> {
        let started = Instant::now();
        let deadline = started + Duration::from_millis(self.settings.wait_ms);
        let mut served = 0usize;
        let mut acked = false;
        let mut executed = false;

        loop {
            self.pump()?;

            let messages = self.messages()?;

            if !acked {
                if let Some(init) = messages
                    .iter()
                    .find(|message| message.get("event").and_then(Value::as_str) == Some("init"))
                {
                    if let (Some(rcv), Value::Object(base)) = (init.get("nextRcV").and_then(Value::as_str), params) {
                        let _ = (rcv, base);
                    }
                    self.deliver(
                        json!({ "event": "init", "source": "cloudflare-challenge", "widgetId": widget_id }),
                        "turnstile:init",
                    )?;
                    acked = true;
                }
            }

            let asked = messages
                .iter()
                .filter(|message| message.get("event").and_then(Value::as_str) == Some("requestExtraParams"))
                .count();

            while served < asked {
                self.post_params(params)?;
                served += 1;
            }

        if served > 0 && !executed {
            if !std::env::var("SQ_NO_EXECUTE").map(|v| v == "1" || v == "true").unwrap_or(false) {
                self.deliver(
                    json!({
                        "event": "execute",
                        "source": "cloudflare-challenge",
                        "widgetId": widget_id
                    }),
                    "turnstile:execute",
                )?;
            }
            executed = true;
        }

            if decided(&messages) {
                break;
            }

            if Instant::now() >= deadline {
                break;
            }

            std::thread::sleep(Duration::from_millis(self.settings.step_ms));
        }

        for _ in 0..8 {
            self.pump()?;
        }

        Ok(started.elapsed().as_millis() as u64)
    }

    fn post_params(&mut self, params: &Value) -> ClientResult<()> {
        self.deliver(params.clone(), "turnstile:params")
    }

    fn deliver(&mut self, data: Value, name: &str) -> ClientResult<()> {
        let origin = std::env::var("SQ_DELIVER_ORIGIN").unwrap_or_else(|_| origin_of(&self.page_url));
        let payload = if std::env::var("SQ_DELIVER_RAW").map(|value| value == "1" || value == "true").unwrap_or(false) {
            json!(serde_json::to_string(&data).unwrap_or_default())
        } else {
            data
        };
        let encoded = serde_json::to_string(&payload).unwrap_or_else(|_| "null".to_string());

        let js = format!(
            r#"(function () {{
  var data = {encoded};
  try {{
    var deliver = globalThis.__wreDeliver;
    if (typeof deliver === "function") {{
      deliver(data, "{origin}", globalThis.parent);
    }} else {{
      globalThis.postMessage(data, "*");
    }}
  }} catch (e) {{}}
}})()"#
        );

        self.browser_mut()?
            .eval(&js, name)
            .map_err(|error| ClientError::internal(format!("{name} failed: {error}")))?;
        Ok(())
    }

    fn messages(&mut self) -> ClientResult<Vec<Value>> {
        let value = self
            .browser_mut()?
            .read("globalThis.__wreOut")
            .map_err(|error| ClientError::internal(format!("the messages could not be read: {error}")))?;
        Ok(value.as_array().cloned().unwrap_or_default())
    }

    fn read_global(&mut self, expression: &str) -> Vec<Value> {
        match self.browser.as_mut() {
            Some(browser) => match browser.read(expression) {
                Ok(value) => value.as_array().cloned().unwrap_or_default(),
                Err(_) => Vec::new(),
            },
            None => Vec::new(),
        }
    }

    fn eval_one(&mut self, expression: &str) -> Value {
        match self.browser.as_mut() {
            Some(browser) => match browser.eval(expression, "turnstile:eval") {
                Ok(()) => Value::Null,
                Err(_) => Value::Null,
            },
            None => Value::Null,
        }
    }

    fn selectors(&mut self) -> Vec<Value> {
        self.read_global("globalThis.__wreSel")
    }

    pub fn log_all(&mut self) -> Vec<Value> {
        match self.browser.as_mut() {
            Some(browser) => browser.log().ok().and_then(|value| value.as_array().cloned()).unwrap_or_default(),
            None => Vec::new(),
        }
    }

    pub fn pump(&mut self) -> ClientResult<usize> {
        let browser = self.browser_mut()?;
        let mut drained = browser.step().map_err(|error| ClientError::internal(error.to_string()))?;
        self.sync_cookies();
        if drained == 0 {
            drained = 0;
        }
        Ok(drained)
    }

    fn sync_cookies(&mut self) {
        let pairs = match self.browser.as_mut() {
            Some(browser) => browser.cookies().ok(),
            None => None,
        };
        if let Some(header) = pairs {
            for part in header.split(';') {
                let trimmed = part.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let _ = self.jar.add(&self.widget_url, trimmed);
            }
        }
    }

    pub fn cookie_pairs(&self) -> Vec<Value> {
        self.jar
            .matching(&self.widget_url)
            .into_iter()
            .map(|cookie| json!({ "name": cookie.name, "value": cookie.value }))
            .collect()
    }

    pub fn sent(&self) -> Vec<Sent> {
        match &self.transport {
            Some(transport) => transport.sent.lock().map(|log| log.clone()).unwrap_or_default(),
            None => Vec::new(),
        }
    }

    pub fn misses(&mut self) -> Vec<String> {
        match self.browser.as_mut() {
            Some(browser) => browser.misses(),
            None => Vec::new(),
        }
    }

    pub fn console(&mut self) -> ClientResult<Vec<Value>> {
        let entries = self
            .log_all()
            .into_iter()
            .filter(|entry| {
                matches!(
                    entry.get("kind").and_then(Value::as_str),
                    Some("console") | Some("miss") | Some("listenerError")
                )
            })
            .collect();
        Ok(entries)
    }

    pub fn close(&mut self) {
        self.browser = None;
        self.transport = None;
    }
}

fn decided(messages: &[Value]) -> bool {
    messages.iter().any(|message| {
        matches!(message.get("event").and_then(Value::as_str), Some("success") | Some("fail"))
    })
}

fn origin_of(url: &str) -> String {
    match Url::parse(url) {
        Ok(parsed) => format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or_default()),
        Err(_) => String::new(),
    }
}

trait IfEmpty {
    fn if_empty(self, fallback: impl FnOnce() -> String) -> String;
}

impl IfEmpty for String {
    fn if_empty(self, fallback: impl FnOnce() -> String) -> String {
        if self.is_empty() { fallback() } else { self }
    }
}
