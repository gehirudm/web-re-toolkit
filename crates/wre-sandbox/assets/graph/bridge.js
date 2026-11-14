(function () {
  var hostNow = __wreGraphNow;
  var hostEntropy = __wreGraphEntropy;
  var hostUuid = __wreGraphUuid;
  var hostDigest = __wreGraphDigest;
  var hostEntries = __wreGraphEntries;
  var hostPage = __wreGraphPage;
  var hostMedia = __wreGraphMedia;
  var hostSend = __wreGraphSend;
  var hostMiss = __wreGraphMiss;

  var page = hostPage();
  var timers = [];
  var deferred = [];
  var MAX_DELAY = 5000;

  var spare = globalThis.__wreSpare || [];
  var frames = new Map();

  delete globalThis.__wreSpare;
  globalThis.__wreSparePool = spare;

  (function () {
    var count = globalThis.__wreFrameCount || 0;
    delete globalThis.__wreFrameCount;

    for (var index = 0; index < count; index += 1) {
      var view = globalThis["__wreFrameView" + index];
      var env = globalThis["__wreFrameEnv" + index];
      var pump = globalThis["__wreFramePump" + index];

      delete globalThis["__wreFrameView" + index];
      delete globalThis["__wreFrameEnv" + index];
      delete globalThis["__wreFramePump" + index];

      if (!view || !env) continue;

      spare.push({ view: view, env: env, pump: pump });
    }
  })();

  globalThis.__wrePoolDebug = function () {
    return {
      pool: (globalThis.__wreSparePool || []).length,
      built: spare.length,
      frame: globalThis.__FRAME ? 1 : 0,
      view0: typeof globalThis.__wreFrameView0 !== "undefined",
    };
  };

  var schedule = function (id, delay, extra) {
    var wait = typeof delay === "number" && isFinite(delay) ? delay : 0;
    if (wait < 0) wait = 0;
    if (wait > MAX_DELAY) wait = MAX_DELAY;
    timers.push({ id: id, due: hostNow() + wait, extra: extra || [] });
  };

  var unschedule = function (id) {
    for (var index = 0; index < timers.length; index += 1) {
      if (timers[index].id === id) {
        timers.splice(index, 1);
        return;
      }
    }
  };

  var due = function () {
    var now = hostNow();
    var ready = [];
    var kept = [];

    for (var index = 0; index < timers.length; index += 1) {
      if (timers[index].due <= now) ready.push(timers[index]);
      else kept.push(timers[index]);
    }

    timers = kept;
    ready.sort(function (left, right) { return left.due - right.due; });
    return ready;
  };

  var BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  var toBase64 = function (bytes) {
    var out = "";

    for (var index = 0; index < bytes.length; index += 3) {
      var first = bytes[index];
      var second = index + 1 < bytes.length ? bytes[index + 1] : 0;
      var third = index + 2 < bytes.length ? bytes[index + 2] : 0;
      var word = (first << 16) | (second << 8) | third;

      out += BASE64.charAt((word >> 18) & 63);
      out += BASE64.charAt((word >> 12) & 63);
      out += index + 1 < bytes.length ? BASE64.charAt((word >> 6) & 63) : "=";
      out += index + 2 < bytes.length ? BASE64.charAt(word & 63) : "=";
    }

    return out;
  };

  var fromBase64 = function (text) {
    var clean = String(text).replace(/[^A-Za-z0-9+/]/g, "");
    var bytes = [];
    var held = 0;
    var bits = 0;

    for (var index = 0; index < clean.length; index += 1) {
      held = (held << 6) | BASE64.indexOf(clean.charAt(index));
      bits += 6;

      if (bits >= 8) {
        bits -= 8;
        bytes.push((held >> bits) & 255);
      }
    }

    return bytes;
  };

  var hexOf = function (bytes) {
    var digits = "0123456789abcdef";
    var out = "";
    for (var index = 0; index < bytes.length; index += 1) {
      out += digits.charAt(bytes[index] >> 4) + digits.charAt(bytes[index] & 15);
    }
    return out;
  };

  var bytesOfHex = function (hex) {
    var out = [];
    for (var index = 0; index + 1 < hex.length; index += 2) {
      out.push(parseInt(hex.slice(index, index + 2), 16));
    }
    return out;
  };

  var bodyOf = function (body) {
    if (body === null || body === undefined) return null;
    if (typeof body === "string") return { text: body };

    if (body instanceof ArrayBuffer) return { bytes: toBase64(new Uint8Array(body)) };
    if (ArrayBuffer.isView(body)) {
      return { bytes: toBase64(new Uint8Array(body.buffer, body.byteOffset, body.byteLength)) };
    }

    return { text: String(body) };
  };

  var sources = globalThis.__SOURCES || new WeakMap();
  delete globalThis.__SOURCES;

  globalThis.__BRIDGE = {
    sources: sources,

    now: function () {
      return hostNow();
    },

    random: function (count) {
      return hexOf(fromBase64(hostEntropy(count)));
    },

    uuid: function () {
      return hostUuid();
    },

    digest: function (algorithm, hex) {
      var out = hostDigest(String(algorithm), toBase64(bytesOfHex(String(hex))));
      return out === null ? null : hexOf(fromBase64(out));
    },

    entries: function (type) {
      return hostEntries(String(type));
    },

    pageUrl: function () {
      return page.url;
    },

    referrer: function () {
      return page.referrer;
    },

    canPlayType: function (type) {
      return hostMedia(String(type));
    },

    schedule: schedule,
    unschedule: unschedule,

    request: function (method, url, headerJson, body, callback) {
      var carried = bodyOf(body);

      var headers = {};

      try {
        headers = JSON.parse(String(headerJson || "{}")) || {};
      } catch (error) {
        headers = {};
      }

      try {
        var _line = String(method || "GET") + " " + String(url || "");
        (globalThis.__REQS = globalThis.__REQS || []).push(_line);
        var _doc = globalThis.document;
        if (_doc) (_doc.__REQS = _doc.__REQS || []).push(_line);
      } catch (error) {}

      var answer = hostSend({
        method: String(method || "GET"),
        url: String(url || ""),
        headers: headers,
        body: carried && carried.text !== undefined ? carried.text : null,
        bodyBytes: carried && carried.bytes !== undefined ? carried.bytes : null
      });

      deferred.push([callback, answer]);
    },

    createFrame: function () {
      var pool = globalThis.__wreSparePool || spare;
      var held = pool.shift();

      if (!held) {
        hostMiss(
          "no spare child realm for an iframe (pool=" +
            (pool && pool.length) +
            ", frame=" +
            (globalThis.__FRAME ? 1 : 0) +
            ")",
        );
        return null;
      }

      frames.set(held.view, held);
      return held.view;
    },

    runInFrame: function (view, source, name, inline) {
      var held = frames.get(view);
      if (!held) {
        hostMiss("runInFrame: no held realm for view (" + String(name) + ")");
        return false;
      }

      try {
        held.env.beginScript(String(name || "frame.js"), Boolean(inline));
        var marked = String(source);
        if (globalThis.__wreRewrite && marked.indexOf("throw new TypeError") !== -1 && marked.indexOf("documentElement.innerHTML=") === -1) {
          marked = marked.replace(/!\(typeof ([A-Za-z0-9_$]+)(?:!==|===)([A-Za-z0-9_$]+)\(([A-Za-z0-9_$]+)\.([A-Za-z0-9_$]+)\)\)/g, function (whole, value, fn, obj, key) {
            return "(function(){var ok=(typeof " + value + "===" + fn + "(" + obj + "." + key + "));try{if(!ok){var rg=globalThis;if(!rg.__wreA)rg.__wreA=[];var msg=String(" + fn + "(" + obj + "." + key + "))+' :: '+typeof " + value + "+' :: '+String(" + obj + "&&" + obj + ".constructor&&" + obj + ".constructor.name)+' :: val='+String(" + value + ").slice(0,140)+' :: '+((new Error).stack||'').split('\\n').slice(1,6).join(' | ');if(rg.__wreA.length<40)rg.__wreA.push(msg);try{if(rg.__wreRootEnv){var _e={kind:'assert',detail:msg,at:Date.now()};if(rg.__wreRootEnv.log)rg.__wreRootEnv.log.push(_e);if(rg.__wreRootEnv.logMirror)rg.__wreRootEnv.logMirror.push(_e);}}catch(q){}}}catch(err){}return !ok;})()";
          });
          marked = marked.replace(/typeof ([A-Za-z0-9_$]+)!==([A-Za-z0-9_$]+)\(([A-Za-z0-9_$]+)\.([A-Za-z0-9_$]+)\)\)throw new TypeError/g, function (whole, value, fn, obj, key) {
            return 'typeof ' + value + '!==' + fn + '(' + obj + '.' + key + '))throw new TypeError("WRE_GUARD exp="+String(' + fn + '(' + obj + '.' + key + '))+" got="+typeof ' + value + '+" obj="+(function(){try{return String(' + obj + '&&' + obj + '.constructor&&' + obj + '.constructor.name);}catch(e){return "?";}})()+"@"+((new Error).stack||"").split("\\n").slice(1,7).join(" | "))';
          });
          marked = marked.replace(/typeof ([A-Za-z0-9_$]+)!==([A-Za-z0-9_$]+)\[([A-Za-z0-9_$]+)\(([0-9]+)\)\]\)throw new TypeError/g, function (whole, value, obj, fn, num) {
            return 'typeof ' + value + '!==' + obj + '[' + fn + '(' + num + ')]' +
              ')throw new TypeError("WRE_G2 exp="+String(' + obj + '[' + fn + '(' + num + ')])+" got="+typeof ' + value +
              '+" val="+String((function(){try{return typeof ' + value + '==="object"&&' + value + '?' + value + '.constructor&&' + value + '.constructor.name:' + value + ';}catch(e){return "?";}})()).slice(0,60)' +
              '+"@"+((new Error).stack||"").split("\\n").slice(1,7).join(" | "))';
          });
          var nth = 0;
          marked = marked.replace(/throw new TypeError(?!\()/g, function () {
            nth += 1;
            return 'throw new TypeError("WRE#' + nth + '@" + ((new Error).stack||"").split("\\n").slice(1,9).join(" | "))';
          });
        }
        if (globalThis.__wreDumpMarked && marked.length > 100000 && typeof __wreGraphDump === "function") {
          try { __wreGraphDump("/tmp/wre_marked.js", marked); } catch (dumpError) {}
        }
        held.env.evaluate(marked);
        return true;
      } catch (error) {
        hostMiss(
          "frame script " + String(name) + ": " +
            String(error && error.name) + ": " +
            String(error && error.message) + " :: " +
            String(error && error.stack),
        );
        return false;
      } finally {
        held.env.endScript();
      }
    },

    deliverMessage: function (view, message, origin, source) {
      var held = frames.get(view);
      if (!held) return false;

      try {
        held.env.deliverMessage(message, origin, source);
        return true;
      } catch (error) {
        hostMiss("frame postMessage: " + String(error && error.message));
        return false;
      }
    },

    deliverRoot: function (message, origin, source) {
      var rootEnv = null;

      try {
        rootEnv = globalThis.__wreRootEnv || null;
      } catch (error) {}

      if (!rootEnv || typeof rootEnv.deliverMessage !== "function") return false;

      try {
        rootEnv.deliverMessage(message, origin, source);
        return true;
      } catch (error) {
        hostMiss("root postMessage: " + String(error && error.message));
        return false;
      }
    },

    setFrameLocation: function (view, url) {
      var held = frames.get(view);
      if (!held || !held.env || typeof held.env.setLocation !== "function") return false;

      try {
        held.env.setLocation(String(url));
        return true;
      } catch (error) {
        return false;
      }
    },

    setFrameBase: function (view, href) {
      var held = frames.get(view);
      if (!held || !held.env) return false;

      try {
        var value = String(href == null ? "" : href);
        if (/^https?:/i.test(value)) held.env.defaultBase = value;
        return true;
      } catch (error) {
        return false;
      }
    },

    setFrameElement: function (view, element) {
      var held = frames.get(view);
      if (!held) return false;

      try {
        if (held.env && typeof held.env.setFrameElement === "function") {
          held.env.setFrameElement(element);
        } else if (view) {
          view.__wreFrameElement = element;
        }
        return true;
      } catch (error) {
        return false;
      }
    },

    miss: function (what) {
      hostMiss(String(what));
    }
  };

  globalThis.__PUMP = {
    step: function (env) {
      var owner = env || globalThis.__ENV;
      var ran = 0;
      var waiting = deferred;
      deferred = [];

      for (var index = 0; index < waiting.length; index += 1) {
        var answer = waiting[index][1];
        var headers = {};

        (answer.headers || []).forEach(function (pair) { headers[pair[0]] = pair[1]; });

        try {
          waiting[index][0](answer.status, JSON.stringify(headers), answer.body || "");
          ran += 1;
        } catch (error) {
          hostMiss("response callback: " + String(error && error.message));
        }
      }

      var ready = due();

      for (var at = 0; at < ready.length; at += 1) {
        try {
          owner.fire(ready[at].id, ready[at].extra);
          ran += 1;
        } catch (error) {
          hostMiss("timer " + ready[at].id + ": " + String(error && error.message) + " :: " + String(error && error.stack));
        }
      }

      frames.forEach(function (held) {
        if (!held.pump) return;
        try {
          ran += held.pump.step(held.env);
        } catch (error) {
          hostMiss("frame pump: " + String(error && error.message));
        }
      });

      return ran;
    },

    pending: function () {
      var waiting = timers.length + deferred.length;

      frames.forEach(function (held) {
        if (held.pump) waiting += held.pump.pending();
      });

      return waiting;
    }
  };

  delete globalThis.__wreGraphNow;
  delete globalThis.__wreGraphEntropy;
  delete globalThis.__wreGraphUuid;
  delete globalThis.__wreGraphDigest;
  delete globalThis.__wreGraphEntries;
  delete globalThis.__wreGraphPage;
  delete globalThis.__wreGraphMedia;
  delete globalThis.__wreGraphSend;
  delete globalThis.__wreGraphMiss;
})();
