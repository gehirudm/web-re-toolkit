(function () {
  var env = globalThis.__ENV;
  var pump = globalThis.__PUMP;

  // Keep a handle on the embedder->frame delivery path so a mounted page can be
  // handed a message that carries the embedder as its source, the way a real
  // parent frame's postMessage would. The realm's own postMessage can only ever
  // deliver with the frame itself as the source.
  globalThis.__wreDeliver = function (message, origin, source) {
    return env.deliverMessage(message, origin, source);
  };

  delete globalThis.__ENV;
  delete globalThis.__PUMP;

  var json = function (value) {
    try {
      return JSON.parse(env.rawStringify(value));
    } catch (error) {
      return null;
    }
  };

  return {
    step: function () {
      return pump.step(env);
    },

    pending: function () {
      return pump.pending();
    },

    begin: function (name, inline) {
      env.beginScript(String(name || ""), Boolean(inline));
    },

    end: function () {
      env.endScript();
    },

    read: function (expression) {
      try {
        return env.evaluate("(" + String(expression) + ")");
      } catch (error) {
        return "THREW " + String(error && error.message);
      }
    },

    cookies: function () {
      return typeof env.cookies === "function" ? env.cookies() : "";
    },

    calls: function () {
      return json(env.calls);
    },

    trail: function () {
      return json(env.trail);
    },

    misses: function () {
      return json(env.misses);
    },

    log: function () {
      var src = (env.logMirror && env.logMirror.length ? env.logMirror : env.log) || [];
      var start = src.length > 2500 ? src.length - 2500 : 0;
      var out = [];

      for (var i = start; i < src.length; i++) {
        try {
          var text = JSON.stringify(src[i]);

          if (text.length > 20000) {
            out.push({ kind: String((src[i] && src[i].kind) || "?"), detail: text.slice(0, 20000) + "<trunc>", at: 0 });
          } else {
            out.push(JSON.parse(text));
          }
        } catch (entryError) {
          out.push({ kind: String((src[i] && src[i].kind) || "?"), detail: "<unserializable>", at: 0 });
        }
      }

      return out;
    },

    layoutMisses: function () {
      return typeof env.layoutMisses === "function" ? json(env.layoutMisses()) : [];
    }
  };
})()
