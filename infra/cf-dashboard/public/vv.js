/* V&V sub-page renderer shared by datatier, federation, mcp-tools, northstar, security and swarm-tools (#7313).
   The page names its state file in <body data-src="...">. Everything is built with DOM nodes and textContent: no
   state value is ever parsed as markup (#7587). A failed fetch or render keeps the last good data on screen, shows
   an alert with a Retry button, and the page polls again (#7594). */
(function () {
  "use strict";
  var SRC = document.body.getAttribute("data-src");
  var REFRESH_MS = 30000;
  var PLACEHOLDER = "—";
  var good = false;
  var busy = false;

  function num(v) {
    var x = typeof v === "number" || (typeof v === "string" && v.trim() !== "") ? Number(v) : NaN;
    return isFinite(x) ? x : null;
  }
  function show(v) { var x = num(v); return x === null ? PLACEHOLDER : String(x); }
  function share(part, whole) {
    var a = num(part), b = num(whole);
    if (a === null || b === null || b <= 0) { return 0; }
    return Math.max(0, Math.min(100, a / b * 100));
  }
  function token(v) { return typeof v === "string" && /^[a-z][a-z-]*$/.test(v) ? v : "unknown"; }
  function node(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) { e.className = cls; }
    if (text != null) { e.textContent = String(text); }
    return e;
  }
  function fail(code) { var e = new Error(code); e.code = code; return e; }

  function famFS(btn) {
    var c = btn.closest(".fam");
    var maximize = function () { c.classList.toggle("maximized"); };
    try {
      if (c.requestFullscreen) {
        if (document.fullscreenElement === c) { document.exitFullscreen(); }
        else { c.requestFullscreen().catch(maximize); }
        return;
      }
    } catch (_) { /* fall through to the CSS maximise */ }
    maximize();
  }
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") {
      document.querySelectorAll(".fam.maximized").forEach(function (c) { c.classList.remove("maximized"); });
    }
  });

  /* Build the whole view first; nothing on the page changes unless every part built. */
  function build(d) {
    if (d === null || typeof d !== "object") { throw fail("render"); }
    var groups = d.groups == null ? [] : d.groups;
    if (!Array.isArray(groups)) { throw fail("render"); }
    var view = { pct: num(d.pct), total: d.total, stats: [], bar: [], cards: [], updated: "" };
    view.stats = [["validated", d.validated, "var(--good)"], ["fail-closed", d.failclosed, "var(--run)"],
                  ["refining", d.refining, "var(--warn)"], ["total tools", d.total, "var(--ink)"]];
    view.bar = [[share(d.validated, d.total), "var(--good)"], [share(d.failclosed, d.total), "var(--run)"],
                [share(d.refining, d.total), "var(--warn)"]];
    groups.forEach(function (fam) {
      if (fam === null || typeof fam !== "object" || !Array.isArray(fam.tools)) { throw fail("render"); }
      var ok = fam.tools.filter(function (t) { return t && t.status !== "fail"; }).length;
      var tot = fam.tools.length;
      var card = node("div", "fam");
      var hdr = node("div", "famhdr");
      hdr.appendChild(node("span", "famname", fam.family == null ? "" : fam.family));
      hdr.appendChild(node("span", "famcount", ok + "/" + tot));
      var btn = node("button", "fsbtn", "⛶");
      btn.type = "button";
      btn.title = "expand this block to full screen (Esc to close)";
      btn.addEventListener("click", function () { famFS(btn); });
      hdr.appendChild(btn);
      var fambar = node("span", "fambar");
      var fill = document.createElement("i");
      fill.style.width = share(ok, tot) + "%";
      fill.style.height = "100%";
      fill.style.background = ok === tot ? "var(--good)" : "var(--warn)";
      fambar.appendChild(fill);
      hdr.appendChild(fambar);
      card.appendChild(hdr);
      var tools = node("div", "tools");
      fam.tools.forEach(function (t) {
        if (t === null || typeof t !== "object") { throw fail("render"); }
        var cls = token(t.cls);
        var row = node("div", "tool " + cls);
        row.title = (t.desc || "") + (t.note ? " — " + t.note : "");
        row.appendChild(node("span", "tn", String(t.name == null ? "" : t.name).replace("memory_", "")));
        row.appendChild(node("span", "ti " + cls, cls === "validated" ? "✓" : cls === "failclosed" ? "⇥" : "…"));
        tools.appendChild(row);
      });
      card.appendChild(tools);
      view.cards.push(card);
    });
    var stamp = Date.parse(d.lastUpdated);
    if (isFinite(stamp)) { view.updated = new Date(stamp).toISOString().slice(0, 16).replace("T", " ") + "Z"; }
    return view;
  }

  function commit(view) {
    var pctEl = document.getElementById("pct");
    pctEl.textContent = view.pct === null ? PLACEHOLDER : String(view.pct);
    pctEl.appendChild(node("span", "u", "%"));
    pctEl.style.color = view.pct !== null && view.pct >= 90 ? "var(--good)" : "var(--warn)";
    var stats = document.getElementById("herostats");
    stats.textContent = "";
    view.stats.forEach(function (s) {
      var h = node("div", "hstat");
      var v = node("div", "v", show(s[1]));
      v.style.color = s[2];
      h.appendChild(v);
      h.appendChild(node("div", "l", s[0]));
      stats.appendChild(h);
    });
    var bar = document.getElementById("bar");
    bar.textContent = "";
    view.bar.forEach(function (b) {
      var i = document.createElement("i");
      i.style.width = b[0].toFixed(1) + "%";
      i.style.background = b[1];
      bar.appendChild(i);
    });
    var host = document.getElementById("families");
    host.textContent = "";
    view.cards.forEach(function (c) { host.appendChild(c); });
    var upd = document.getElementById("upd");
    upd.textContent = "";
    if (view.updated) {
      upd.appendChild(document.createElement("br"));
      var s = node("span", "", view.updated);
      s.style.opacity = ".7";
      upd.appendChild(s);
    }
    var subtotal = document.getElementById("subtotal");
    if (subtotal) { subtotal.textContent = show(view.total); }
  }

  var MESSAGES = {
    network: "the state file could not be fetched",
    http: "the state file request failed",
    json: "the state file is not valid JSON",
    render: "the state file could not be rendered"
  };
  function showError(code) {
    var holder = document.getElementById("banner");
    holder.textContent = "";
    var bar = node("div", "errbar");
    bar.setAttribute("role", "alert");
    bar.appendChild(node("span", "", (MESSAGES[code] || MESSAGES.render) + (good ? " — showing the last good data" : "") + " "));
    var retry = node("button", "fsbtn", "Retry");
    retry.type = "button";
    retry.addEventListener("click", load);
    bar.appendChild(retry);
    holder.appendChild(bar);
  }
  function clearError() { document.getElementById("banner").textContent = ""; }

  function load() {
    if (busy) { return; }
    busy = true;
    fetch(SRC + "?t=" + Date.now(), { cache: "no-store" })
      .then(function (r) {
        if (!r.ok) { throw fail("http"); }
        return r.json().catch(function () { throw fail("json"); });
      }, function () { throw fail("network"); })
      .then(function (d) {
        commit(build(d));
        good = true;
        clearError();
      })
      .catch(function (e) { showError(e && e.code ? e.code : "render"); })
      .then(function () { busy = false; });
  }
  load();
  setInterval(load, REFRESH_MS);
})();
