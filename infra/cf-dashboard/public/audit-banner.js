/* audit-banner.js - renders the "GA audit #8741" block from the "audit" key of /state.json (issue #8741).
 *
 * The key is merged into the dashboard state by /ai-scratch/conductor/audit_telemetry_push.py from the audit telemetry
 * file; this script only draws it.
 * Safe under the shipped CSP (script-src 'self', Trusted Types enforced): it builds nodes with createElement and
 * textContent only, never assigns markup, sets no inline style, and loads its stylesheet from this origin.
 * A section with no telemetry shows "not run yet", never a pass.
 */
(function () {
  "use strict";
  var ISSUE_BASE = "https://github.com/alphaonedev/ai-memory-mcp/issues/";
  var SECTIONS = ["northstar", "security", "mcp-tools", "swarm-tools", "datatier", "federation"];
  var LABEL = {
    "northstar": "North Star", "security": "Security E2E", "mcp-tools": "MCP tools",
    "swarm-tools": "Swarm / Hive", "datatier": "Data tier", "federation": "Federation"
  };
  var STATUS_TEXT = { pass: "pass", fail: "fail", running: "running", not_run: "not run yet", partial: "partial" };
  var MAX_ROWS = 14;

  function h(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) { e.className = cls; }
    if (text !== undefined && text !== null) { e.textContent = String(text); }
    return e;
  }
  function num(v) { return (typeof v === "number" && isFinite(v)) ? v : 0; }
  function stat(s) { return Object.keys(STATUS_TEXT).indexOf(s) >= 0 ? s : "not_run"; }

  function currentSection() {
    var p = location.pathname.replace(/^\/+|\/+$/g, "").replace(/\.html$/, "");
    return SECTIONS.indexOf(p) >= 0 ? p : "";
  }

  function counts(c) {
    var box = h("span", "ab-counts");
    [["pass", "pass"], ["fail", "fail"], ["running", "running"], ["not_run", "not run"]].forEach(function (p) {
      var chip = h("span", "ab-chip ab-" + p[0], num(c && c[p[0]]) + " " + p[1]);
      box.appendChild(chip);
    });
    return box;
  }

  function head(d, section) {
    var top = h("div", "ab-head");
    top.appendChild(h("strong", "ab-title", d.audit_id || "GA audit"));
    var sha = typeof d.sha === "string" ? d.sha.slice(0, 8) : "";
    if (sha) { top.appendChild(h("code", "ab-sha", "sha " + sha)); }
    if (Number.isInteger(d.issue) && d.issue > 0) {
      var a = h("a", "ab-link", "issue #" + d.issue);
      a.setAttribute("href", ISSUE_BASE + d.issue);
      a.setAttribute("rel", "noopener noreferrer");
      top.appendChild(a);
    }
    var when = d.updated_at ? String(d.updated_at) : "never";
    var t = Date.parse(when);
    var age = isNaN(t) ? "" : " (" + Math.max(0, Math.round((Date.now() - t) / 60000)) + " min ago)";
    top.appendChild(h("span", "ab-when", "updated " + when + age));
    if (section) { top.appendChild(h("span", "ab-sec", LABEL[section])); }
    return top;
  }

  function phaseLine(d) {
    var line = h("div", "ab-phases");
    var ph = d.phases || {};
    Object.keys(ph).sort().forEach(function (k) {
      var p = ph[k] || {};
      var s = stat(p.status);
      var c = h("span", "ab-ph ab-" + s, k + " " + STATUS_TEXT[s]);
      if (typeof p.name === "string") { c.setAttribute("title", p.name); }
      line.appendChild(c);
    });
    return line;
  }

  function rowTable(rows) {
    var order = { fail: 0, running: 1, pass: 2, not_run: 3 };
    var sorted = rows.slice().sort(function (a, b) { return order[stat(a.status)] - order[stat(b.status)]; });
    var tbl = h("table", "ab-rows");
    sorted.slice(0, MAX_ROWS).forEach(function (r) {
      var tr = h("tr", "ab-row ab-" + stat(r.status));
      tr.appendChild(h("td", "ab-id", r.id));
      tr.appendChild(h("td", "ab-st", STATUS_TEXT[stat(r.status)]));
      tr.appendChild(h("td", "ab-what", (r.title || "") + (r.reason ? " - " + r.reason : "")));
      tr.appendChild(h("td", "ab-ph", r.phase || ""));
      tbl.appendChild(tr);
    });
    return { table: tbl, more: Math.max(0, sorted.length - MAX_ROWS) };
  }

  function sectionBlock(d, section) {
    var box = h("section", "ab-box");
    box.appendChild(head(d, section));
    var s = (d.sections || {})[section];
    var c = s && s.counts;
    var total = c ? num(c.total) : 0;
    if (!c || total === 0 || num(c.not_run) === total) {
      box.appendChild(h("div", "ab-none", "not run yet - no audit result has been recorded for this section"));
      box.appendChild(counts(c || {}));
      return box;
    }
    box.appendChild(counts(c));
    box.appendChild(phaseLine(d));
    var t = rowTable(s.rows || []);
    box.appendChild(t.table);
    if (t.more > 0) { box.appendChild(h("div", "ab-more", "+ " + t.more + " more rows in the published audit data")); }
    return box;
  }

  function mainBlock(d) {
    var box = h("section", "ab-box");
    box.appendChild(head(d, ""));
    var tot = d.totals || {};
    box.appendChild(counts(tot));
    box.appendChild(phaseLine(d));
    var tbl = h("table", "ab-rows");
    SECTIONS.forEach(function (k) {
      var s = (d.sections || {})[k] || {};
      var c = s.counts || {};
      var st = stat(s.status);
      var tr = h("tr", "ab-row ab-" + st);
      var td = h("td", "ab-id");
      var a = h("a", "ab-link", LABEL[k]);
      a.setAttribute("href", "/" + k + ".html");
      td.appendChild(a);
      tr.appendChild(td);
      tr.appendChild(h("td", "ab-st", STATUS_TEXT[st]));
      tr.appendChild(h("td", "ab-what", num(c.pass) + " pass / " + num(c.fail) + " fail / " + num(c.running) +
        " running / " + num(c.not_run) + " not run (" + num(c.total) + " rows)"));
      tbl.appendChild(tr);
    });
    box.appendChild(tbl);
    return box;
  }

  function place(box, section) {
    var host = document.createElement("div");
    host.id = "audit-banner";
    host.className = "ab-host";
    host.appendChild(box);
    var anchor = section ? document.getElementById("sub") : document.getElementById("kpis");
    if (anchor && anchor.parentNode) {
      if (section) { anchor.parentNode.insertBefore(host, anchor.nextSibling); }
      else { anchor.parentNode.insertBefore(host, anchor); }
    } else {
      document.body.insertBefore(host, document.body.firstChild);
    }
    return host;
  }

  function draw(d, section, host) {
    var box = section ? sectionBlock(d, section) : mainBlock(d);
    if (host && host.parentNode) { host.parentNode.removeChild(host); }
    return place(box, section);
  }

  function start() {
    var link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = "/audit-banner.css";
    document.head.appendChild(link);
    var section = currentSection();
    var host = null;
    function load() {
      fetch("/state.json?t=" + Date.now(), { cache: "no-store" })
        .then(function (r) { if (!r.ok) { throw new Error("http " + r.status); } return r.json(); })
        .then(function (s) { if (!s || typeof s.audit !== "object" || s.audit === null) { throw new Error("no audit block"); } host = draw(s.audit, section, host); })
        .catch(function () {
          host = draw({ audit_id: "GA audit #8741", issue: 8741, sections: {}, totals: {}, phases: {} }, section, host);
        });
    }
    load();
    setInterval(load, 30000);
  }

  if (document.readyState === "loading") { document.addEventListener("DOMContentLoaded", start); } else { start(); }
})();
