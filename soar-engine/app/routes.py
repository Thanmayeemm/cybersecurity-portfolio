"""
HTTP routes: JSON API for analysis and incidents, demo dashboard UI.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from flask import Blueprint, jsonify, render_template_string, request

from app.models import incident as incident_model
from app.services.decision_engine import ThreatDecisionEngine
from app.services import enrichment as enrichment_service
from app.services import response_engine
from app.utils.json_response import sanitize_for_json
from app.utils.logger import setup_logging

bp = Blueprint("soar", __name__)
log = setup_logging(__name__)

MAX_INDICATOR_LEN = 512
_SAFE_INDICATOR_RE = re.compile(r"^[\w.\-:\/\@\*]+$")


def _validate_indicator(raw: str | None) -> tuple[str | None, str | None]:
    if raw is None or not isinstance(raw, str):
        return None, "indicator is required"
    s = raw.strip()
    if not s:
        return None, "indicator cannot be empty"
    if len(s) > MAX_INDICATOR_LEN:
        return None, f"indicator exceeds max length {MAX_INDICATOR_LEN}"
    if not _SAFE_INDICATOR_RE.match(s):
        return None, "indicator contains invalid characters"
    return s, None


@bp.route("/analyze", methods=["POST"])
def analyze():
    """
    JSON body: { "indicator": "<ipv4|ipv6|domain|hash>" }.
    Returns enrichment, decision (confidence 0–100), playbook steps, and action_list.
    """
    try:
        payload: dict[str, Any]
        if request.is_json:
            payload = request.get_json(silent=True) or {}
        else:
            payload = request.form.to_dict() or {}

        indicator, err = _validate_indicator(payload.get("indicator"))
        if err:
            return jsonify({"error": err}), 400

        assert indicator is not None

        enr = enrichment_service.enrich_indicator(indicator)
        if enr.get("indicator_type") == "unknown":
            return jsonify(
                {
                    "error": "could not parse indicator type",
                    "enrichment": enr,
                }
            ), 400

        engine = ThreatDecisionEngine()
        decision = engine.classify(float(enr.get("combined_score", 0.0)))
        conf = decision.confidence_percent

        playbook = response_engine.run_playbook(
            indicator=indicator,
            indicator_type=str(enr.get("indicator_type")),
            verdict=decision.verdict,
            severity=decision.severity,
            confidence_percent=conf,
            combined_score=float(enr.get("combined_score", 0.0)),
            vt_score=float(enr.get("vt_score", 0.0)),
            abuse_score=enr.get("abuse_score"),
        )

        body: dict[str, Any] = {
            "success": True,
            "indicator": indicator,
            "indicator_type": enr.get("indicator_type"),
            "enrichment": enr,
            "scores": {
                "vt_score": enr.get("vt_score"),
                "abuse_score": enr.get("abuse_score"),
                "combined_score": enr.get("combined_score"),
            },
            "decision": decision.to_dict(),
            # Full playbook object (verdict key, steps, action_list) — stable shape for clients
            "actions": playbook,
            "action_list": playbook.get("action_list", []),
        }
        return jsonify(sanitize_for_json(body))
    except Exception as e:
        log.exception("analyze_failed: %s", e)
        return jsonify({"error": "internal error during analysis", "detail": str(e)}), 500


@bp.route("/incidents", methods=["GET"])
def incidents():
    limit = request.args.get("limit", default="500", type=int) or 500
    limit = max(1, min(limit, 2000))
    rows = incident_model.get_all_incidents(limit=limit)
    return jsonify({"count": len(rows), "incidents": rows})


_UI_PAGE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>SOAR & Threat Intelligence Engine</title>
  <style>
    :root {
      --bg: #0f1419;
      --panel: #1a2332;
      --border: #2d3a4d;
      --text: #e7ecf3;
      --muted: #8b9cb3;
      --mal: #f85149;
      --sus: #d29922;
      --ben: #3fb950;
      --accent: #58a6ff;
    }
    * { box-sizing: border-box; }
    body {
      font-family: "Segoe UI", system-ui, sans-serif;
      background: var(--bg);
      color: var(--text);
      margin: 0;
      min-height: 100vh;
      line-height: 1.5;
    }
    .wrap { max-width: 1100px; margin: 0 auto; padding: 1.5rem; }
    header { margin-bottom: 1.5rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem; }
    h1 { font-size: 1.35rem; font-weight: 600; margin: 0 0 0.35rem; }
    .sub { color: var(--muted); font-size: 0.9rem; }
    .grid { display: grid; gap: 1.25rem; }
    @media (min-width: 840px) { .grid-2 { grid-template-columns: 1fr 1fr; } }
    .card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1.1rem 1.25rem;
    }
    .card h2 { font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); margin: 0 0 0.75rem; }
    label { display: block; font-size: 0.85rem; color: var(--muted); margin-bottom: 0.35rem; }
    textarea {
      width: 100%; min-height: 72px; padding: 0.65rem; border-radius: 8px;
      border: 1px solid var(--border); background: #0d1117; color: var(--text);
      font-family: ui-monospace, monospace; font-size: 0.9rem; resize: vertical;
    }
    button {
      margin-top: 0.75rem; padding: 0.55rem 1.2rem; border-radius: 8px; border: none;
      background: var(--accent); color: #0f1419; font-weight: 600; cursor: pointer;
    }
    button:hover { filter: brightness(1.08); }
    button:disabled { opacity: 0.5; cursor: not-allowed; }
    .verdict-banner {
      border-radius: 8px; padding: 0.85rem 1rem; font-weight: 600; font-size: 1.05rem;
      margin-bottom: 1rem; border: 1px solid transparent;
    }
    .verdict-malicious { background: rgba(248,81,73,0.15); border-color: var(--mal); color: #ffb1ad; }
    .verdict-suspicious { background: rgba(210,153,34,0.15); border-color: var(--sus); color: #f0d080; }
    .verdict-benign { background: rgba(63,185,80,0.12); border-color: var(--ben); color: #7ee787; }
    .kv { display: grid; grid-template-columns: auto 1fr; gap: 0.35rem 1rem; font-size: 0.9rem; }
    .kv dt { color: var(--muted); }
    .kv dd { margin: 0; font-family: ui-monospace, monospace; word-break: break-all; }
    .actions ul { margin: 0; padding-left: 1.1rem; }
    .actions li { margin: 0.35rem 0; font-size: 0.88rem; }
    .badge { display: inline-block; padding: 0.15rem 0.45rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
    .badge-mal { background: rgba(248,81,73,0.25); color: #ffb1ad; }
    .badge-sus { background: rgba(210,153,34,0.25); color: #f0d080; }
    .badge-ben { background: rgba(63,185,80,0.25); color: #7ee787; }
    .badge-low { background: #21262d; color: var(--muted); }
    .badge-med { background: rgba(210,153,34,0.2); color: #f0d080; }
    .badge-high { background: rgba(248,81,73,0.2); color: #ffb1ad; }
    table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
    th, td { text-align: left; padding: 0.5rem 0.6rem; border-bottom: 1px solid var(--border); }
    th { color: var(--muted); font-weight: 600; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.04em; }
    tr:hover td { background: rgba(88,166,255,0.04); }
    .empty { color: var(--muted); font-size: 0.9rem; padding: 1rem 0; }
    .err { color: var(--mal); font-size: 0.9rem; margin-top: 0.5rem; }
    #result-area { min-height: 120px; }
  </style>
</head>
<body>
  <div class="wrap">
    <header>
      <h1>Automated Threat Intelligence &amp; SOAR Engine</h1>
      <p class="sub">Enrichment (VirusTotal + AbuseIPDB) → decision engine → playbooks (block / Slack / SQLite)</p>
    </header>

    <div class="grid grid-2">
      <div class="card">
        <h2>Analyze indicator</h2>
        <form id="analyze-form">
          <label for="indicator">IPv4, IPv6, domain, or file hash (MD5 / SHA1 / SHA256)</label>
          <textarea id="indicator" name="indicator" placeholder="e.g. 8.8.8.8 or example.com or paste a hash"></textarea>
          <button type="submit" id="btn-run">Run analysis</button>
          <div id="form-err" class="err" style="display:none;"></div>
        </form>
      </div>
      <div class="card" id="result-area">
        <h2>Latest result</h2>
        <p class="empty" id="result-placeholder">Submit an indicator to see verdict, scores, and actions.</p>
        <div id="result-content" style="display:none;"></div>
      </div>
    </div>

    <div class="card" style="margin-top:1.25rem;">
      <h2>Recent incidents</h2>
      <p class="sub" style="margin-top:0;font-size:0.8rem;">Sorted by newest first (from SQLite)</p>
      <div id="incidents-wrap">
        <p class="empty">Loading…</p>
      </div>
    </div>
  </div>

  <script>
    function verdictClass(v) {
      if (v === 'malicious') return 'verdict-malicious';
      if (v === 'suspicious') return 'verdict-suspicious';
      return 'verdict-benign';
    }
    function sevBadge(sev) {
      const s = (sev || '').toLowerCase();
      let cls = 'badge-low';
      if (s === 'medium') cls = 'badge-med';
      if (s === 'high') cls = 'badge-high';
      return '<span class="badge ' + cls + '">' + (sev || '-') + '</span>';
    }
    function verBadge(v) {
      const s = (v || '').toLowerCase();
      let cls = 'badge-ben';
      if (s === 'suspicious') cls = 'badge-sus';
      if (s === 'malicious') cls = 'badge-mal';
      return '<span class="badge ' + cls + '">' + (v || '-') + '</span>';
    }

    function renderResult(data) {
      const d = data.decision || {};
      const e = data.enrichment || {};
      const acts = data.action_list || [];
      const v = d.verdict || 'unknown';
      const banner = '<div class="verdict-banner ' + verdictClass(v) + '">Verdict: ' + v.toUpperCase() + '</div>';
      const kv = '<dl class="kv">' +
        '<dt>Indicator</dt><dd>' + escapeHtml(data.indicator || '') + '</dd>' +
        '<dt>Type</dt><dd>' + escapeHtml(e.indicator_type || '-') + '</dd>' +
        '<dt>Severity</dt><dd>' + sevBadge(d.severity) + '</dd>' +
        '<dt>Confidence</dt><dd>' + (d.confidence_percent != null ? d.confidence_percent + '%' : (d.confidence != null ? d.confidence + '%' : '-')) + '</dd>' +
        '<dt>VT score</dt><dd>' + (e.vt_score != null ? e.vt_score : '-') + '</dd>' +
        '<dt>AbuseIPDB</dt><dd>' + (e.abuse_score != null ? e.abuse_score : 'n/a') + '</dd>' +
        '<dt>Combined</dt><dd>' + (e.combined_score != null ? e.combined_score : '-') + '</dd>' +
        '</dl>';
      let alist = '<div class="actions" style="margin-top:1rem;"><strong style="font-size:0.8rem;color:var(--muted);">ACTIONS</strong><ul>';
      acts.forEach(function (a) {
        let line = (a.action || '') + ' — <code>' + escapeHtml(String(a.status || '')) + '</code>';
        if (a.reason) line += ' (' + escapeHtml(a.reason) + ')';
        if (a.incident_id) line += ' · id ' + a.incident_id;
        alist += '<li>' + line + '</li>';
      });
      alist += '</ul></div>';
      return banner + kv + alist;
    }

    function escapeHtml(s) {
      const div = document.createElement('div');
      div.textContent = s;
      return div.innerHTML;
    }

    async function loadIncidents() {
      const el = document.getElementById('incidents-wrap');
      try {
        const res = await fetch('/incidents?limit=50');
        const j = await res.json();
        const rows = j.incidents || [];
        if (!rows.length) {
          el.innerHTML = '<p class="empty">No incidents stored yet.</p>';
          return;
        }
        let html = '<table><thead><tr><th>ID</th><th>Time (UTC)</th><th>Indicator</th><th>Verdict</th><th>Severity</th><th>Actions</th></tr></thead><tbody>';
        rows.forEach(function (r) {
          const sev = (r.severity || '').toLowerCase();
          let rowStyle = '';
          if (sev === 'high') rowStyle = ' style="box-shadow:inset 3px 0 0 var(--mal)"';
          else if (sev === 'medium') rowStyle = ' style="box-shadow:inset 3px 0 0 var(--sus)"';
          else rowStyle = ' style="box-shadow:inset 3px 0 0 var(--ben)"';
          html += '<tr' + rowStyle + '><td>' + r.id + '</td><td>' + escapeHtml(r.timestamp || '') + '</td><td><code>' +
            escapeHtml(r.indicator || '') + '</code></td><td>' + verBadge(r.verdict) + '</td><td>' + sevBadge(r.severity) + '</td><td>' +
            escapeHtml((r.action_taken || '').substring(0, 80)) + (r.action_taken && r.action_taken.length > 80 ? '…' : '') + '</td></tr>';
        });
        html += '</tbody></table>';
        el.innerHTML = html;
      } catch (e) {
        el.innerHTML = '<p class="empty">Could not load incidents.</p>';
      }
    }

    document.getElementById('analyze-form').onsubmit = async function (ev) {
      ev.preventDefault();
      const btn = document.getElementById('btn-run');
      const errEl = document.getElementById('form-err');
      const ind = document.getElementById('indicator').value.trim();
      errEl.style.display = 'none';
      if (!ind) {
        errEl.textContent = 'Enter an indicator.';
        errEl.style.display = 'block';
        return;
      }
      btn.disabled = true;
      document.getElementById('result-placeholder').style.display = 'none';
      document.getElementById('result-content').style.display = 'block';
      document.getElementById('result-content').innerHTML = '<p class="empty">Analyzing…</p>';
      try {
        const res = await fetch('/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ indicator: ind })
        });
        const data = await res.json();
        if (!res.ok) {
          document.getElementById('result-content').innerHTML =
            '<p class="err">' + escapeHtml(data.error || 'Request failed') + '</p>';
        } else {
          document.getElementById('result-content').innerHTML = renderResult(data);
        }
        loadIncidents();
      } catch (e) {
        document.getElementById('result-content').innerHTML =
          '<p class="err">Network error. Is the server running?</p>';
      }
      btn.disabled = false;
    };

    loadIncidents();
  </script>
</body>
</html>
"""


@bp.route("/", methods=["GET"])
def index():
    return render_template_string(_UI_PAGE)
