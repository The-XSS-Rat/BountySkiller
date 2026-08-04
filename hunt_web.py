"""Web front-end for the bug bounty hunt orchestrator.

Drives the same engines as `/buddy` (tools/hunt_orchestrator.py) from a browser:
paste a target profile, get a gap analysis, run every applicable module, watch
progress, read ranked findings.

The hunter toolchain lives in the claude-bug-bounty repo. Point HUNT_TOOLS at
its tools/ directory if it is not at the default path.
"""

import io
import json
import os
import sys
import threading
import traceback
from contextlib import redirect_stdout
from datetime import datetime, timezone

from flask import Blueprint, jsonify, render_template_string, request

DEFAULT_TOOLS = os.path.expanduser("~/Bounty/claude-bug-bounty/tools")
TOOLS = os.environ.get("HUNT_TOOLS", DEFAULT_TOOLS)
if TOOLS not in sys.path:
    sys.path.insert(0, TOOLS)

hunt_bp = Blueprint("hunt", __name__)

JOB = {
    "running": False,
    "status": "idle",
    "module": None,
    "log": [],
    "plan": [],
    "findings": [],
    "totals": {},
    "errors": {},
    "started_at": None,
    "finished_at": None,
}
LOCK = threading.Lock()


def orchestrator():
    """Import lazily so the rest of the app works without the toolchain."""
    try:
        import hunt_orchestrator
        return hunt_orchestrator
    except ImportError as exc:
        raise RuntimeError(
            f"hunt toolchain not found at {TOOLS} — set HUNT_TOOLS to the "
            f"claude-bug-bounty/tools directory ({exc})"
        )


def build_plan(profile):
    orch = orchestrator()
    plan = []
    for key in orch.DEFAULT_ORDER:
        ready, reason = orch.module_ready(key, profile)
        plan.append({
            "module": key,
            "purpose": orch.MODULES[key][2],
            "ready": ready,
            "reason": reason,
        })
    return plan


def log(line):
    with LOCK:
        JOB["log"].append(line)
        JOB["log"][:] = JOB["log"][-400:]


def run_hunt(profile, only, skip, dry_run):
    orch = orchestrator()
    cli = type("Cli", (), {"dry_run": dry_run})()
    plan = [p for p in build_plan(profile)
            if (not only or p["module"] in only) and p["module"] not in skip]

    with LOCK:
        JOB["plan"] = plan

    findings, errors = [], {}
    for entry in plan:
        key = entry["module"]
        if not entry["ready"]:
            log(f"[skip] {key}: {entry['reason']}")
            continue
        with LOCK:
            JOB["module"] = key
            JOB["status"] = f"running {key}"
        log(f"[run ] {key} — {entry['purpose']}")
        buffer = io.StringIO()
        try:
            with redirect_stdout(buffer):
                report = orch.run_module(key, profile, cli)
        except Exception as exc:  # noqa: BLE001 - one module must not kill the hunt
            errors[key] = str(exc)[:400]
            log(f"[err ] {key}: {str(exc)[:160]}")
            traceback.print_exc(file=io.StringIO())
            continue
        for line in buffer.getvalue().splitlines():
            if line.strip():
                log(f"       {line.strip()}")
        if report is None:
            continue
        found = orch.normalize(key, report)
        findings += found
        log(f"[done] {key}: {len(found)} findings, {report.get('requests_made', 0)} requests")
        with LOCK:
            JOB["findings"] = sorted(orch.dedupe(findings),
                                     key=lambda f: orch.SEV_ORDER.get(f["severity"], 9))

    with LOCK:
        deduped = orch.dedupe(findings)
        JOB["findings"] = sorted(deduped, key=lambda f: orch.SEV_ORDER.get(f["severity"], 9))
        JOB["errors"] = errors
        JOB["totals"] = {
            "findings": len(deduped),
            "critical": sum(1 for f in deduped if f["severity"] == "critical"),
            "high": sum(1 for f in deduped if f["severity"] == "high"),
            "modules_run": sum(1 for p in plan if p["ready"]),
            "modules_skipped": sum(1 for p in plan if not p["ready"]),
        }
        JOB["status"] = "done"
        JOB["module"] = None
        JOB["running"] = False
        JOB["finished_at"] = datetime.now(timezone.utc).isoformat()


@hunt_bp.post("/api/hunt/plan")
def api_plan():
    try:
        profile = request.get_json(force=True) or {}
    except Exception:  # noqa: BLE001
        return jsonify({"error": "profile must be valid JSON"}), 400
    if not (profile.get("scope") or {}).get("domains"):
        return jsonify({"error": "scope.domains is required — nothing runs without a scope"}), 400
    try:
        return jsonify({"plan": build_plan(profile)})
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 500


@hunt_bp.post("/api/hunt/run")
def api_run():
    with LOCK:
        if JOB["running"]:
            return jsonify({"error": "a hunt is already running"}), 409
    body = request.get_json(force=True) or {}
    profile = body.get("profile") or {}
    if not (profile.get("scope") or {}).get("domains"):
        return jsonify({"error": "scope.domains is required — nothing runs without a scope"}), 400

    only = [m for m in (body.get("only") or []) if m]
    skip = [m for m in (body.get("skip") or []) if m]
    dry_run = bool(body.get("dry_run"))

    with LOCK:
        JOB.update(running=True, status="starting", module=None, log=[], plan=[], findings=[],
                   totals={}, errors={},
                   started_at=datetime.now(timezone.utc).isoformat(), finished_at=None)
    threading.Thread(target=run_hunt, args=(profile, only, skip, dry_run), daemon=True).start()
    return jsonify({"started": True, "dry_run": dry_run})


@hunt_bp.get("/api/hunt/status")
def api_status():
    with LOCK:
        return jsonify(dict(JOB))


@hunt_bp.get("/api/hunt/report")
def api_report():
    with LOCK:
        if not JOB["findings"] and JOB["running"]:
            return jsonify({"error": "still running"}), 409
        return jsonify({
            "generated_at": JOB.get("finished_at"),
            "plan": JOB["plan"],
            "totals": JOB["totals"],
            "findings": JOB["findings"],
            "errors": JOB["errors"],
        })


PAGE = """
<!doctype html>
<title>Hunt Buddy</title>
<style>
 body{font:15px/1.55 -apple-system,Segoe UI,Roboto,sans-serif;max-width:1100px;margin:32px auto;
      padding:0 20px;background:#0f1115;color:#e6e6e6}
 h1{font-size:22px;margin-bottom:4px} h2{font-size:16px;margin:26px 0 8px;color:#9aa4b2}
 textarea{width:100%;height:280px;padding:12px;border-radius:8px;border:1px solid #2a2f3a;
          background:#171a21;color:#e6e6e6;font:12px/1.5 ui-monospace,Menlo,monospace}
 button{margin:14px 8px 0 0;padding:10px 18px;border:0;border-radius:6px;background:#4f8cff;
        color:#fff;font-weight:600;cursor:pointer}
 button.ghost{background:#242a36} button:disabled{opacity:.5;cursor:default}
 table{width:100%;border-collapse:collapse;margin-top:10px;font-size:13px}
 th,td{text-align:left;padding:7px 8px;border-bottom:1px solid #232833;vertical-align:top}
 th{color:#9aa4b2;font-weight:600}
 pre{background:#171a21;padding:12px;border-radius:8px;border:1px solid #2a2f3a;
     max-height:260px;overflow:auto;font-size:12px}
 .sev{font-weight:700;padding:1px 7px;border-radius:4px;font-size:11px;letter-spacing:.03em}
 .critical{background:#7f1d1d;color:#fecaca} .high{background:#7c2d12;color:#fed7aa}
 .medium{background:#78350f;color:#fde68a} .low{background:#1e3a5f;color:#bfdbfe}
 .info{background:#27313f;color:#cbd5e1}
 .run{color:#4ade80} .skip{color:#f59e0b} .muted{color:#7c8698;font-size:12px}
 code{background:#1b2029;padding:1px 5px;border-radius:4px;font-size:12px}
</style>
<h1>Hunt Buddy</h1>
<p class="muted">One profile, every applicable bug class, one ranked list. Same engines as
<code>/buddy</code>. Scope is enforced in code — nothing is sent outside it.</p>

<h2>Target profile</h2>
<textarea id="profile" spellcheck="false"></textarea>
<button onclick="plan()">Plan (no traffic)</button>
<button class="ghost" onclick="run(true)">Dry run</button>
<button onclick="run(false)" id="runbtn">Run hunt</button>
<button class="ghost" onclick="loadExample()">Load example</button>

<div id="planbox"></div>
<h2>Progress</h2>
<pre id="log">idle</pre>
<div id="results"></div>

<script>
const EXAMPLE = {
  target: "target.com",
  base_url: "https://target.com",
  scope: {domains: ["target.com", "*.target.com"], excluded_paths: ["^/internal/"],
          allowed_methods: ["GET","POST","PUT","PATCH"]},
  urls_file: "recon/target.com/urls.txt",
  cookies: {session: "SESSION_COOKIE"},
  identities: [
    {name:"admin", privilege:100, tenant:"org1", global_scope:true, auth:{type:"bearer", token:"ADMIN"}},
    {name:"user_a", privilege:10, tenant:"org1", auth:{type:"bearer", token:"USER_A"}}
  ],
  oast_domain: "abc.oast.pro"
};
function loadExample(){ profile.value = JSON.stringify(EXAMPLE, null, 2); }
if(!profile.value) loadExample();

function parseProfile(){
  try { return JSON.parse(profile.value); }
  catch(e){ alert("Profile is not valid JSON: " + e.message); return null; }
}
function renderPlan(plan){
  const rows = plan.map(p => `<tr>
      <td class="${p.ready?'run':'skip'}">${p.ready?'RUN':'SKIP'}</td>
      <td><code>${p.module}</code></td><td>${p.purpose}</td>
      <td class="muted">${p.ready?'':p.reason}</td></tr>`).join('');
  planbox.innerHTML = `<h2>Plan — ${plan.filter(p=>p.ready).length}/${plan.length} modules ready</h2>
    <table><tr><th></th><th>module</th><th>class</th><th>missing input</th></tr>${rows}</table>`;
}
async function plan(){
  const p = parseProfile(); if(!p) return;
  const r = await fetch('/api/hunt/plan', {method:'POST', headers:{'Content-Type':'application/json'},
                                           body: JSON.stringify(p)});
  const j = await r.json();
  if(j.error){ planbox.innerHTML = `<p class="skip">${j.error}</p>`; return; }
  renderPlan(j.plan);
}
let timer = null;
async function run(dry){
  const p = parseProfile(); if(!p) return;
  runbtn.disabled = true;
  const r = await fetch('/api/hunt/run', {method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({profile: p, dry_run: dry})});
  const j = await r.json();
  if(j.error){ alert(j.error); runbtn.disabled=false; return; }
  timer = setInterval(poll, 1000); poll();
}
async function poll(){
  const j = await (await fetch('/api/hunt/status')).json();
  log.textContent = (j.log||[]).join('\\n') || j.status;
  log.scrollTop = log.scrollHeight;
  if(j.plan && j.plan.length) renderPlan(j.plan);
  if(j.findings) renderFindings(j.findings, j.totals);
  if(!j.running){ clearInterval(timer); runbtn.disabled = false; }
}
function renderFindings(findings, totals){
  if(!findings.length){ results.innerHTML = '<h2>Findings</h2><p class="muted">none yet</p>'; return; }
  const rows = findings.map(f => `<tr>
      <td><span class="sev ${f.severity}">${f.severity.toUpperCase()}</span></td>
      <td><code>${f.module}</code></td><td><code>${f.kind}</code></td>
      <td>${f.param?'<code>'+f.param+'</code>':''}</td>
      <td class="muted">${(f.url||'').slice(0,70)}</td>
      <td>${f.evidence||''}</td></tr>`).join('');
  const t = totals||{};
  results.innerHTML = `<h2>Findings — ${findings.length} (${t.critical||0} critical, ${t.high||0} high)</h2>
    <table><tr><th>sev</th><th>module</th><th>kind</th><th>param</th><th>url</th><th>evidence</th></tr>
    ${rows}</table>
    <p class="muted">Reproduce by hand before reporting. "Not tested" is not "clean" — check the plan above.</p>`;
}
</script>
"""


@hunt_bp.get("/hunt")
def hunt_page():
    return render_template_string(PAGE)
