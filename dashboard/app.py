"""AutoRedTeam dashboard (Phase 8 visual layer).

A presentation-grade cockpit over the FastAPI app (api/main.py), in three tabs:

* Benchmark  — the evaluation story: precision/recall/FP-rate KPIs, per-class bars,
               confusion breakdown, engine-vs-agent variance, RAG ablation, and the
               AutoRedTeam-vs-ZAP noise comparison.
* Scenarios  — each named scenario with its EXPECTED vs ACTUAL verdict (true positives,
               correct non-alarms, and honest out-of-scope misses).
* Live Run   — start a real red-team run against the sandbox and watch the findings.

Data source: it prefers the API, and falls back to reading the bundled snapshot files
in evals/results/ directly — so a demo always has something to show even with the
sandbox and LLM down. Start the API for live runs:

    uvicorn api.main:app --port 8077
    streamlit run dashboard/app.py
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import altair as alt
import httpx
import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from evals import results as eval_results  # noqa: E402

st.set_page_config(page_title="AutoRedTeam", page_icon="🛡️", layout="wide")

SEV_COLOR = {"critical": "#b3123b", "high": "#d9534f", "medium": "#e8a13a",
             "low": "#4a90d9", "info": "#888"}
KIND_STYLE = {
    "tp":             ("#1a7f4b", "Exploited (true positive)"),
    "true_negative":  ("#2f6fb0", "Correctly safe (true negative)"),
    "fp_guard":       ("#2f6fb0", "False-positive guard"),
    "false_negative": ("#8a6d1a", "Out-of-scope miss"),
}
PASS_COLOR = {True: "#1a7f4b", False: "#b3123b", None: "#888"}

# Plain-language explanations so a non-specialist viewer (e.g. a professor) understands
# what each finding actually is, beyond the acronym + CVSS number.
VULN_INFO = {
    "IDOR": {
        "name": "Insecure Direct Object Reference",
        "what": "The app trusts an ID in the request and returns the matching record "
                "without checking who owns it — so changing `/basket/1` to `/basket/2` "
                "hands you another user's data.",
        "impact": "One logged-in user can read (or tamper with) other users' private data."},
    "SQLI_ERROR": {
        "name": "SQL Injection (error-based)",
        "what": "User input is concatenated straight into a database query, so a crafted "
                "value (e.g. a stray quote) breaks the SQL and the database returns an "
                "error that reveals the query.",
        "impact": "An attacker can read, modify or dump the whole database, and often "
                  "bypass the login entirely."},
    "SQLI_BLIND": {
        "name": "SQL Injection (blind / time-based)",
        "what": "The same injection flaw, but with no visible error — the attacker infers "
                "the data from how long the server takes to respond.",
        "impact": "Full database compromise, extracted one inferred bit at a time."},
    "XSS_REFLECTED": {
        "name": "Reflected Cross-Site Scripting",
        "what": "The app echoes user input back into the page without sanitizing it, so "
                "attacker-supplied JavaScript runs inside the victim's browser.",
        "impact": "Steal a victim's session/cookies, act as them, or deface the page."},
    "BROKEN_AUTH": {
        "name": "Broken Authentication",
        "what": "The token check can be bypassed — here a tampered, unsigned JWT "
                "(`alg:none`) is accepted as a valid admin token.",
        "impact": "Account takeover and privilege escalation — act as any user, incl. admin."},
    "SSRF": {
        "name": "Server-Side Request Forgery",
        "what": "The server is tricked into making HTTP requests to attacker-chosen "
                "addresses, including internal systems it should never reach.",
        "impact": "Reach internal services or cloud metadata, or pivot deeper into the network."},
    "PATH_TRAVERSAL": {
        "name": "Path Traversal",
        "what": "File-path input isn't constrained, so sequences like `../../` let a request "
                "escape the intended folder and read arbitrary files.",
        "impact": "Disclosure of source code, config, secrets or other sensitive files."},
}


def vuln_name(vuln_class: str) -> str:
    return VULN_INFO.get(vuln_class, {}).get("name", vuln_class)


def finding_explainer(vuln_class: str) -> None:
    """A small 'what is this?' box shown next to a finding."""
    i = VULN_INFO.get(vuln_class)
    if not i:
        return
    st.info(f"**What is this? — {i['name']}**\n\n{i['what']}\n\n**Why it matters:** {i['impact']}")


def render_glossary(classes) -> None:
    present = sorted({c for c in classes if c in VULN_INFO})
    if not present:
        return
    with st.expander("📖 Vulnerability glossary — what each class means"):
        for vc in present:
            i = VULN_INFO[vc]
            st.markdown(f"**{vc} — {i['name']}**  \n{i['what']}  \n*Why it matters:* {i['impact']}")


# --------------------------------------------------------------------------- #
# data access — API first, local snapshot files as fallback
# --------------------------------------------------------------------------- #

def _api_base() -> str:
    return st.session_state.get("api_base", "http://127.0.0.1:8077")


def _request(method: str, path: str, **kw):
    """Fresh connection per request + small retry (the server can drop an idle keep-alive
    while a recon pass is briefly CPU-bound)."""
    last = None
    for _ in range(5):
        try:
            with httpx.Client(base_url=_api_base(), timeout=kw.pop("timeout", 30)) as c:
                return c.request(method, path, **kw)
        except httpx.HTTPError as exc:
            last = exc
            time.sleep(0.4)
    raise last if last else RuntimeError("request failed")


@st.cache_data(ttl=5, show_spinner=False)
def api_online(base: str) -> bool:
    """One fast health ping, cached briefly. No retry loop — so when the API is down the
    whole dashboard stays snappy on the local-snapshot fallback (the sandbox-down demo path)."""
    try:
        with httpx.Client(base_url=base, timeout=1.5) as c:
            return c.get("/health").status_code == 200
    except Exception:
        return False


def _local_snapshot_list() -> list[dict]:
    out = []
    for p in eval_results.list_snapshots():
        try:
            r = eval_results.load(p)
        except Exception:
            continue
        out.append({"name": p.stem, "label": r.label, "target": r.target, "model": r.model,
                    "mode": r.mode, "created_at": r.created_at.isoformat(),
                    "in_scope_recall": r.overall_in_scope.recall,
                    "in_scope_precision": r.overall_in_scope.precision})
    out.sort(key=lambda d: d["created_at"], reverse=True)
    return out


def list_snapshots(online: bool) -> list[dict]:
    if online:
        try:
            return _request("GET", "/benchmark/snapshots", timeout=5).json()
        except Exception:
            pass
    return _local_snapshot_list()


def load_snapshot(name: str, online: bool) -> eval_results.BenchmarkResult:
    if online:
        try:
            return eval_results.BenchmarkResult.model_validate(
                _request("GET", f"/benchmark/snapshots/{name}", timeout=5).json())
        except Exception:
            pass
    return eval_results.load(eval_results.RESULTS_DIR / f"{name}.json")


# --------------------------------------------------------------------------- #
# small render helpers
# --------------------------------------------------------------------------- #

def badge(text: str, color: str) -> str:
    return (f"<span style='background:{color};color:#fff;padding:2px 8px;border-radius:10px;"
            f"font-size:0.78rem;font-weight:600;white-space:nowrap'>{text}</span>")


def pct(x: float) -> str:
    return f"{x * 100:.0f}%"


def _error_detail(resp) -> str:
    """Pull the API's human-readable `detail` out of an error response (FastAPI puts the
    clear message there), falling back to the raw body."""
    try:
        return resp.json().get("detail", resp.text)
    except Exception:
        return resp.text


# --------------------------------------------------------------------------- #
# BENCHMARK TAB
# --------------------------------------------------------------------------- #

def render_benchmark(r: eval_results.BenchmarkResult) -> None:
    st.caption(f"**{r.label}** · target `{r.target}` · model `{r.model}` · mode `{r.mode}` · "
               f"{r.created_at:%Y-%m-%d %H:%M}")

    iso = r.overall_in_scope
    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Precision (in-scope)", pct(iso.precision))
    k2.metric("Recall (in-scope)", pct(iso.recall))
    k3.metric("False-positive rate", pct(iso.fp_rate))
    k4.metric("Avg attempts / success", f"{r.avg_attempts_to_success:.2f}")
    st.caption("In-scope = the vulnerability classes AutoRedTeam is designed to verify "
               "deterministically. Every finding is execution-proven, so the deterministic "
               "false-positive rate is the headline number.")

    left, right = st.columns([3, 2])

    with left:
        st.subheader("Per-class results")
        if r.per_class:
            rows = [{"class": c.label, "metric": m, "count": getattr(c, m)}
                    for c in r.per_class for m in ("tp", "fp", "fn")]
            df = pd.DataFrame(rows)
            chart = (alt.Chart(df).mark_bar().encode(
                x=alt.X("class:N", title=None, axis=alt.Axis(labelAngle=-20)),
                xOffset="metric:N",
                y=alt.Y("count:Q", title="count"),
                color=alt.Color("metric:N", scale=alt.Scale(
                    domain=["tp", "fp", "fn"], range=["#1a7f4b", "#b3123b", "#e8a13a"]),
                    legend=alt.Legend(title="")),
                tooltip=["class", "metric", "count"])
                .properties(height=240))
            st.altair_chart(chart, use_container_width=True)
        else:
            st.info("No per-class data in this snapshot.")

    with right:
        st.subheader("Scope honesty")
        scope_df = pd.DataFrame([
            {"view": "In-scope", "recall": iso.recall},
            {"view": "All documented vulns", "recall": r.overall_all.recall},
        ])
        chart = (alt.Chart(scope_df).mark_bar(size=46).encode(
            x=alt.X("view:N", title=None),
            y=alt.Y("recall:Q", title="recall", scale=alt.Scale(domain=[0, 1])),
            color=alt.value("#2f6fb0"),
            tooltip=["view", alt.Tooltip("recall:Q", format=".2f")])
            .properties(height=240))
        text = chart.mark_text(dy=-8, color="#ccc").encode(text=alt.Text("recall:Q", format=".2f"))
        st.altair_chart(chart + text, use_container_width=True)
        st.caption("Recall drops honestly when scored against classes the system is not "
                   "designed to catch — denominator is not cherry-picked.")

    # agent variance + RAG ablation
    cols = st.columns(2)
    with cols[0]:
        st.subheader("Agent-mode variance")
        if r.agent_recall:
            a1, a2, a3 = st.columns(3)
            a1.metric("Recall", f"{pct(r.agent_recall.mean)}",
                      f"± {r.agent_recall.stddev:.2f}" if r.agent_recall.stddev else "stable")
            a2.metric("Precision", f"{pct(r.agent_precision.mean)}",
                      f"± {r.agent_precision.stddev:.2f}" if r.agent_precision.stddev else "stable")
            a3.metric("Attempts", f"{r.agent_attempts.mean:.2f}",
                      f"± {r.agent_attempts.stddev:.2f}")
            st.caption(f"Mean ± stddev across {r.agent_recall.n} LLM seeds — shows the "
                       f"result is reproducible, not a lucky run.")
        else:
            st.info("This snapshot has no multi-seed agent data.")
    with cols[1]:
        st.subheader("RAG ablation")
        if r.rag_ablation:
            rows = [{"config": a.label, "metric": m, "value": getattr(a, {"recall": "recall",
                     "precision": "precision"}[m])}
                    for a in r.rag_ablation for m in ("recall", "precision")]
            df = pd.DataFrame(rows)
            chart = (alt.Chart(df).mark_bar().encode(
                x=alt.X("config:N", title=None), xOffset="metric:N",
                y=alt.Y("value:Q", title=None, scale=alt.Scale(domain=[0, 1])),
                color=alt.Color("metric:N", legend=alt.Legend(title="")),
                tooltip=["config", "metric", alt.Tooltip("value:Q", format=".2f")])
                .properties(height=200))
            st.altair_chart(chart, use_container_width=True)
            st.caption("Knowledge base on vs off. No accuracy delta here = the in-scope set "
                       "is already saturated (ablation-on-easy-set limitation).")
        else:
            st.info("No RAG ablation in this snapshot.")

    # ZAP head-to-head — the noise/precision thesis
    if r.zap and r.zap.ran:
        st.subheader("AutoRedTeam vs OWASP ZAP — signal, not noise")
        z = r.zap
        zdf = pd.DataFrame([
            {"tool": f"ZAP raw alerts ({z.mode})", "count": z.total_alerts, "kind": "noise"},
            {"tool": "ZAP mapped to in-scope class", "count": len(z.mapped_in_scope_classes), "kind": "noise"},
            {"tool": "AutoRedTeam confirmed (PoC-backed)", "count": z.autoredteam_confirmed, "kind": "signal"},
        ])
        chart = (alt.Chart(zdf).mark_bar().encode(
            y=alt.Y("tool:N", title=None, sort="-x"),
            x=alt.X("count:Q", title="count (log scale)", scale=alt.Scale(type="symlog")),
            color=alt.Color("kind:N", scale=alt.Scale(domain=["noise", "signal"],
                            range=["#b3123b", "#1a7f4b"]), legend=alt.Legend(title="")),
            tooltip=["tool", "count"])
            .properties(height=160))
        labels = chart.mark_text(align="left", dx=4, color="#ccc").encode(text="count:Q")
        st.altair_chart(chart + labels, use_container_width=True)
        st.caption(z.note)

    # confusion breakdown
    st.subheader("What was found, missed, and (not) false-flagged")
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(f"**{badge('Confirmed (TP)', '#1a7f4b')}**", unsafe_allow_html=True)
        for f in r.findings:
            st.markdown(f"- **{f.vuln_class}** — {vuln_name(f.vuln_class)}  \n"
                        f"  `{f.endpoint}` · {f.severity} (CVSS {f.cvss_score}) · "
                        f"attempt {f.attempt_number}")
        if not r.findings:
            st.caption("none")
    with c2:
        st.markdown(f"**{badge('Missed (FN)', '#e8a13a')}**", unsafe_allow_html=True)
        for m in r.missed:
            tag = "" if m.get("in_scope", True) else " _(out-of-scope)_"
            st.markdown(f"- `{m['vuln_class']}` @ `{m['endpoint']}`{tag}")
        if not r.missed:
            st.caption("none")
    with c3:
        st.markdown(f"**{badge('False positives', '#b3123b')}**", unsafe_allow_html=True)
        for f in r.false_positives:
            st.markdown(f"- `{f.vuln_class}` @ `{f.endpoint}` ({f.confidence})")
        if not r.false_positives:
            st.caption("none — every finding is execution-proven")

    # plain-English glossary for every class that appears in this result
    render_glossary([f.vuln_class for f in r.findings]
                    + [m["vuln_class"] for m in r.missed]
                    + [s.vuln_class for s in r.scenarios])

    if r.notes:
        with st.expander("Run notes"):
            for n in r.notes:
                st.markdown(f"- {n}")


# --------------------------------------------------------------------------- #
# SCENARIO TAB
# --------------------------------------------------------------------------- #

def render_scenarios(r: eval_results.BenchmarkResult) -> None:
    if not r.scenarios:
        st.info("This snapshot has no scenario sweep.")
        return
    passed = sum(1 for s in r.scenarios if s.passed is True)
    runnable = sum(1 for s in r.scenarios if s.passed is not None)
    st.caption(f"Each scenario declares an **expected** verdict; the verifier produces the "
               f"**actual** one. {passed}/{runnable} runnable scenarios behaved as expected "
               f"(out-of-scope misses are shown but not counted).")

    for s in r.scenarios:
        color, kind_label = KIND_STYLE.get(s.kind, ("#888", s.kind))
        exp = "exploitable" if s.expected_exploited else "safe"
        act = ("not run" if s.actual_exploited is None
               else ("exploited" if s.actual_exploited else "safe"))
        status = ("PASS" if s.passed else ("— " if s.passed is None else "FAIL"))
        with st.container(border=True):
            top = st.columns([3, 2, 2, 1.4])
            top[0].markdown(f"**{s.name}** &nbsp; {badge(kind_label, color)}",
                            unsafe_allow_html=True)
            top[1].markdown(f"class `{s.vuln_class}`")
            top[2].markdown(f"expected **{exp}** → actual **{act}**")
            top[3].markdown(badge(status, PASS_COLOR[s.passed]), unsafe_allow_html=True)
            st.markdown(f"<span style='color:#999'>`{s.endpoint}` — {s.description}</span>",
                        unsafe_allow_html=True)
            if s.note:
                st.caption(s.note)

    render_glossary([s.vuln_class for s in r.scenarios])


# --------------------------------------------------------------------------- #
# LIVE RUN TAB
# --------------------------------------------------------------------------- #

def render_live_run() -> None:
    st.caption("Start a real red-team run against the sandbox target. Requires the API "
               "(and the Docker sandbox + LLM key) to be running.")
    c = st.columns([2, 1, 1, 1])
    target = c[0].text_input("Target base URL", "http://127.0.0.1:3000")
    request_cap = c[1].number_input("Request cap", 10, 5000, 500, step=10)
    max_retries = c[2].number_input("Max retries", 1, 10, 3)
    use_rag = c[3].checkbox("Use RAG", value=False)

    if st.button("Start run", type="primary"):
        try:
            resp = _request("POST", "/runs", json={
                "target_base_url": target, "request_cap": int(request_cap),
                "max_retries": int(max_retries), "use_rag": bool(use_rag)})
            if resp.status_code >= 400:
                st.error(f"Could not start run: {_error_detail(resp)}")
            else:
                st.session_state["run_id"] = resp.json()["run_id"]
        except Exception as exc:
            st.error(f"Could not reach the API at {_api_base()}: {exc}")

    run_id = st.session_state.get("run_id")
    if not run_id:
        st.info("Configure the run above and click **Start run**.")
        return

    st.caption(f"run_id: `{run_id}`")
    status_box = st.empty()
    status = {}
    try:
        for _ in range(600):
            status = _request("GET", f"/runs/{run_id}").json()
            status_box.info(f"status: **{status['status']}** · attempts: "
                            f"{status['attempts']} · requests: {status['request_count']}")
            if status["status"] in ("completed", "error"):
                break
            time.sleep(1)

        if status.get("status") == "error":
            st.error(f"Run failed: {status.get('error')}")
        elif status.get("status") == "completed":
            findings = _request("GET", f"/runs/{run_id}/findings").json()
            st.subheader(f"{len(findings)} verified finding(s)")
            if not findings:
                st.warning("No verified findings (nothing was proven exploitable).")
            for f in findings:
                v = f["verification"]
                sev = f["severity"]
                color = SEV_COLOR.get(sev, "#888")
                vclass = v['hypothesis']['vuln_class']
                st.markdown(
                    f"### {badge(sev.upper(), color)} "
                    f"{vclass} — CVSS {f['cvss_score']}", unsafe_allow_html=True)
                st.caption(vuln_name(vclass))
                finding_explainer(vclass)   # plain-English "what is this?"
                st.code(f["cvss_vector"], language="text")
                m = st.columns(3)
                m[0].markdown(f"**Endpoint**\n\n`{v['hypothesis']['endpoint']['url']}`")
                m[1].markdown(f"**Confidence**\n\n{v['confidence']}")
                m[2].markdown(f"**Attempt**\n\n{v['hypothesis']['attempt_number']}")
                st.markdown("**Proof-of-concept steps**")
                for i, step in enumerate(f["poc_steps"], 1):
                    st.markdown(f"{i}. {step}")
                st.markdown("**Remediation**")
                st.info(f["remediation"])
                st.divider()
    except Exception as exc:
        st.error(f"API error: {exc}")


# --------------------------------------------------------------------------- #
# layout
# --------------------------------------------------------------------------- #

st.title("🛡️ AutoRedTeam — execution-verified pentest")

with st.sidebar:
    st.header("Connection")
    st.session_state["api_base"] = st.text_input("API base URL", _api_base())
    up = api_online(_api_base())
    st.markdown(badge("API online" if up else "API offline — using saved snapshots",
                      "#1a7f4b" if up else "#8a6d1a"), unsafe_allow_html=True)
    st.divider()
    st.header("Benchmark data")
    snaps = list_snapshots(up)
    options = {s["name"]: f"{s['label']}  ·  R={pct(s['in_scope_recall'])} "
                           f"P={pct(s['in_scope_precision'])}" for s in snaps}
    chosen = st.selectbox("Saved result", list(options.keys()),
                          format_func=lambda n: options.get(n, n)) if options else None
    st.divider()
    st.caption("Run a fresh benchmark against the sandbox (needs the API up):")
    run_mode = st.radio("Mode", ["engine (fast, deterministic)", "agent (LLM)"], index=0)
    if st.button("Run benchmark now"):
        if not up:
            st.error("API offline — start uvicorn to run live.")
        else:
            with st.spinner("Running benchmark against the sandbox…"):
                try:
                    mode = "engine" if run_mode.startswith("engine") else "agent"
                    resp = _request("POST", "/benchmark",
                                    json={"target_base_url": "http://127.0.0.1:3000",
                                          "mode": mode}, timeout=300)
                    if resp.status_code >= 400:
                        st.error(f"Benchmark failed: {_error_detail(resp)}")
                    else:
                        st.session_state["fresh_result"] = resp.json()
                        st.success("Benchmark complete — shown in the Benchmark tab.")
                except Exception as exc:
                    st.error(f"Benchmark failed: {exc}")

tab_bench, tab_scen, tab_live = st.tabs(["📊 Benchmark", "🧪 Scenarios", "🚀 Live Run"])

# resolve the result to display: a freshly-run one wins, else the selected snapshot
result = None
if st.session_state.get("fresh_result"):
    result = eval_results.BenchmarkResult.model_validate(st.session_state["fresh_result"])
elif chosen:
    try:
        result = load_snapshot(chosen, up)
    except Exception as exc:
        st.sidebar.error(f"Could not load snapshot: {exc}")

with tab_bench:
    if result:
        render_benchmark(result)
    else:
        st.info("No benchmark results found. Generate the bundled snapshot with "
                "`python scripts/make_snapshots.py`, or run one from the sidebar.")

with tab_scen:
    if result:
        render_scenarios(result)
    else:
        st.info("Select or run a benchmark to see its scenario sweep.")

with tab_live:
    render_live_run()
