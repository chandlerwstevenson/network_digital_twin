#!/usr/bin/env python3
"""
Web dashboard for SDN Fault Diagnosis experiment results.

Shows 4-engine comparison (rule-based, LLM, ML, hybrid) with:
- Accuracy bar chart with 95% CI error bars
- Cost-per-correct-diagnosis comparison
- Hybrid engine defer-rate and cost-savings panel
- Pairwise statistical significance table (McNemar + Cohen's h)
- Per-fault-class F1 breakdown
- Timing comparison for all engines
- Trial-level detail table with all engines
- Network topology SVG

Usage:
    python dashboard.py
    python dashboard.py --port 8050
    python dashboard.py --results evaluation/results/results_20260302_055742.json
"""

import argparse
import json
import glob
import os
import sys
from pathlib import Path

from flask import Flask, render_template_string, jsonify

app = Flask(__name__)

RESULTS_DIR = Path("./evaluation/results")


def find_latest_results() -> dict | None:
    pattern = str(RESULTS_DIR / "results_*.json")
    files = sorted(glob.glob(pattern))
    if not files:
        return None
    real = [f for f in files if "_mock" not in f]
    target = real[-1] if real else files[-1]
    with open(target) as f:
        return json.load(f)


def find_latest_trials() -> list | None:
    pattern = str(RESULTS_DIR / "trials_*.json")
    files = sorted(glob.glob(pattern))
    if not files:
        return None
    real = [f for f in files if "_mock" not in f]
    target = real[-1] if real else files[-1]
    with open(target) as f:
        return json.load(f)


_cached_results = None
_cached_trials = None


def get_results():
    global _cached_results
    if _cached_results is None:
        _cached_results = find_latest_results()
    return _cached_results


def get_trials():
    global _cached_trials
    if _cached_trials is None:
        _cached_trials = find_latest_trials()
    return _cached_trials


@app.route("/api/results")
def api_results():
    r = get_results()
    return jsonify(r if r else {"error": "No results found"})


@app.route("/api/trials")
def api_trials():
    t = get_trials()
    return jsonify(t if t else [])


@app.route("/api/topology")
def api_topology():
    return jsonify({
        "spines": ["spine1", "spine2", "spine3", "spine4"],
        "leaves": ["leaf1", "leaf2", "leaf3", "leaf4"],
        "hosts": {
            "leaf1": ["host1", "host2"],
            "leaf2": ["host3", "host4"],
            "leaf3": ["host5", "host6"],
            "leaf4": ["host7", "host8"],
        },
        "spine_ips": {"spine1": "10.0.0.1", "spine2": "10.0.0.2", "spine3": "10.0.0.3", "spine4": "10.0.0.4"},
        "leaf_ips": {"leaf1": "10.0.1.1", "leaf2": "10.0.1.2", "leaf3": "10.0.1.3", "leaf4": "10.0.1.4"},
        "host_subnets": {"leaf1": "192.168.1.0/24", "leaf2": "192.168.2.0/24", "leaf3": "192.168.3.0/24", "leaf4": "192.168.4.0/24"},
    })


DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SDN Fault Diagnosis Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
<style>
  :root {
    --bg: #0f1117; --card: #1a1d2e; --border: #2a2d3e;
    --text: #e2e8f0; --text-dim: #94a3b8;
    --accent: #6366f1; --accent2: #22d3ee; --green: #34d399;
    --red: #f87171; --orange: #fb923c; --yellow: #fbbf24;
    --ml: #a78bfa; --hybrid: #f472b6;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Inter', -apple-system, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }
  .header { background: linear-gradient(135deg, #1e1b4b 0%, #1a1d2e 100%); border-bottom: 1px solid var(--border); padding: 1.5rem 2rem; display: flex; align-items: center; gap: 1rem; }
  .header h1 { font-size: 1.5rem; font-weight: 700; background: linear-gradient(135deg, var(--accent), var(--accent2)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
  .header .badge { background: var(--accent); color: white; font-size: 0.7rem; padding: 0.2rem 0.6rem; border-radius: 9999px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
  .container { max-width: 1500px; margin: 0 auto; padding: 1.5rem; }
  .summary-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 0.8rem; margin-bottom: 1.5rem; }
  .stat-card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 1rem; text-align: center; transition: transform 0.15s; }
  .stat-card:hover { transform: translateY(-2px); box-shadow: 0 8px 24px rgba(0,0,0,0.3); }
  .stat-card .label { font-size: 0.7rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 0.3rem; }
  .stat-card .value { font-size: 1.6rem; font-weight: 700; }
  .stat-card .sub { font-size: 0.75rem; color: var(--text-dim); margin-top: 0.2rem; }
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 1.5rem; }
  .grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 1.5rem; margin-bottom: 1.5rem; }
  .grid-full { margin-bottom: 1.5rem; }
  @media (max-width: 1100px) { .grid-3 { grid-template-columns: 1fr; } }
  @media (max-width: 900px) { .grid-2 { grid-template-columns: 1fr; } }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; }
  .card h2 { font-size: 0.9rem; font-weight: 600; margin-bottom: 1rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.06em; }
  .card canvas { width: 100% !important; }
  #topology-svg { width: 100%; height: auto; }
  .topo-node { cursor: pointer; } .topo-node:hover { filter: brightness(1.3); }
  .topo-link { stroke: #475569; stroke-width: 2; } .topo-link:hover { stroke: var(--accent); stroke-width: 3; }
  .topo-label { fill: var(--text); font-size: 11px; font-weight: 600; text-anchor: middle; pointer-events: none; }
  .topo-sublabel { fill: var(--text-dim); font-size: 9px; text-anchor: middle; pointer-events: none; }
  .pair-table { width: 100%; border-collapse: collapse; font-size: 0.78rem; }
  .pair-table th { text-align: left; padding: 0.5rem; border-bottom: 2px solid var(--border); color: var(--text-dim); font-size: 0.7rem; text-transform: uppercase; }
  .pair-table td { padding: 0.5rem; border-bottom: 1px solid var(--border); }
  .pair-table tr:hover td { background: rgba(99,102,241,0.06); }
  .trial-table { width: 100%; border-collapse: collapse; font-size: 0.78rem; }
  .trial-table th { text-align: left; padding: 0.6rem 0.4rem; border-bottom: 2px solid var(--border); color: var(--text-dim); font-weight: 600; text-transform: uppercase; font-size: 0.65rem; letter-spacing: 0.06em; }
  .trial-table td { padding: 0.5rem 0.4rem; border-bottom: 1px solid var(--border); }
  .trial-table tr:hover td { background: rgba(99,102,241,0.06); }
  .pill { display: inline-block; padding: 0.12rem 0.45rem; border-radius: 6px; font-size: 0.68rem; font-weight: 600; }
  .pill-correct { background: rgba(52,211,153,0.15); color: var(--green); }
  .pill-wrong { background: rgba(248,113,113,0.15); color: var(--red); }
  .pill-fault { background: rgba(99,102,241,0.15); color: var(--accent); }
  .pill-defer { background: rgba(244,114,182,0.15); color: var(--hybrid); }
  .no-data { text-align: center; padding: 3rem; color: var(--text-dim); font-size: 1.1rem; }
  .no-data p { margin-top: 0.5rem; font-size: 0.9rem; }
  .tooltip-box { position: fixed; background: #1e2030; border: 1px solid var(--border); border-radius: 8px; padding: 0.7rem 1rem; font-size: 0.8rem; pointer-events: none; z-index: 1000; opacity: 0; transition: opacity 0.15s; max-width: 260px; box-shadow: 0 8px 24px rgba(0,0,0,0.5); }
  .tooltip-box.visible { opacity: 1; }
  .eng-rb { color: var(--accent2); } .eng-llm { color: var(--accent); } .eng-ml { color: var(--ml); } .eng-hybrid { color: var(--hybrid); }
</style>
</head>
<body>
<div class="header">
  <h1>SDN Fault Diagnosis</h1>
  <span class="badge">4-Engine Comparison</span>
</div>
<div class="container" id="app"><div class="no-data" id="loading">Loading results...</div></div>
<div class="tooltip-box" id="tooltip"></div>

<script>
const C = { rb: '#22d3ee', llm: '#6366f1', ml: '#a78bfa', hybrid: '#f472b6', green: '#34d399', red: '#f87171', dim: '#94a3b8' };
const ENGINE_LABELS = { rule_based: 'Rule-Based', llm: 'LLM Agent', ml: 'ML (RF)', hybrid: 'Hybrid' };
const ENGINE_COLORS = { rule_based: C.rb, llm: C.llm, ml: C.ml, hybrid: C.hybrid };

const tooltipEl = document.getElementById('tooltip');
function showTooltip(e, html) { tooltipEl.innerHTML = html; tooltipEl.style.left = (e.clientX+14)+'px'; tooltipEl.style.top = (e.clientY+14)+'px'; tooltipEl.classList.add('visible'); }
function hideTooltip() { tooltipEl.classList.remove('visible'); }

function buildTopology(topo) {
  const W=800,H=420,spineY=60,leafY=200,hostY=340;
  const spineXs=topo.spines.map((_,i)=>140+i*160), leafXs=topo.leaves.map((_,i)=>140+i*160);
  let s=`<svg id="topology-svg" viewBox="0 0 ${W} ${H}" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="gSpine" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#6366f1"/><stop offset="100%" stop-color="#4f46e5"/></linearGradient><linearGradient id="gLeaf" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#22d3ee"/><stop offset="100%" stop-color="#0891b2"/></linearGradient><linearGradient id="gHost" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#475569"/><stop offset="100%" stop-color="#334155"/></linearGradient><filter id="glow"><feDropShadow dx="0" dy="0" stdDeviation="3" flood-color="#6366f1" flood-opacity="0.4"/></filter></defs>`;
  topo.spines.forEach((sp,si)=>topo.leaves.forEach((l,li)=>{s+=`<line class="topo-link" x1="${spineXs[si]}" y1="${spineY+20}" x2="${leafXs[li]}" y2="${leafY-20}"/>`;}));
  topo.leaves.forEach((l,li)=>{const cx=leafXs[li];(topo.hosts[l]||[]).forEach((h,hi)=>{const hx=cx+(hi===0?-30:30);s+=`<line class="topo-link" x1="${cx}" y1="${leafY+20}" x2="${hx}" y2="${hostY-16}" style="stroke-dasharray:5,4"/>`;});});
  topo.spines.forEach((sp,i)=>{const x=spineXs[i];s+=`<g class="topo-node" data-node="${sp}"><rect x="${x-44}" y="${spineY-20}" width="88" height="40" rx="10" fill="url(#gSpine)" filter="url(#glow)"/><text class="topo-label" x="${x}" y="${spineY+4}">${sp}</text><text class="topo-sublabel" x="${x}" y="${spineY+30}">${topo.spine_ips[sp]}</text></g>`;});
  topo.leaves.forEach((l,i)=>{const x=leafXs[i];s+=`<g class="topo-node" data-node="${l}"><rect x="${x-44}" y="${leafY-20}" width="88" height="40" rx="10" fill="url(#gLeaf)"/><text class="topo-label" x="${x}" y="${leafY+4}">${l}</text><text class="topo-sublabel" x="${x}" y="${leafY+30}">${topo.leaf_ips[l]}</text></g>`;});
  topo.leaves.forEach((l,li)=>{const cx=leafXs[li];(topo.hosts[l]||[]).forEach((h,hi)=>{const hx=cx+(hi===0?-30:30);s+=`<g class="topo-node" data-node="${h}"><rect x="${hx-24}" y="${hostY-16}" width="48" height="32" rx="6" fill="url(#gHost)"/><text class="topo-label" x="${hx}" y="${hostY+4}" style="font-size:9px">${h}</text></g>`;});s+=`<text class="topo-sublabel" x="${cx}" y="${hostY+32}">${topo.host_subnets[l]}</text>`;});
  s+=`<text x="30" y="${spineY+5}" style="fill:#6366f1;font-size:11px;font-weight:700">SPINE</text><text x="30" y="${leafY+5}" style="fill:#22d3ee;font-size:11px;font-weight:700">LEAF</text><text x="30" y="${hostY+5}" style="fill:#64748b;font-size:11px;font-weight:700">HOSTS</text></svg>`;
  return s;
}

async function init() {
  const [rR,tR,topoR] = await Promise.all([fetch('/api/results'),fetch('/api/trials'),fetch('/api/topology')]);
  const results=await rR.json(), trials=await tR.json(), topo=await topoR.json();
  const container = document.getElementById('app');

  if (results.error) { container.innerHTML = `<div class="no-data"><h2>No Results Found</h2><p>Run: <code style="color:var(--accent)">python -m evaluation.runner --trials 10 --mock-llm</code></p></div>`; return; }

  const m = results.metrics, meta = results.run_metadata || {}, st = results.statistical_tests || {}, perClass = results.per_class || {};
  const pct = v => (v*100).toFixed(1)+'%';

  // Detect available engines
  const engines = [];
  if (m.rule_based) engines.push({key:'rule_based', m:m.rule_based});
  if (m.llm_agent) engines.push({key:'llm', m:m.llm_agent});
  if (m.ml_engine) engines.push({key:'ml', m:m.ml_engine});
  if (m.hybrid_engine) engines.push({key:'hybrid', m:m.hybrid_engine});

  const costData = st.cost_analysis || {};
  const ciData = st.bootstrap_ci || {};
  const pairwise = st.pairwise_comparisons || {};

  let html = '';

  // === SUMMARY CARDS ===
  html += '<div class="summary-row">';
  html += `<div class="stat-card"><div class="label">Trials</div><div class="value" style="color:var(--accent)">${m.trial_count}</div><div class="sub">${results.elapsed_seconds?(results.elapsed_seconds/60).toFixed(1)+' min':''}</div></div>`;

  engines.forEach(eng => {
    const cls = eng.m.classification;
    const ci = ciData[eng.key];
    const ciStr = ci ? ` [${(ci.ci_95[0]*100).toFixed(1)}, ${(ci.ci_95[1]*100).toFixed(1)}]` : '';
    html += `<div class="stat-card"><div class="label">${ENGINE_LABELS[eng.key]} Accuracy</div><div class="value" style="color:${ENGINE_COLORS[eng.key]}">${pct(cls.accuracy)}</div><div class="sub">${cls.correct}/${cls.total}${ciStr}</div></div>`;
  });

  // Hybrid defer rate card
  if (m.hybrid_engine) {
    const hybridCost = costData.hybrid;
    const llmCost = costData.llm;
    const savings = llmCost && llmCost.total_cost_usd > 0 ? ((1 - (hybridCost?.total_cost_usd||0)/llmCost.total_cost_usd)*100).toFixed(0) : 'N/A';
    html += `<div class="stat-card"><div class="label">Hybrid Cost Savings</div><div class="value" style="color:var(--hybrid)">${savings}%</div><div class="sub">vs always-LLM</div></div>`;
  }

  html += `<div class="stat-card"><div class="label">LLM Model</div><div class="value" style="color:var(--accent);font-size:1rem">${meta.llm_model||'N/A'}</div><div class="sub">Tokens: ${((meta.llm_total_input_tokens||0)+(meta.llm_total_output_tokens||0)).toLocaleString()}</div></div>`;
  html += '</div>';

  // === ACCURACY + COST CHARTS ROW ===
  html += '<div class="grid-2">';
  html += '<div class="card"><h2>Classification Accuracy with 95% CI</h2><canvas id="chart-accuracy" height="280"></canvas></div>';
  html += '<div class="card"><h2>Cost per Correct Diagnosis (USD)</h2><canvas id="chart-cost" height="280"></canvas></div>';
  html += '</div>';

  // === TOPOLOGY + PER-CLASS ROW ===
  html += '<div class="grid-2">';
  html += `<div class="card"><h2>Network Topology</h2>${buildTopology(topo)}</div>`;
  html += '<div class="card"><h2>Per-Fault-Class F1 Score</h2><canvas id="chart-perclass" height="280"></canvas></div>';
  html += '</div>';

  // === PAIRWISE STATS + TIMING + HYBRID ROW ===
  html += '<div class="grid-3">';

  // Pairwise table
  html += '<div class="card"><h2>Pairwise Statistical Tests</h2><table class="pair-table"><thead><tr><th>Pair</th><th>p-value</th><th>Cohen\'s h</th><th>Acc Diff</th></tr></thead><tbody>';
  Object.entries(pairwise).forEach(([key, pw]) => {
    const mc = pw.mcnemar || {};
    const sig = mc.significant;
    const pv = mc.p_value !== undefined ? mc.p_value.toFixed(4) : 'N/A';
    const h = pw.cohens_h !== undefined ? pw.cohens_h.toFixed(3) : 'N/A';
    const interp = pw.cohens_h_interpretation || '';
    const diff = pw.accuracy_difference !== undefined ? (pw.accuracy_difference >= 0 ? '+' : '') + (pw.accuracy_difference * 100).toFixed(1) + '%' : '';
    const label = key.replace(/_vs_/,' vs ').replace('rule_based','RB').replace('llm','LLM').replace('ml','ML').replace('hybrid','Hybrid');
    html += `<tr><td style="font-weight:600">${label}</td><td><span style="color:${sig?'var(--green)':'var(--text-dim)'}">${pv}</span></td><td>${h} <span style="color:var(--text-dim);font-size:0.7rem">${interp}</span></td><td style="font-family:monospace">${diff}</td></tr>`;
  });
  html += '</tbody></table></div>';

  // Timing chart
  html += '<div class="card"><h2>Diagnosis Latency (ms)</h2><canvas id="chart-time" height="280"></canvas></div>';

  // Hybrid panel
  html += '<div class="card"><h2>Hybrid Engine Breakdown</h2>';
  if (m.hybrid_engine) {
    const hTime = m.hybrid_engine.time;
    const hCost = costData.hybrid || {};
    const lCost = costData.llm || {};
    html += `<div style="display:grid;grid-template-columns:1fr 1fr;gap:0.8rem;margin-bottom:1rem">`;
    html += `<div style="text-align:center"><div style="font-size:0.7rem;color:var(--text-dim);text-transform:uppercase">Accuracy</div><div style="font-size:1.8rem;font-weight:700;color:var(--hybrid)">${pct(m.hybrid_engine.classification.accuracy)}</div></div>`;
    html += `<div style="text-align:center"><div style="font-size:0.7rem;color:var(--text-dim);text-transform:uppercase">Median Time</div><div style="font-size:1.8rem;font-weight:700;color:var(--hybrid)">${hTime.median_ms.toFixed(0)}<span style="font-size:0.8rem">ms</span></div></div>`;
    html += `<div style="text-align:center"><div style="font-size:0.7rem;color:var(--text-dim);text-transform:uppercase">Cost/Correct</div><div style="font-size:1.4rem;font-weight:700;color:var(--hybrid)">$${(hCost.cost_per_correct_usd||0).toFixed(4)}</div></div>`;
    html += `<div style="text-align:center"><div style="font-size:0.7rem;color:var(--text-dim);text-transform:uppercase">LLM Cost/Correct</div><div style="font-size:1.4rem;font-weight:700;color:var(--accent)">$${(lCost.cost_per_correct_usd||0).toFixed(4)}</div></div>`;
    html += '</div>';
    html += '<canvas id="chart-hybrid-pie" height="180"></canvas>';
  } else {
    html += '<div style="color:var(--text-dim);text-align:center;padding:2rem">Run with hybrid engine to see data</div>';
  }
  html += '</div></div>';

  // === BOOTSTRAP CI BARS ===
  html += '<div class="grid-full"><div class="card"><h2>95% Bootstrap Confidence Intervals</h2>';
  engines.forEach(eng => {
    const ci = ciData[eng.key];
    if (!ci) return;
    const lo = ci.ci_95[0]*100, hi = ci.ci_95[1]*100, acc = ci.accuracy*100;
    html += `<div style="margin-bottom:0.8rem"><div style="font-size:0.78rem;color:var(--text-dim)">${ENGINE_LABELS[eng.key]}: <span style="color:${ENGINE_COLORS[eng.key]};font-weight:600">${acc.toFixed(1)}%</span> [${lo.toFixed(1)}, ${hi.toFixed(1)}]</div>`;
    html += `<div style="position:relative;height:20px;background:rgba(255,255,255,0.05);border-radius:6px;margin-top:0.3rem">`;
    html += `<div style="position:absolute;left:${lo}%;width:${Math.max(hi-lo,0.5)}%;height:100%;background:${ENGINE_COLORS[eng.key]};opacity:0.5;border-radius:6px"></div>`;
    html += `<div style="position:absolute;left:${acc}%;top:0;width:3px;height:100%;background:${ENGINE_COLORS[eng.key]};border-radius:2px"></div>`;
    html += '</div></div>';
  });
  html += '</div></div>';

  // === TRIAL TABLE ===
  html += '<div class="grid-full"><div class="card"><h2>Trial Details (' + trials.length + ' trials)</h2><div style="overflow-x:auto"><table class="trial-table"><thead><tr><th>#</th><th>Fault</th><th>Location</th>';
  engines.forEach(eng => { html += `<th>${ENGINE_LABELS[eng.key]}</th><th>OK?</th>`; });
  html += '</tr></thead><tbody>';

  trials.forEach((t, i) => {
    html += `<tr><td style="color:var(--text-dim)">${i+1}</td><td><span class="pill pill-fault">${t.injected_fault_type||'-'}</span></td><td style="font-family:monospace;font-size:0.72rem">${t.injected_fault_location||'-'}</td>`;
    engines.forEach(eng => {
      let diag, ok;
      if (eng.key === 'rule_based') { diag = t.rule_based_diagnosis||{}; ok = t.rule_based_correct_class; }
      else if (eng.key === 'llm') { diag = t.llm_diagnosis||{}; ok = t.llm_correct_class; }
      else if (eng.key === 'ml') { diag = t.ml_diagnosis||{}; ok = t.ml_correct_class; }
      else if (eng.key === 'hybrid') { diag = t.hybrid_diagnosis||{}; ok = t.hybrid_correct_class; }
      const cls = diag.fault_class || '-';
      html += `<td style="font-size:0.72rem">${cls}</td><td><span class="pill ${ok?'pill-correct':'pill-wrong'}">${ok?'Y':'N'}</span></td>`;
    });
    html += '</tr>';
  });
  html += '</tbody></table></div></div></div>';

  container.innerHTML = html;

  // ============ CHARTS ============
  const chartOpts = {
    responsive: true, maintainAspectRatio: false,
    plugins: { legend: { labels: { color: '#94a3b8', font: { size: 11 } } } },
    scales: { x: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.05)' } }, y: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.05)' } } }
  };

  // 1. ACCURACY BAR WITH ERROR BARS (using Chart.js native errorBars plugin not available, simulate with floating bars)
  const accLabels = engines.map(e => ENGINE_LABELS[e.key]);
  const accData = engines.map(e => e.m.classification.accuracy);
  const accColors = engines.map(e => ENGINE_COLORS[e.key] + 'cc');
  const accBorders = engines.map(e => ENGINE_COLORS[e.key]);

  new Chart(document.getElementById('chart-accuracy'), {
    type: 'bar',
    data: { labels: accLabels, datasets: [{ label: 'Accuracy', data: accData, backgroundColor: accColors, borderColor: accBorders, borderWidth: 1, borderRadius: 8 }] },
    options: { ...chartOpts, plugins: { ...chartOpts.plugins, legend: { display: false } }, scales: { ...chartOpts.scales, y: { ...chartOpts.scales.y, min: 0, max: 1, ticks: { ...chartOpts.scales.y.ticks, callback: v=>(v*100)+'%' } } } }
  });

  // 2. COST CHART
  const costEngines = engines.filter(e => costData[e.key]);
  if (costEngines.length > 0) {
    new Chart(document.getElementById('chart-cost'), {
      type: 'bar',
      data: {
        labels: costEngines.map(e => ENGINE_LABELS[e.key]),
        datasets: [
          { label: 'Cost/Diagnosis', data: costEngines.map(e => costData[e.key].cost_per_diagnosis_usd), backgroundColor: costEngines.map(e => ENGINE_COLORS[e.key] + '88'), borderRadius: 6 },
          { label: 'Cost/Correct', data: costEngines.map(e => costData[e.key].cost_per_correct_usd), backgroundColor: costEngines.map(e => ENGINE_COLORS[e.key] + 'cc'), borderRadius: 6 },
        ]
      },
      options: { ...chartOpts, scales: { ...chartOpts.scales, y: { ...chartOpts.scales.y, title: { display: true, text: 'USD', color: '#94a3b8' } } } }
    });
  }

  // 3. PER-CLASS F1
  const faultClasses = Object.keys(perClass);
  const pcDatasets = engines.map(eng => {
    const engKey = eng.key === 'llm' ? 'llm' : eng.key === 'rule_based' ? 'rule_based' : eng.key;
    return {
      label: ENGINE_LABELS[eng.key],
      data: faultClasses.map(f => { const d = perClass[f][engKey] || perClass[f][eng.key]; return d ? (d.f1||0) : 0; }),
      backgroundColor: ENGINE_COLORS[eng.key] + 'cc',
      borderRadius: 4,
    };
  });
  new Chart(document.getElementById('chart-perclass'), {
    type: 'bar',
    data: { labels: faultClasses.map(f => f.replace(/_/g,' ')), datasets: pcDatasets },
    options: { ...chartOpts, indexAxis: 'y', scales: { x: { ...chartOpts.scales.x, min: 0, max: 1 }, y: chartOpts.scales.y } }
  });

  // 4. TIME CHART
  const timeMetrics = ['mean_ms','median_ms','p95_ms'];
  const timeLabels = ['Mean','Median','P95'];
  new Chart(document.getElementById('chart-time'), {
    type: 'bar',
    data: {
      labels: timeLabels,
      datasets: engines.map(eng => ({
        label: ENGINE_LABELS[eng.key],
        data: timeMetrics.map(k => eng.m.time[k] || 0),
        backgroundColor: ENGINE_COLORS[eng.key] + 'cc',
        borderRadius: 6,
      }))
    },
    options: { ...chartOpts, scales: { ...chartOpts.scales, y: { ...chartOpts.scales.y, title: { display: true, text: 'ms', color: '#94a3b8' } } } }
  });

  // 5. HYBRID PIE (rule-accepted vs LLM-deferred) — use doughnut
  const hybridPieCanvas = document.getElementById('chart-hybrid-pie');
  if (hybridPieCanvas && m.hybrid_engine) {
    // Estimate from trials
    let rbAccepted = 0, llmDeferred = 0;
    trials.forEach(t => {
      if (t.hybrid_diagnosis && t.hybrid_diagnosis.raw_output) {
        try {
          const ro = JSON.parse(t.hybrid_diagnosis.raw_output);
          if (ro.source === 'rule_based') rbAccepted++;
          else llmDeferred++;
        } catch(e) { rbAccepted++; }
      }
    });
    new Chart(hybridPieCanvas, {
      type: 'doughnut',
      data: {
        labels: ['Rule-Based Accepted', 'LLM Deferred'],
        datasets: [{ data: [rbAccepted, llmDeferred], backgroundColor: [C.rb+'cc', C.llm+'cc'], borderWidth: 0 }]
      },
      options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8', font: { size: 11 } } } } }
    });
  }

  // Topology hover
  document.querySelectorAll('.topo-node').forEach(node => {
    node.addEventListener('mouseenter', e => {
      const n = node.dataset.node; let info = `<strong>${n}</strong>`;
      if (topo.spine_ips[n]) info += `<br>IP: ${topo.spine_ips[n]}<br>Role: Spine`;
      else if (topo.leaf_ips[n]) info += `<br>IP: ${topo.leaf_ips[n]}<br>Role: Leaf<br>Hosts: ${(topo.hosts[n]||[]).join(', ')}`;
      else info += '<br>Role: Host';
      showTooltip(e, info);
    });
    node.addEventListener('mouseleave', hideTooltip);
    node.addEventListener('mousemove', e => { tooltipEl.style.left=(e.clientX+14)+'px'; tooltipEl.style.top=(e.clientY+14)+'px'; });
  });
}
init();
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)


def main():
    parser = argparse.ArgumentParser(description="SDN Fault Diagnosis Dashboard")
    parser.add_argument("--port", type=int, default=8050, help="Port (default: 8050)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host")
    parser.add_argument("--results", type=str, help="Path to specific results JSON")
    parser.add_argument("--debug", action="store_true", help="Debug mode")
    args = parser.parse_args()

    global _cached_results, _cached_trials

    if args.results:
        with open(args.results) as f:
            _cached_results = json.load(f)
        trials_path = args.results.replace("results_", "trials_")
        if os.path.exists(trials_path):
            with open(trials_path) as f:
                _cached_trials = json.load(f)

    print(f"\n  SDN Fault Diagnosis Dashboard")
    print(f"  Open http://{args.host}:{args.port} in your browser\n")

    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
