"use strict";

// Same-origin API (FastAPI serves this SPA). Override for local split-dev.
const API = window.location.origin;

const $ = (id) => document.getElementById(id);
const fmt = (n) => (n == null ? "—" : Number(n).toLocaleString());

// The API emits UTC. SQLite timestamps arrive without a tz marker, so we tag
// them as UTC before parsing; Postgres values already carry an offset.
function parseUTC(iso) {
  if (!iso) return null;
  const hasTz = /[zZ]$|[+-]\d{2}:?\d{2}$/.test(iso);
  return new Date(hasTz ? iso : iso + "Z");
}

function timeAgo(iso) {
  const d = parseUTC(iso);
  if (!d) return "—";
  const s = Math.floor((Date.now() - d.getTime()) / 1000);
  if (s < 0) return "just now";
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function flag(cc) {
  if (!cc || cc.length !== 2) return "🏳️";
  return String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
}

function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.classList.add("show");
  setTimeout(() => t.classList.remove("show"), 2600);
}

async function api(path, opts) {
  const r = await fetch(API + path, opts);
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return r.status === 204 ? null : r.json();
}

// ---------- Tabs ----------
document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
    tab.classList.add("active");
    $(tab.dataset.panel).classList.add("active");
    if (tab.dataset.panel === "explorer") loadIocs();
    if (tab.dataset.panel === "watchlist") loadWatchlist();
  });
});

// ---------- Charts (Chart.js) ----------
let trendChart, typeChart;
const AXIS = "#5c6f8c";
const GRID = "rgba(34,48,74,0.5)";
const TYPE_COLORS = { url: "#35a0ff", ip: "#ff4d6d", domain: "#7c6bff", md5: "#ffb020", sha256: "#ffb020", sha1: "#ffb020" };

function renderTrend(trend) {
  const ctx = $("trend-chart");
  const labels = trend.map((t) => t.date.slice(5));
  const data = trend.map((t) => t.count);
  const g = ctx.getContext("2d").createLinearGradient(0, 0, 0, 240);
  g.addColorStop(0, "rgba(55,226,198,0.35)");
  g.addColorStop(1, "rgba(55,226,198,0)");
  if (trendChart) trendChart.destroy();
  trendChart = new Chart(ctx, {
    type: "line",
    data: { labels, datasets: [{ data, borderColor: "#37e2c6", backgroundColor: g, fill: true, tension: 0.35, pointRadius: 2, pointHoverRadius: 5, borderWidth: 2 }] },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: AXIS, maxRotation: 0, autoSkip: true, maxTicksLimit: 7 }, grid: { display: false } },
        y: { beginAtZero: true, ticks: { color: AXIS, precision: 0 }, grid: { color: GRID } },
      },
    },
  });
}

function renderTypes(byType) {
  const ctx = $("type-chart");
  if (typeChart) typeChart.destroy();
  typeChart = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: byType.map((t) => t.name),
      datasets: [{ data: byType.map((t) => t.count), backgroundColor: byType.map((t) => TYPE_COLORS[t.name] || "#8ba0bf"), borderColor: "#111726", borderWidth: 2 }],
    },
    options: {
      responsive: true, maintainAspectRatio: false, cutout: "62%",
      plugins: { legend: { position: "right", labels: { color: "#8ba0bf", boxWidth: 12, padding: 12, font: { size: 12 } } } },
    },
  });
}

function renderBarList(el, items, maxLabel) {
  if (!items.length) { el.innerHTML = '<div class="empty">No data yet.</div>'; return; }
  const max = Math.max(...items.map((i) => i.count));
  el.innerHTML = items
    .map((i) => {
      const pct = Math.max(4, (i.count / max) * 100);
      const name = maxLabel ? maxLabel(i) : i.name;
      return `<div class="barrow"><span class="name" title="${i.name}">${name}</span>
        <div class="bartrack"><div class="barfill" style="width:${pct}%"></div></div>
        <span class="cnt">${fmt(i.count)}</span></div>`;
    })
    .join("");
}

// ---------- Dashboard ----------
async function loadDashboard() {
  try {
    const s = await api("/api/stats");
    $("c-total").textContent = fmt(s.cards.total_iocs);
    $("c-new").textContent = fmt(s.cards.new_today);
    $("c-fam").textContent = fmt(s.cards.unique_families);
    $("c-feeds").textContent = fmt(s.cards.active_feeds);
    $("last-updated").textContent = "updated " + timeAgo(s.last_updated);
    renderTrend(s.trend);
    renderTypes(s.by_type);
    renderBarList($("families-list"), s.top_families);
    renderBarList($("geo-list"), s.map, (i) => `${flag(i.country)} ${i.country}`);
  } catch (e) {
    toast("Failed to load dashboard: " + e.message);
  }
}

// ---------- IOC Explorer ----------
let page = 0;
const PAGE_SIZE = 50;
let searchTimer;

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

async function loadIocs() {
  const params = new URLSearchParams({ limit: PAGE_SIZE, offset: page * PAGE_SIZE });
  const q = $("search").value.trim();
  if (q) params.set("q", q);
  if ($("filter-type").value) params.set("ioc_type", $("filter-type").value);
  if ($("filter-source").value) params.set("source", $("filter-source").value);

  const tbody = $("ioc-tbody");
  tbody.innerHTML = '<tr><td colspan="7" class="loading">loading…</td></tr>';
  try {
    const data = await api("/api/iocs?" + params);
    if (!data.items.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="empty">No indicators match your filters.</td></tr>';
    } else {
      tbody.innerHTML = data.items
        .map((i) => `<tr>
          <td class="val-cell mono" title="${escapeHtml(i.value)}">${escapeHtml(i.value)}</td>
          <td><span class="pill ${i.ioc_type}">${i.ioc_type}</span></td>
          <td>${escapeHtml(i.malware_family) || '<span style="color:var(--text-faint)">—</span>'}</td>
          <td><span class="pill src">${i.source}</span></td>
          <td>${i.country ? flag(i.country) + " " + i.country : "—"}</td>
          <td style="color:var(--text-dim)">${timeAgo(i.first_seen)}</td>
          <td style="color:var(--text-dim)">${timeAgo(i.last_seen)}</td>
        </tr>`)
        .join("");
    }
    const start = data.total ? page * PAGE_SIZE + 1 : 0;
    const end = Math.min((page + 1) * PAGE_SIZE, data.total);
    $("page-info").textContent = `${fmt(start)}–${fmt(end)} of ${fmt(data.total)}`;
    $("prev-page").disabled = page === 0;
    $("next-page").disabled = end >= data.total;
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty">Error: ${e.message}</td></tr>`;
  }
}

$("search").addEventListener("input", () => { clearTimeout(searchTimer); searchTimer = setTimeout(() => { page = 0; loadIocs(); }, 300); });
$("filter-type").addEventListener("change", () => { page = 0; loadIocs(); });
$("filter-source").addEventListener("change", () => { page = 0; loadIocs(); });
$("prev-page").addEventListener("click", () => { if (page > 0) { page--; loadIocs(); } });
$("next-page").addEventListener("click", () => { page++; loadIocs(); });

// ---------- Enrichment ----------
async function runEnrich() {
  const val = $("enrich-input").value.trim();
  if (!val) return;
  const box = $("enrich-result");
  box.innerHTML = '<div class="loading">analyzing…</div>';
  try {
    const v = await api("/api/enrich", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ indicator: val }) });
    const cls = v.verdict;
    box.innerHTML = `
      <div class="verdict-card">
        <div class="verdict-head h-${cls}">
          <span class="verdict-badge v-${cls}">${cls}</span>
          <div><div class="mono" style="font-size:15px">${escapeHtml(v.indicator)}</div>
            <div style="color:var(--text-faint);font-size:12px;margin-top:2px">detected type: ${v.ioc_type}</div></div>
          <div class="score-ring"><div class="n" style="color:${cls === "malicious" ? "var(--danger)" : cls === "suspicious" ? "var(--warn)" : "var(--ok)"}">${v.score}</div><div class="l">threat score</div></div>
        </div>
        <div class="verdict-meta">
          <span>First seen: <b>${v.first_seen ? parseUTC(v.first_seen).toLocaleString() : "not in feeds"}</b></span>
          <span>Last seen: <b>${v.last_seen ? parseUTC(v.last_seen).toLocaleString() : "—"}</b></span>
        </div>
        ${v.sources.map((s) => `<div class="source-row"><span class="dot ${s.hit ? "hit" : "miss"}"></span>
          <span class="sname">${escapeHtml(s.name)}</span><span class="sdetail">${escapeHtml(s.detail)}</span></div>`).join("")}
      </div>`;
  } catch (e) {
    box.innerHTML = `<div class="empty">Analysis failed: ${e.message}</div>`;
  }
}
$("enrich-btn").addEventListener("click", runEnrich);
$("enrich-input").addEventListener("keydown", (e) => { if (e.key === "Enter") runEnrich(); });

// ---------- Watchlist ----------
async function loadWatchlist() {
  const el = $("watch-list");
  el.innerHTML = '<div class="loading">loading…</div>';
  try {
    const items = await api("/api/watchlist");
    if (!items.length) { el.innerHTML = '<div class="empty">Nothing on your watchlist yet. Add an indicator above to track it over time.</div>'; return; }
    el.innerHTML = items
      .map((w) => {
        const active = w.sightings > 0;
        return `<div class="watch-item">
          <div>
            <div class="wval mono">${escapeHtml(w.value)}</div>
            <div class="wmeta">${w.ioc_type || "unknown"} · ${active ? `seen ${w.sightings}× · first ${timeAgo(w.first_seen)} · last ${timeAgo(w.last_seen)} · ${w.sources.join(", ")}` : "not yet observed in feeds"}${w.note ? " · " + escapeHtml(w.note) : ""}</div>
          </div>
          <div style="display:flex;align-items:center;gap:10px">
            <span class="watch-badge ${active ? "active" : ""}">${active ? "ON FEEDS" : "clear"}</span>
            <button class="icon-btn" title="Remove" data-id="${w.id}">✕</button>
          </div>
        </div>`;
      })
      .join("");
    el.querySelectorAll(".icon-btn").forEach((b) =>
      b.addEventListener("click", async () => { await api("/api/watchlist/" + b.dataset.id, { method: "DELETE" }); loadWatchlist(); })
    );
  } catch (e) {
    el.innerHTML = `<div class="empty">Error: ${e.message}</div>`;
  }
}

async function addWatch() {
  const val = $("watch-input").value.trim();
  if (!val) return;
  try {
    await api("/api/watchlist", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ value: val }) });
    $("watch-input").value = "";
    toast("Added to watchlist");
    loadWatchlist();
  } catch (e) {
    toast("Failed: " + e.message);
  }
}
$("watch-btn").addEventListener("click", addWatch);
$("watch-input").addEventListener("keydown", (e) => { if (e.key === "Enter") addWatch(); });

// ---------- Boot ----------
loadDashboard();
setInterval(loadDashboard, 60000); // keep the dashboard live
