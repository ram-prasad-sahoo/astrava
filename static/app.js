/* ============================================================
   Astrava Web GUI — Frontend Application (app.js)
   All Socket.IO event handlers, scan control, UI state mgmt
   ============================================================ */

"use strict";

// ── Socket.IO Connection ──────────────────────────────────────
const socket = io({ transports: ["websocket", "polling"] });

// ── State ─────────────────────────────────────────────────────
let isScanning = false;
let scanTimer = null;
let scanSeconds = 0;
let consoleLineCount = 0;
let allVulns = [];       // raw vuln objects for filtering
let sortCol = -1;
let sortAsc = true;
let latestReportPath = "";
let autoScrollEnabled = true;
let currentAIConfig = null;  // Stores current AI configuration
let aiModelsData = null;     // Stores available AI models
let totalParameters = 0;     // Total parameters to test
let testedParameters = 0;    // Parameters tested so far

// ── DOM References ────────────────────────────────────────────
const $ = id => document.getElementById(id);
const btnStart   = $("btnStart");
const btnStop    = $("btnStop");
const btnReport  = $("btnReport");
const btnRefresh = $("btnRefresh");
const progressBar = $("progressBar");
const progressText = $("progressText");
const statusText  = $("statusText");
const statusDot   = document.querySelector("#statusBar .status-dot");
const consoleOutput = $("consoleOutput");
const vulnTableBody = $("vulnTableBody");
const consoleBadge  = $("consoleBadge");
const vulnsBadge    = $("vulnsBadge");
const scanTimerEl   = $("scanTimer");
const timerText     = $("timerText");
const aiStatusDot   = $("aiStatusDot");
const aiStatusText  = $("aiStatusText");

// Stat counters
const counters = {
  total:    $("cntTotal"),
  critical: $("cntCritical"),
  high:     $("cntHigh"),
  medium:   $("cntMedium"),
  low:      $("cntLow"),
};

// ── Utilities ─────────────────────────────────────────────────
function setStatus(text, color = "#7fa4c4") {
  statusText.textContent = text;
  statusText.style.color = color;
  if (statusDot) statusDot.style.background = color;
}

function bumpCounter(key) {
  const el = counters[key];
  if (!el) return;
  el.classList.add("bump");
  setTimeout(() => el.classList.remove("bump"), 250);
}

function animateCounter(el, targetVal) {
  const start = parseInt(el.textContent) || 0;
  const diff = targetVal - start;
  if (diff === 0) return;
  const steps = Math.min(Math.abs(diff), 20);
  const step = diff / steps;
  let current = start;
  let count = 0;
  const interval = setInterval(() => {
    count++;
    current += step;
    el.textContent = Math.round(count === steps ? targetVal : current);
    if (count >= steps) clearInterval(interval);
  }, 40);
  
  // Add/remove glitch animation class for critical counter
  if (el === counters.critical) {
    if (targetVal > 0) {
      el.classList.add('has-vulns');
    } else {
      el.classList.remove('has-vulns');
    }
  }
}

function setCounters(data) {
  ["total","critical","high","medium","low"].forEach(k => {
    const val = data[k] ?? 0;
    animateCounter(counters[k], val);
  });
}

function getActiveAIModel() {
  // Check selected Ollama radio button first
  const selectedOllama = document.querySelector('input[name="ollamaModel"]:checked');
  if (selectedOllama) return selectedOllama.value;
  // Fall back to saved config
  if (currentAIConfig && currentAIConfig.active_identifier) return currentAIConfig.active_identifier;
  return "llama3.2:3b";
}

function startScanTimer() {
  scanSeconds = 0;
  scanTimerEl.style.display = "flex";
  scanTimer = setInterval(() => {
    scanSeconds++;
    const m = String(Math.floor(scanSeconds / 60)).padStart(2, "0");
    const s = String(scanSeconds % 60).padStart(2, "0");
    timerText.textContent = `${m}:${s}`;
  }, 1000);
}

function stopScanTimer() {
  clearInterval(scanTimer);
  scanTimer = null;
}

function setProgress(mode, percentage = 0) {
  progressBar.className = "progress-bar";
  if (mode === "run") {
    progressBar.classList.add("indeterminate");
    if (progressText) progressText.textContent = "0%";
  } else if (mode === "done") {
    progressBar.style.width = "100%";
    if (progressText) progressText.textContent = "100%";
  } else if (mode === "percentage") {
    progressBar.classList.remove("indeterminate");
    progressBar.style.width = `${percentage}%`;
    if (progressText) progressText.textContent = `${percentage}%`;
  } else {
    progressBar.style.width = "0%";
    if (progressText) progressText.textContent = "0%";
  }
}

function updateProgress(tested, total) {
  if (total > 0) {
    const percentage = Math.round((tested / total) * 100);
    setProgress("percentage", percentage);
  }
}

// ── Clock ─────────────────────────────────────────────────────
function updateClock() {
  const now = new Date();
  const h = String(now.getHours()).padStart(2, "0");
  const m = String(now.getMinutes()).padStart(2, "0");
  const s = String(now.getSeconds()).padStart(2, "0");
  $("clock").textContent = `${h}:${m}:${s}`;
}
setInterval(updateClock, 1000);
updateClock();

// ── AI Status Polling ─────────────────────────────────────────
async function checkAiStatus() {
  try {
    const res = await fetch("/api/status");
    const data = await res.json();
    if (data.ollama_running && data.model_ready) {
      aiStatusDot.className = "status-dot online";
      aiStatusText.textContent = "AI Online";
    } else if (data.ollama_running) {
      aiStatusDot.className = "status-dot";
      aiStatusDot.style.background = "#f0a500";
      aiStatusText.textContent = "Model Not Loaded";
    } else {
      aiStatusDot.className = "status-dot offline";
      aiStatusText.textContent = "AI Offline";
    }
  } catch {
    aiStatusDot.className = "status-dot offline";
    aiStatusText.textContent = "Server Error";
  }
}
checkAiStatus();
setInterval(checkAiStatus, 8000);

// ── Mode Selection ─────────────────────────────────────────────
function onModeChange() {
  const mode = document.querySelector('input[name="mode"]:checked')?.value || "basic";
  // Update mode card highlight
  document.querySelectorAll(".mode-card").forEach(c => {
    c.classList.remove("selected-basic","selected-medium","selected-aggressive");
  });
  const sel = { basic: "modeCardBasic", medium: "modeCardMedium", aggressive: "modeCardAggressive" };
  if (sel[mode]) {
    $(sel[mode])?.classList.add(`selected-${mode}`);
  }

  const owaspToggle = $("toggleOwasp");
  const chainToggle = $("toggleChain");
  const optOwasp = $("optOwasp");
  const optChain = $("optChain");

  if (mode === "basic") {
    owaspToggle?.classList.remove("disabled");
    chainToggle?.classList.add("disabled");
    optOwasp.checked = false;
    optChain.checked = false;
  } else if (mode === "medium") {
    owaspToggle?.classList.remove("disabled");
    chainToggle?.classList.remove("disabled");
    optOwasp.checked = true;
    optChain.checked = false;
  } else if (mode === "aggressive") {
    owaspToggle?.classList.remove("disabled");
    chainToggle?.classList.remove("disabled");
    optOwasp.checked = true;
    optChain.checked = true;
  }
}
// Init on load
document.addEventListener("DOMContentLoaded", () => {
  onModeChange();
  // set default radio selected state
  $("modeCardBasic")?.classList.add("selected-basic");
});

// Also init synchronously
setTimeout(onModeChange, 0);

// ── URL Helpers ────────────────────────────────────────────────
function fillUrl(url) {
  $("targetUrl").value = url;
  $("targetUrl").focus();
}

// ── Console Output ─────────────────────────────────────────────
function appendConsole(text, type) {
  const div = document.createElement("div");
  div.className = `line-${type || "default"}`;
  div.textContent = text;
  consoleOutput.appendChild(div);
  consoleLineCount++;
  consoleBadge.textContent = consoleLineCount;

  if (autoScrollEnabled) {
    consoleOutput.scrollTop = consoleOutput.scrollHeight;
  }
}

function scrollConsoleBottom() { consoleOutput.scrollTop = consoleOutput.scrollHeight; }
function scrollConsoleTop()    { consoleOutput.scrollTop = 0; }

$("autoScroll")?.addEventListener("change", e => {
  autoScrollEnabled = e.target.checked;
});

// ── Vulnerability Table ────────────────────────────────────────
function addVulnRow(v) {
  allVulns.push(v);
  vulnsBadge.textContent = allVulns.length;
  counters.total.textContent = allVulns.length;
  bumpCounter("total");

  // Normalize severity - capitalize first letter, trim whitespace
  const rawSev = (v.severity || "medium").trim();
  const normalized = rawSev.charAt(0).toUpperCase() + rawSev.slice(1).toLowerCase();
  v.severity = normalized;  // fix in place

  const sevKey = normalized.toLowerCase();
  if (counters[sevKey]) {
    const cur = parseInt(counters[sevKey].textContent) || 0;
    counters[sevKey].textContent = cur + 1;
    bumpCounter(sevKey);
  }

  renderVulnTable();
}

function renderVulnTable() {
  const search = ($("vulnSearch")?.value || "").toLowerCase();
  const sevFilter = $("vulnSeverityFilter")?.value || "";

  let rows = allVulns.filter(v => {
    const matchSearch = !search ||
      JSON.stringify(v).toLowerCase().includes(search);
    const matchSev = !sevFilter || v.severity === sevFilter;
    return matchSearch && matchSev;
  });

  if (sortCol >= 0) {
    const cols = ["id","type","severity","url","parameter","evidence"];
    const col = cols[sortCol];
    rows.sort((a,b) => {
      const av = String(a[col]||"").toLowerCase();
      const bv = String(b[col]||"").toLowerCase();
      return sortAsc ? av.localeCompare(bv) : bv.localeCompare(av);
    });
  }

  if (rows.length === 0) {
    vulnTableBody.innerHTML = `<tr class="empty-row"><td colspan="6">${
      allVulns.length === 0
        ? "No vulnerabilities detected yet. Start a scan to populate this table."
        : "No matching vulnerabilities."
    }</td></tr>`;
    return;
  }

  const sevClass = { Critical: "sev-critical", High: "sev-high", Medium: "sev-medium", Low: "sev-low" };

  vulnTableBody.innerHTML = rows.map(v => `
    <tr>
      <td>${v.id}</td>
      <td title="${esc(v.type)}">${esc(v.type)}</td>
      <td><span class="sev-badge ${sevClass[v.severity]||"sev-medium"}">${esc(v.severity)}</span></td>
      <td title="${esc(v.url)}">${esc(v.url)}</td>
      <td title="${esc(v.parameter)}">${esc(v.parameter)}</td>
      <td title="${esc(v.evidence)}">${esc(v.evidence)}</td>
    </tr>
  `).join("");
}

function esc(str) {
  return String(str||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

function filterVulns() { renderVulnTable(); }

function sortTable(colIndex) {
  if (sortCol === colIndex) sortAsc = !sortAsc;
  else { sortCol = colIndex; sortAsc = true; }
  renderVulnTable();
}

function exportCsv() {
  if (allVulns.length === 0) return alert("No vulnerabilities to export.");
  const header = ["ID","Type","Severity","URL","Parameter","Evidence"];
  const rows = allVulns.map(v =>
    [v.id, v.type, v.severity, v.url, v.parameter, v.evidence].map(c => `"${c}"`).join(",")
  );
  const csv = [header.join(","), ...rows].join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `astrava_vulns_${Date.now()}.csv`;
  a.click();
}

// ── Tab Switching ──────────────────────────────────────────────
function switchTab(name) {
  document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
  document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
  $(`tab-${name}`)?.classList.add("active");
  $(`panel-${name}`)?.classList.add("active");
}

// ── Scan Start ─────────────────────────────────────────────────
function startScan() {
  const url = ($("targetUrl")?.value || "").trim();
  if (!url) { return setStatus("⚠ Please enter a target URL", "#ff4444"); }
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    return setStatus("⚠ URL must start with http:// or https://", "#ff4444");
  }

  const mode = document.querySelector('input[name="mode"]:checked')?.value || "basic";
  if (mode === "aggressive") {
    showModal(
      "⚠ Aggressive Scan Warning",
      "Aggressive scans use intensive testing techniques.<br>Only scan systems you own or have explicit written permission to test.<br><br><strong>Continue with aggressive scan?</strong>",
      () => { closeModal(); _doStartScan(url, mode); }
    );
    return;
  }
  _doStartScan(url, mode);
}

function _doStartScan(url, mode) {
  isScanning = true;
  allVulns = [];
  consoleLineCount = 0;
  consoleBadge.textContent = "0";
  vulnsBadge.textContent = "0";
  Object.values(counters).forEach(el => el.textContent = "0");
  vulnTableBody.innerHTML = `<tr class="empty-row"><td colspan="6">Scan running…</td></tr>`;
  latestReportPath = "";
  
  // Reset progress tracking
  totalParameters = 0;
  testedParameters = 0;

  setProgress("run");
  btnStart.disabled = true;
  btnStart.classList.add("scanning");
  btnStart.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" style="animation:spin 1s linear infinite"><path d="M12 2a10 10 0 1 0 10 10" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round"/></svg> SCANNING...`;
  btnStop.disabled = false;
  btnReport.disabled = true;
  btnRefresh.disabled = true;
  document.body.classList.add("scanning");
  setStatus("● Initializing scan…", "#f0a500");
  startScanTimer();
  switchTab("console");

  socket.emit("start_scan", {
    url,
    mode,
    owasp:    $("optOwasp")?.checked || false,
    chain:    $("optChain")?.checked || false,
    passive:  $("optPassive")?.checked || false,
    verbose:  $("optVerbose")?.checked !== false,
    ai_model: getActiveAIModel(),
    custom_payloads: $("customPayloads")?.value || "",
  });
}

function stopScan() {
  socket.emit("stop_scan");
  stopScanTimer();
  isScanning = false;
  resetScanUI("stopped");
  setProgress("none");
}

function resetScanUI(reason = "done") {
  isScanning = false;
  document.body.classList.remove("scanning");
  btnStart.disabled = false;
  btnStart.classList.remove("scanning");
  btnStart.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><polygon points="5,3 19,12 5,21"/></svg> START SECURITY SCAN`;
  btnStop.disabled = true;
}

// ── Scan Actions ───────────────────────────────────────────────
function clearResults() {
  consoleOutput.innerHTML = "";
  consoleLineCount = 0;
  consoleBadge.textContent = "0";
  allVulns = [];
  vulnsBadge.textContent = "0";
  vulnTableBody.innerHTML = `<tr class="empty-row"><td colspan="6">No vulnerabilities detected yet. Start a scan to populate this table.</td></tr>`;
  Object.values(counters).forEach(el => el.textContent = "0");
  $("summaryPanel").innerHTML = `<div class="placeholder-msg"><p>Scan summary will appear here after a scan completes.</p></div>`;
  $("aiPanel").innerHTML = `<div class="placeholder-msg"><p>AI analysis and recommendations will appear here after a scan completes.</p></div>`;
  setProgress("none");
  setStatus("● Ready to scan", "#00e676");
  latestReportPath = "";
  btnReport.disabled = true;
  btnRefresh.disabled = true;
  scanTimerEl.style.display = "none";
  timerText.textContent = "00:00";
}

async function openReport() {
  if (latestReportPath) {
    window.open(`/report/${latestReportPath}`, "_blank");
    return;
  }
  try {
    const res = await fetch("/api/reports");
    const data = await res.json();
    if (data.reports?.length) {
      const r = data.reports[0];
      // Use dir/name so the Flask route can resolve it
      latestReportPath = `${r.dir}/${r.name}`;
      window.open(`/report/${latestReportPath}`, "_blank");
    } else {
      setStatus("⚠ No report files found", "#f0a500");
    }
  } catch {
    setStatus("⚠ Failed to fetch report list", "#ff4444");
  }
}

async function refreshCounts() {
  try {
    setStatus("● Refreshing counts from report…", "#f0a500");
    const res = await fetch("/api/refresh-counts");
    const data = await res.json();
    if (data.ok) {
      setCounters(data);
      if (data.report_relpath) latestReportPath = data.report_relpath;
      setStatus(`● Counts refreshed — Total: ${data.total}`, "#00e676");
    } else {
      setStatus(`⚠ Refresh failed: ${data.error}`, "#ff4444");
    }
  } catch (e) {
    setStatus(`⚠ Error: ${e.message}`, "#ff4444");
  }
}

// ── Summary & AI Panel Builders ────────────────────────────────
function buildSummary(mode, url, counts, duration) {
  const now = new Date().toLocaleString();
  return `ASTRAVA AI SECURITY SCANNER — DETAILED SCAN SUMMARY
======================================================

SCAN INFORMATION:
-----------------
  Target URL    : ${url}
  Attack Mode   : ${mode.charAt(0).toUpperCase() + mode.slice(1)} Scan
  AI Model      : ${getActiveAIModel()}
  Scan Duration : ${duration}
  Completed At  : ${now}

CONFIGURATION:
--------------
  OWASP Top 10     : ${$("optOwasp")?.checked ? "Enabled" : "Disabled"}
  Chain Attacks    : ${$("optChain")?.checked ? "Enabled" : "Disabled"}
  Passive Only     : ${$("optPassive")?.checked ? "Enabled" : "Disabled"}
  Verbose Output   : ${$("optVerbose")?.checked ? "Enabled" : "Disabled"}
  Custom Payloads  : ${$("customPayloads")?.value ? "Yes" : "No"}

RESULTS SUMMARY:
----------------
  Total Vulnerabilities : ${counts.total || 0}
  Critical              : ${counts.critical || 0}
  High                  : ${counts.high || 0}
  Medium                : ${counts.medium || 0}
  Low                   : ${counts.low || 0}

RECOMMENDATIONS:
----------------
${
  (counts.total || 0) === 0
    ? "  ✓ No significant vulnerabilities detected.\n  Continue regular security assessments and monitoring."
    : (counts.total || 0) < 5
    ? "  ⚠ Few vulnerabilities detected.\n  Address identified issues and implement preventive controls."
    : "  ✖ Multiple vulnerabilities detected.\n  Immediate security review and remediaton required.\n  Prioritize Critical and High severity findings first."
}

STATUS: SCAN COMPLETED SUCCESSFULLY
`;
}

function buildAiAnalysis(counts) {
  const now = new Date().toLocaleString();
  const total = counts.total || 0;
  const risk = total === 0 ? "LOW" : total < 5 ? "MEDIUM" : total < 15 ? "HIGH" : "CRITICAL";
  const riskColors = { LOW:"#00e676", MEDIUM:"#ffc107", HIGH:"#ff8c00", CRITICAL:"#ff3b3b" };
  return `AI-POWERED SECURITY ANALYSIS REPORT
======================================

RISK ASSESSMENT: ${risk}
-----------------------
  AI has analyzed ${total} vulnerabilities across ${
    Object.keys({critical:counts.critical,high:counts.high,medium:counts.medium,low:counts.low})
      .filter(k => counts[k] > 0).join(", ") || "no"
  } severity levels.

VULNERABILITY BREAKDOWN:
------------------------
  Critical  : ${counts.critical || 0}  (Immediate remediation required)
  High      : ${counts.high || 0}  (Address within 24-72 hours)
  Medium    : ${counts.medium || 0}  (Address within 2 weeks)
  Low       : ${counts.low || 0}  (Address in next maintenance cycle)

ATTACK VECTOR ANALYSIS:
-----------------------
  The AI engine has evaluated possible attack paths and exploitation scenarios.
  Vulnerability chaining and privilege escalation opportunities have been assessed.

AI RECOMMENDATIONS:
-------------------
  1. Prioritize fixing Critical and High severity vulnerabilities immediately.
  2. Implement strict input validation and contextual output encoding.
  3. Deploy a Web Application Firewall (WAF) with custom ruleset.
  4. Apply the principle of least privilege across all application components.
  5. Enable strict Content Security Policy (CSP) headers.
  6. Conduct regular security training for the development team.
  7. Schedule periodic automated and manual security assessments.

THREAT INTELLIGENCE:
--------------------
  Findings cross-referenced with OWASP Top 10 2021 and current CVE databases.
  Exploitation techniques and active threat actors have been considered.

AI MODEL    : ${getActiveAIModel()}
CONFIDENCE  : High
TIMESTAMP   : ${now}
`;
}

// ── AI Settings Management ─────────────────────────────────────
// Note: aiModelsData and currentAIConfig are declared at the top of the file in the State section

async function loadAIModels() {
  try {
    console.log('[DEBUG] Starting loadAIModels...');
    
    // Add timeout to prevent infinite loading
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout
    
    console.log('[DEBUG] Fetching /api/ai/models...');
    const response = await fetch('/api/ai/models', { signal: controller.signal });
    clearTimeout(timeoutId);
    
    console.log('[DEBUG] Response status:', response.status);
    const data = await response.json();
    console.log('[DEBUG] Response data:', data);
    
    if (data.error) {
      console.warn('[DEBUG] AI features not available:', data.error);
      showAIError(data.error);
      return;
    }
    
    console.log('[DEBUG] Setting aiModelsData and rendering...');
    aiModelsData = data;
    console.log('[DEBUG] Ollama models:', data.ollama);

    renderOllamaModels(data.ollama || []);
    updateActiveModelDisplay(data.active_mode, data.active_identifier);
    await loadAIConfiguration();
    
  } catch (error) {
    console.error('[DEBUG] Failed to load AI models:', error);
    if (error.name === 'AbortError') {
      showAIError('Request timed out - AI service may be unavailable');
    } else {
      showAIError('Failed to connect to AI service');
    }
    // Show empty state instead of infinite loading
    renderOllamaModels([]);
    renderAPIProviders([]);
  }
}

async function loadAIConfiguration() {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    const response = await fetch('/api/ai/config', { signal: controller.signal });
    clearTimeout(timeoutId);
    const data = await response.json();
    if (data.error) return;
    currentAIConfig = data;
    updateActiveModelDisplay(data.active_mode, data.active_identifier);
  } catch (error) {
    updateActiveModelDisplay('ollama', 'Not configured');
  }
}

function renderOllamaModels(models) {
  const container = document.getElementById('ollamaModelsList');
  
  if (!container) {
    console.warn('Ollama models container not found');
    return;
  }
  
  if (!models || models.length === 0) {
    container.innerHTML = `
      <div class="loading-placeholder" style="color: #888; padding: 12px;">
        No Ollama models found.<br/>
        <span style="font-size: 0.9em; color: #666;">
          Install models with: <code style="color: #00d4ff;">ollama pull llama3.2:3b</code>
        </span>
      </div>
    `;
    return;
  }
  
  container.innerHTML = models.map(model => `
    <div class="ollama-model-option" onclick="selectOllamaModel('${model}')">
      <input type="radio" name="ollamaModel" value="${model}" class="ollama-model-radio" id="model_${model.replace(/[^a-zA-Z0-9]/g, '_')}" />
      <label for="model_${model.replace(/[^a-zA-Z0-9]/g, '_')}" class="ollama-model-name">${model}</label>
    </div>
  `).join('');
  
  // Select current active model if it's an Ollama model
  if (currentAIConfig && currentAIConfig.active_mode === 'ollama') {
    selectOllamaModel(currentAIConfig.active_identifier, false);
  }
}

function selectOllamaModel(modelName, updateConfig = true) {
  // Update radio button
  const radio = document.querySelector(`input[value="${modelName}"]`);
  if (radio) {
    radio.checked = true;
  }
  
  // Update visual selection
  document.querySelectorAll('.ollama-model-option').forEach(option => {
    option.classList.remove('selected');
  });
  
  const selectedOption = document.querySelector(`input[value="${modelName}"]`)?.closest('.ollama-model-option');
  if (selectedOption) {
    selectedOption.classList.add('selected');
  }
  
  if (updateConfig) {
    updateActiveModelDisplay('ollama', modelName);
  }
}

function updateActiveModelDisplay(mode, identifier) {
  const activeModelText = document.getElementById('activeModelText');
  if (!activeModelText) return;
  activeModelText.textContent = identifier ? `${identifier} (Ollama)` : 'Not configured';
}

async function refreshAIModels() {
  const button = document.getElementById('btnRefreshModels');
  const originalText = button?.innerHTML;
  
  if (button) {
    button.disabled = true;
    button.innerHTML = `
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="animation: spin 1s linear infinite;">
        <polyline points="23 4 23 10 17 10"/>
        <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
      </svg>
      Refreshing...
    `;
  }
  
  try {
    // Emit refresh event to server
    socket.emit('refresh_models');
    
  } catch (error) {
    console.error('Failed to refresh models:', error);
    showNotification('Failed to refresh models', 'error');
  } finally {
    if (button && originalText) {
      setTimeout(() => {
        button.disabled = false;
        button.innerHTML = originalText;
      }, 1000);
    }
  }
}

async function saveAIConfiguration() {
  const button = document.getElementById('btnSaveAIConfig');
  const originalText = button?.innerHTML;
  if (button) { button.disabled = true; button.textContent = 'Saving...'; }
  
  try {
    const selectedOllama = document.querySelector('input[name="ollamaModel"]:checked');
    if (!selectedOllama) {
      showNotification('Please select a model first', 'warning');
      return;
    }
    
    const response = await fetch('/api/ai/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'ollama', identifier: selectedOllama.value })
    });
    const result = await response.json();
    if (!result.success) throw new Error(result.error || 'Failed to save');
    
    showNotification('Model saved: ' + selectedOllama.value, 'success');
    await loadAIConfiguration();
  } catch (error) {
    showNotification(`Failed: ${error.message}`, 'error');
  } finally {
    if (button && originalText) { button.disabled = false; button.innerHTML = originalText; }
  }
}

function showAIError(message) {
  const panel = document.getElementById('aiSettingsPanel');
  if (panel) {
    panel.innerHTML = `
      <div class="ai-settings-header">
        <h3 class="ai-settings-title">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/>
            <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/>
            <line x1="12" y1="17" x2="12.01" y2="17"/>
          </svg>
          AI Model Settings
        </h3>
      </div>
      <div class="placeholder-msg">
        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#ff4444" stroke-width="1.5">
          <circle cx="12" cy="12" r="10"/>
          <line x1="15" y1="9" x2="9" y2="15"/>
          <line x1="9" y1="9" x2="15" y2="15"/>
        </svg>
        <p>AI features are not available: ${message}</p>
        <p style="font-size: 0.8rem; color: var(--text-muted); margin-top: 8px;">
          Please ensure the AI model management system is properly installed and configured.
        </p>
      </div>
    `;
  }
}

function showNotification(message, type = 'info') {
  // Create a simple toast notification
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  
  // Style the toast
  Object.assign(toast.style, {
    position: 'fixed',
    top: '20px',
    right: '20px',
    padding: '12px 20px',
    borderRadius: '8px',
    color: 'white',
    fontWeight: '500',
    fontSize: '0.85rem',
    zIndex: '1000',
    opacity: '0',
    transform: 'translateY(-20px)',
    transition: 'all 0.3s ease',
    maxWidth: '400px',
    wordWrap: 'break-word'
  });
  
  // Set background color based on type
  const colors = {
    success: '#00e676',
    error: '#ff5252',
    warning: '#ffab00',
    info: '#29b6f6'
  };
  toast.style.background = colors[type] || colors.info;
  
  document.body.appendChild(toast);
  
  // Animate in
  setTimeout(() => {
    toast.style.opacity = '1';
    toast.style.transform = 'translateY(0)';
  }, 100);
  
  // Remove after 4 seconds
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(-20px)';
    setTimeout(() => {
      if (toast.parentNode) {
        toast.parentNode.removeChild(toast);
      }
    }, 300);
  }, 4000);
}

function capitalizeFirst(str) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

// ── Simple refresh models wrapper ──────────────────────────────
function refreshModels() {
  refreshAIModels();
}

// ── Socket.IO Event Handlers for AI ─────────────────────────────
socket.on('models_updated', (data) => {
  if (data.success) {
    renderOllamaModels(data.ollama || []);
    showNotification(`Models refreshed - ${data.ollama?.length || 0} Ollama models found`, 'success');
  }
});

socket.on('models_error', (data) => {
  showNotification(`Model refresh failed: ${data.error}`, 'error');
});

// ── Initial AI Setup ────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  // Load AI models and configuration when page loads with a small delay
  setTimeout(() => {
    loadAIModels().catch(err => {
      console.error('Failed to initialize AI models:', err);
      // Show error state instead of infinite loading
      const container = document.getElementById('ollamaModelsList');
      if (container) {
        container.innerHTML = '<div class="loading-placeholder" style="color: #ff8888;">Failed to load AI models. Check if the server is running.</div>';
      }
      const activeDisplay = document.getElementById('activeModelText');
      if (activeDisplay) {
        activeDisplay.textContent = 'Not configured';
      }
    });
  }, 100);
  
  // Add event listeners for API key validation - removed (API providers not supported)
});

// ── Socket.IO Event Handlers ───────────────────────────────────
socket.on("connect", () => {
  setStatus("● Connected to Astrava server", "#00d4ff");
});

socket.on("disconnect", () => {
  setStatus("⚠ Disconnected from server", "#ff4444");
  if (isScanning) { stopScanTimer(); resetScanUI(); setProgress("none"); }
});

socket.on("status_update", d => {
  setStatus(d.text, d.color);
});

socket.on("scan_started", d => {
  appendConsole(`► Starting scan\n`, "success");
  appendConsole(`  Command: ${d.cmd}\n\n`, "info");
});

socket.on("console_line", d => {
  appendConsole(d.text, d.type);
  
  // Track parameter testing progress
  const text = d.text;
  if (text.includes("Testing parameter")) {
    // Extract "Testing parameter X/Y" format
    const match = text.match(/Testing parameter (\d+)\/(\d+)/);
    if (match) {
      const tested = parseInt(match[1]);
      const total = parseInt(match[2]);
      testedParameters = tested;
      totalParameters = total;
      updateProgress(tested, total);
    }
  }
});

socket.on("vuln_found", v => {
  addVulnRow(v);
});

socket.on("scan_complete", d => {
  stopScanTimer();
  resetScanUI();
  setProgress("done");
  btnReport.disabled = false;
  btnRefresh.disabled = false;

  const counts = d.counts || {};
  setCounters(counts);
  // d.report is now 'dir/filename' relpath
  if (d.report) latestReportPath = d.report;
  else if (counts.report_relpath) latestReportPath = counts.report_relpath;

  const url  = ($("targetUrl")?.value || "").trim();
  const mode = document.querySelector('input[name="mode"]:checked')?.value || "basic";

  // Update summary and AI tabs
  $("summaryPanel").textContent = buildSummary(mode, url, counts, d.duration || "N/A");
  $("aiPanel").textContent = buildAiAnalysis(counts);

  appendConsole(`\n✓ Scan completed in ${d.duration} — ${d.vuln_count} vulnerabilities found\n`, "success");

  // Brief toast in status
  setStatus(`● Scan completed — ${d.vuln_count} vulnerabilities — ${d.duration}`, "#00e676");
});

socket.on("scan_error", d => {
  stopScanTimer();
  resetScanUI();
  setProgress("none");
  setStatus(`● Error: ${d.message}`, "#ff4444");
  appendConsole(`\nERROR: ${d.message}\n`, "error");
});

socket.on("scan_stopped", () => {
  resetScanUI("stopped");
  setProgress("none");
  setStatus("● Scan stopped by user", "#f0a500");
});

// ── Modal ──────────────────────────────────────────────────────
function showModal(title, body, onConfirm) {
  $("modalTitle").textContent = title;
  $("modalBody").innerHTML = body;
  $("modalConfirm").onclick = onConfirm;
  $("modalOverlay").classList.add("show");
  $("modal").classList.add("show");
}
function closeModal() {
  $("modalOverlay").classList.remove("show");
  $("modal").classList.remove("show");
}

// ── Spin keyframe for scanning button ─────────────────────────
const style = document.createElement("style");
style.textContent = "@keyframes spin { to { transform: rotate(360deg); } }";
document.head.appendChild(style);

// ── Initial greeting ───────────────────────────────────────────
appendConsole("Astrava AI Security Scanner — Web Interface\n", "success");
appendConsole("Ready. Enter a target URL and click START SECURITY SCAN.\n\n", "info");
