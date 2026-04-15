#!/usr/bin/env python3
"""
Astrava AI Security Scanner - Web GUI (Flask + Socket.IO)
Replaces the Tkinter desktop GUI with a modern web-based interface.
Run: python web_gui.py
"""

import os
import sys
import re
import json
import time
import queue
import threading
import subprocess
import webbrowser
import requests as http_requests
from pathlib import Path
from datetime import datetime

from flask import Flask, render_template, jsonify, request, send_from_directory
from flask_socketio import SocketIO, emit

# ── Project root setup ────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))

# Import AI model management modules
try:
    from utils.model_manager import ModelManager
    from utils import config_store
    
    model_manager = None
    AI_FEATURES_AVAILABLE = True
    _model_manager_initialized = False
    
    def init_model_manager():
        """Initialize model manager - ensures Ollama is running first"""
        global model_manager, _model_manager_initialized
        
        if _model_manager_initialized:
            return True
        
        try:
            from utils.ollama_manager import OllamaManager
            
            # Ensure Ollama is running
            ollama = OllamaManager()
            if not ollama.is_ollama_running():
                print("[*] Starting Ollama service...")
                success, msg = ollama.initialize(auto_download=False)
                if not success:
                    print(f"[!] {msg}")
                    return False
            
            # Initialize model manager
            model_manager = ModelManager()
            success = model_manager.initialize()
            
            if success:
                models = model_manager.get_available_models()
                model_count = len(models.get('ollama', []))
                print(f"[✓] Model Manager ready: {model_count} models available")
                _model_manager_initialized = True
                return True
            else:
                print("[!] Model Manager initialization incomplete")
                return False
                
        except Exception as e:
            print(f"[ERROR] Failed to initialize Model Manager: {e}")
            import traceback
            traceback.print_exc()
            model_manager = None
            return False
    
    # Try to initialize immediately
    init_model_manager()
    
except ImportError as e:
    print(f"Warning: AI model management not available: {e}")
    model_manager = None
    AI_FEATURES_AVAILABLE = False

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
)
app.config["SECRET_KEY"] = "astrava_secret_2024"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ── Global scan state ─────────────────────────────────────────────────────────
scan_process: subprocess.Popen | None = None
scanning: bool = False
scan_start_time: datetime | None = None
vulnerability_count: int = 0
report_path: Path | None = None


# ═════════════════════════════════════════════════════════════════════════════
# HTTP Routes
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
def api_status():
    """Check Ollama and scanner status."""
    try:
        from utils import config_store
        config = config_store.load_config()
        active_model = config.get("active_model", "xploiter/pentester")
    except:
        active_model = "xploiter/pentester"

    ollama_running = _is_ollama_running()
    model_ready = _is_model_available(active_model) if ollama_running else False

    return jsonify({
        "ollama_running": ollama_running,
        "model_ready": model_ready,
        "active_model": active_model,
        "active_mode": "ollama",
        "scanning": scanning,
    })


@app.route("/api/reports")
def api_reports():
    """List HTML report files, newest first."""
    dirs = ["reports", "results", "fixed_results", "fast_scan_results"]
    reports = []
    for d in dirs:
        p = BASE_DIR / d
        if p.exists():
            for f in sorted(p.glob("*.html"), key=os.path.getctime, reverse=True):
                reports.append({"name": f.name, "path": str(f), "dir": d})
    return jsonify({"reports": reports})


@app.route("/api/refresh-counts")
def api_refresh_counts():
    """Re-parse the latest report file and return vuln counts."""
    try:
        counts = _parse_report_counts()
        return jsonify({"ok": True, **counts})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/report/<path:relpath>")
def serve_report(relpath):
    """Serve a report file from any known report directory.
    relpath may be 'reports/foo.html' or just 'foo.html'.
    """
    # Try treating relpath as-is (dir/file)
    full = BASE_DIR / relpath
    if full.exists():
        return send_from_directory(str(full.parent), full.name)
    # Try all known report dirs
    for d in ["reports", "results", "fixed_results", "fast_scan_results"]:
        candidate = BASE_DIR / d / relpath
        if candidate.exists():
            return send_from_directory(str(BASE_DIR / d), relpath)
    return "Report not found", 404


@app.route("/api/ai/models")
def get_ai_models():
    """
    Return available AI models and current configuration.
    
    Implements Requirements 13.1, 13.3 - GET route to return available models
    """
    global model_manager, _model_manager_initialized
    
    if not AI_FEATURES_AVAILABLE:
        return jsonify({
            "error": "AI features not available",
            "ollama": [],
            "active_mode": "ollama",
            "active_identifier": "xploiter/pentester",
            "ai_available": False
        }), 503

    # Try to initialize if not already done
    if not model_manager or not _model_manager_initialized:
        print("[*] Attempting to initialize model manager...")
        if not init_model_manager():
            return jsonify({
                "error": "AI model manager failed to initialize. Check if Ollama is installed.",
                "ollama": [],
                "active_mode": "ollama",
                "active_identifier": "xploiter/pentester",
                "ai_available": False
            }), 503
    
    try:
        # Get available models from model manager
        models = model_manager.get_available_models()

        # Get current active model
        _, active_identifier = model_manager.get_active_model()

        return jsonify({
            "ollama": models.get("ollama", []),
            "active_mode": "ollama",
            "active_identifier": active_identifier,
            "ai_available": model_manager.is_ai_available()
        })
        
    except Exception as e:
        print(f"[ERROR] Failed to get AI models: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "error": f"Failed to get AI models: {str(e)}",
            "ollama": [],
            "active_mode": "ollama",
            "active_identifier": "xploiter/pentester",
            "ai_available": False
        }), 500


@app.route("/api/ai/config", methods=["GET", "POST"])
def ai_config():
    """
    Get or update AI configuration.
    
    GET: Returns current AI configuration
    POST: Updates AI configuration with new settings
    
    Implements Requirements 13.3, 13.5 - GET/POST routes for configuration
    """
    if not AI_FEATURES_AVAILABLE or not model_manager:
        return jsonify({"error": "AI features not available"}), 503
    
    if request.method == "POST":
        try:
            data = request.get_json()
            if not data:
                return jsonify({"error": "No JSON data provided"}), 400

            # Update active model if provided
            if "mode" in data and "identifier" in data:
                identifier = data["identifier"]
                if not model_manager.set_active_model("ollama", identifier):
                    return jsonify({"error": f"Failed to set active model: {identifier}"}), 400

            return jsonify({"success": True})

        except Exception as e:
            return jsonify({"error": f"Failed to update configuration: {str(e)}"}), 500

    else:  # GET request
        try:
            _, active_identifier = model_manager.get_active_model()

            return jsonify({
                "active_model": active_identifier,
                "active_identifier": active_identifier,
                "ai_available": model_manager.is_ai_available()
            })

        except Exception as e:
            return jsonify({"error": f"Failed to get configuration: {str(e)}"}), 500


# ═════════════════════════════════════════════════════════════════════════════
# Socket.IO Events
# ═════════════════════════════════════════════════════════════════════════════

@socketio.on("connect")
def on_connect():
    emit("status_update", {"text": "● Connected to Astrava Server", "color": "#00d4ff"})


@socketio.on("start_scan")
def on_start_scan(data):
    """Launch the scanner subprocess and stream output."""
    global scan_process, scanning, scan_start_time, vulnerability_count, report_path

    if scanning:
        emit("status_update", {"text": "⚠ Scan already running", "color": "#f0a500"})
        return

    url = data.get("url", "").strip()
    mode = data.get("mode", "basic")
    owasp = data.get("owasp", False)
    chain = data.get("chain", False)
    passive = data.get("passive", False)
    verbose = data.get("verbose", True)
    ai_model = data.get("ai_model", "")  # Get from frontend
    custom_payloads = data.get("custom_payloads", "").strip()
    
    # If no model specified, get from config
    if not ai_model:
        try:
            from utils import config_store
            config = config_store.load_config()
            ai_model = config.get("active_model", "xploiter/pentester")
        except:
            ai_model = "xploiter/pentester"

    if not url:
        emit("status_update", {"text": "⚠ No target URL provided", "color": "#ff4444"})
        return

    # Build command
    if mode == "basic":
        cmd = [sys.executable, "fast_scan.py", "-u", url, "--model", ai_model]
    else:
        cmd = [sys.executable, "main.py", "-u", url]
        if owasp and mode in ("medium", "aggressive"):
            cmd.append("--owasp-all")
        if mode == "medium":
            cmd += ["--threads", "10", "--timeout", "30"]
        elif mode == "aggressive":
            cmd += ["--threads", "20", "--timeout", "60"]
            if chain:
                cmd.append("--chain-attacks")
        if passive:
            cmd.append("--passive-only")
        cmd += ["--model", ai_model]
        if verbose:
            cmd.append("--verbose")

    if custom_payloads:
        cmd += ["--custom-payloads", custom_payloads]

    scanning = True
    scan_start_time = datetime.now()
    vulnerability_count = 0
    report_path = None

    emit("scan_started", {"cmd": " ".join(cmd)})
    emit("status_update", {"text": "● Initializing scan...", "color": "#f0a500"})

    # Run in background thread so Socket.IO stays responsive
    t = threading.Thread(target=_run_scan_thread, args=(cmd,), daemon=True)
    t.start()


@socketio.on("stop_scan")
def on_stop_scan():
    global scan_process, scanning
    if scan_process:
        try:
            scan_process.terminate()
            scan_process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            scan_process.kill()
        except Exception:
            pass
    scanning = False
    emit("status_update", {"text": "● Scan stopped by user", "color": "#f0a500"})
    socketio.emit("scan_stopped", {})


@socketio.on("refresh_models")
def handle_refresh_models():
    """
    Refresh Ollama model list and emit updated models to client.
    
    Implements Requirements 13.6 - Socket.IO event handler for model refresh
    """
    if not AI_FEATURES_AVAILABLE or not model_manager:
        emit("models_error", {"error": "AI features not available"})
        return
    
    try:
        # Refresh Ollama models (bypasses cache)
        ollama_models = model_manager.refresh_ollama_models()
        
        # Get all available models
        all_models = model_manager.get_available_models()
        
        # Emit updated models to the client
        emit("models_updated", {
            "ollama": ollama_models,
            "success": True
        })
        
        emit("status_update", {
            "text": f"● Models refreshed - {len(ollama_models)} Ollama models found",
            "color": "#00ff88"
        })
        
    except Exception as e:
        emit("models_error", {"error": f"Failed to refresh models: {str(e)}"})
        emit("status_update", {
            "text": f"● Model refresh failed: {str(e)}",
            "color": "#ff4444"
        })


# ═════════════════════════════════════════════════════════════════════════════
# Scan Runner Thread
# ═════════════════════════════════════════════════════════════════════════════

def _get_severity_from_type(vuln_type: str) -> str:
    """Map vulnerability type to severity level."""
    t = vuln_type.lower()
    if any(k in t for k in ["command injection", "rce", "remote code"]):
        return "Critical"
    elif any(k in t for k in ["sql injection", "lfi", "local file", "ssrf", "server-side request"]):
        return "High"
    elif any(k in t for k in ["xss", "cross-site scripting", "open redirect", "csrf"]):
        return "Medium"
    elif any(k in t for k in ["security header", "information disclosure", "missing header", "clickjacking"]):
        return "Low"
    return "Medium"  # default


def _run_scan_thread(cmd: list):
    global scan_process, scanning, vulnerability_count, report_path

    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"

    # Vulnerability parsing state
    collecting_vuln = False
    current_vuln = {}

    # Regex to detect any VULNERABILITY FOUND line
    VULN_TRIGGER = re.compile(r"VULNERABILITY FOUND", re.IGNORECASE)

    def flush_vuln():
        """Emit current_vuln if it has a valid type."""
        if current_vuln.get("type") and current_vuln["type"] != "Unknown":
            _emit_vuln(current_vuln.copy())

    try:
        scan_process = subprocess.Popen(
            cmd,
            cwd=str(BASE_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )

        for line in scan_process.stdout:
            if not scanning:
                break

            # Clean ANSI codes
            clean = re.sub(r"\x1b\[[0-9;]*m", "", line)
            clean = re.sub(r"\[\d+m", "", clean)
            clean = clean.rstrip("\n")

            # Classify line type for console coloring
            ltype = "info"
            if re.search(r"\bERROR\b|Failed", clean, re.I):
                ltype = "error"
            elif re.search(r"\bWARNING\b|\bWARN\b", clean, re.I):
                ltype = "warning"
            elif VULN_TRIGGER.search(clean):
                ltype = "vulnerability"
            elif re.search(r"\bSUCCESS\b|completed", clean, re.I):
                ltype = "success"

            socketio.emit("console_line", {"text": clean + "\n", "type": ltype})

            # ── Vulnerability state machine ──────────────────────────
            if VULN_TRIGGER.search(clean):
                # New vulnerability found — flush previous if any
                flush_vuln()
                current_vuln = {
                    "type": "Unknown", "severity": "Medium",
                    "url": "", "parameter": "", "evidence": "",
                    "lines": 0
                }
                collecting_vuln = True

                # Pre-classify severity from trigger line keywords
                if "CRITICAL" in clean:
                    current_vuln["severity"] = "Critical"
                elif any(k in clean for k in ["SQL", "LFI", "SSRF"]):
                    current_vuln["severity"] = "High"
                elif "XSS" in clean or "Cross-Site" in clean:
                    current_vuln["severity"] = "Medium"
                elif "Security Header" in clean or "Information Disclosure" in clean:
                    current_vuln["severity"] = "Low"

            elif collecting_vuln:
                current_vuln["lines"] += 1

                stripped = clean.strip()

                if stripped.startswith("Type:"):
                    vuln_type = stripped[5:].strip()
                    current_vuln["type"] = vuln_type
                    # Always derive severity from type (most accurate)
                    current_vuln["severity"] = _get_severity_from_type(vuln_type)

                elif stripped.startswith("URL:"):
                    current_vuln["url"] = stripped[4:].strip()

                elif stripped.startswith("Parameter:"):
                    current_vuln["parameter"] = stripped[10:].strip()

                elif stripped.startswith("Evidence:") or stripped.startswith("Payload:"):
                    current_vuln["evidence"] = stripped.split(":", 1)[-1].strip()[:120]

                elif stripped.startswith("Severity:"):
                    sev = stripped[9:].strip()
                    if sev in ("Critical", "High", "Medium", "Low"):
                        current_vuln["severity"] = sev

                # Flush after collecting enough lines or on separator
                if current_vuln["lines"] >= 6 or "===" in clean:
                    flush_vuln()
                    collecting_vuln = False
                    current_vuln = {}

        # Flush any remaining vulnerability
        flush_vuln()

        scan_process.wait()

        # Final report parsing
        counts = _parse_report_counts()
        vulnerability_count = counts.get("total", vulnerability_count)

        duration = ""
        if scan_start_time:
            delta = datetime.now() - scan_start_time
            duration = str(delta).split(".")[0]

        rp = _find_latest_report()  # 'dir/filename' string
        if rp:
            report_path = rp

        scanning = False
        socketio.emit("scan_complete", {
            "vuln_count": vulnerability_count,
            "duration": duration,
            "report": report_path or "",  # already 'dir/file' string
            "counts": counts,
        })
        socketio.emit("status_update", {
            "text": f"● Scan completed — {vulnerability_count} vulnerabilities found — {duration}",
            "color": "#00ff88"
        })

    except Exception as e:
        scanning = False
        socketio.emit("scan_error", {"message": str(e)})
        socketio.emit("status_update", {"text": f"● Scan error: {e}", "color": "#ff4444"})


def _emit_vuln(vuln: dict):
    global vulnerability_count
    vulnerability_count += 1
    socketio.emit("vuln_found", {
        "id": vulnerability_count,
        "type": vuln.get("type", "Unknown"),
        "severity": vuln.get("severity", "Medium"),
        "url": (vuln.get("url") or "N/A")[:80],
        "parameter": (vuln.get("parameter") or "N/A")[:40],
        "evidence": (vuln.get("evidence") or "N/A")[:100],
    })


# ═════════════════════════════════════════════════════════════════════════════
# Helpers
# ═════════════════════════════════════════════════════════════════════════════

def _is_ollama_running() -> bool:
    try:
        r = http_requests.get("http://localhost:11434/api/tags", timeout=2)
        return r.status_code == 200
    except Exception:
        return False


def _is_model_available(model_name: str = None) -> bool:
    """Check if a specific Ollama model is available"""
    try:
        # If no model specified, get from config
        if not model_name:
            from utils import config_store
            config = config_store.load_config()
            model_name = config.get("active_model", "xploiter/pentester")
        
        r = http_requests.get("http://localhost:11434/api/tags", timeout=2)
        if r.status_code == 200:
            models = [m["name"] for m in r.json().get("models", [])]
            return any(model_name in m for m in models)
    except Exception:
        pass
    return False


def _find_latest_report() -> str | None:
    """Return 'dir/filename' of most recent report across all known report dirs."""
    best_file = None
    best_mtime = 0
    for d in ["reports", "results", "fixed_results", "fast_scan_results"]:
        p = BASE_DIR / d
        if p.exists():
            for f in p.glob("*.html"):
                mtime = os.path.getctime(f)
                if mtime > best_mtime:
                    best_mtime = mtime
                    best_file = f"{d}/{f.name}"
    return best_file


def _parse_report_counts() -> dict:
    rp = _find_latest_report()  # returns 'dir/filename' string or None
    counts = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "report_relpath": ""}
    if not rp:
        return counts
    try:
        full_path = BASE_DIR / rp
        content = full_path.read_text(encoding="utf-8", errors="ignore")
        counts["report_relpath"] = rp  # e.g. 'reports/Astrava_report_xyz.html'

        # Updated patterns to match the actual HTML report format
        patterns = {
            "total": [
                r'<div class="stat-number">(\d+)</div>\s*<div class="stat-label">Total Vulnerabilities</div>',
                r"Total Vulnerabilities[:\s]+(\d+)",
                r"Total[:\s]+(\d+)\s+vulnerabilities",
                r"(\d+)\s+Total\s+Vulnerabilities",
            ],
            "critical": [
                r'<div class="stat-number">(\d+)</div>\s*<div class="stat-label">Critical</div>',
                r"Critical[:\s]+(\d+)", 
                r"(\d+)\s+Critical",
                r'Critical Severity \((\d+)\)',
            ],
            "high": [
                r'<div class="stat-number">(\d+)</div>\s*<div class="stat-label">High</div>',
                r"High[:\s]+(\d+)",
                r"(\d+)\s+High",
                r'High Severity \((\d+)\)',
            ],
            "medium": [
                r'<div class="stat-number">(\d+)</div>\s*<div class="stat-label">Medium</div>',
                r"Medium[:\s]+(\d+)",
                r"(\d+)\s+Medium",
                r'Medium Severity \((\d+)\)',
            ],
            "low": [
                r'<div class="stat-number">(\d+)</div>\s*<div class="stat-label">Low</div>',
                r"Low[:\s]+(\d+)",
                r"(\d+)\s+Low",
                r'Low Severity \((\d+)\)',
            ],
        }
        for key, pats in patterns.items():
            for pat in pats:
                m = re.search(pat, content, re.I | re.DOTALL)
                if m:
                    counts[key] = int(m.group(1))
                    break
    except Exception as e:
        print(f"Error parsing report counts: {e}")
        pass
    return counts


# ═════════════════════════════════════════════════════════════════════════════
# Entry Point
# ═════════════════════════════════════════════════════════════════════════════

def open_browser():
    time.sleep(1.2)
    webbrowser.open("http://localhost:5000")


def run():
    """Start the Astrava Web GUI server."""
    print("=" * 60)
    print("  Web GUI Server Starting")
    print("  http://localhost:5000")
    print("=" * 60)

    threading.Thread(target=open_browser, daemon=True).start()
    socketio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)


if __name__ == "__main__":
    run()
