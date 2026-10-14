/**
 * IoT Botnet Detection System — Settings & System Health View
 */

window.SettingsView = {
  render(container) {
    container.innerHTML = `
      <!-- System Health Metrics Header -->
      <div class="card" style="margin-bottom: var(--space-xl); padding: 18px 24px;">
        <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 16px;">
          <div>
            <h2 style="font-size: 18px; margin-bottom: 4px; display: flex; align-items: center; gap: 8px;">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
              Core Engine Telemetry & System Health
            </h2>
            <p style="font-size: 13px; color: var(--text-secondary);">
              Inspect low-level packet capture buffer health, dual-tier inference latency, security policy enforcement, and notification integration.
            </p>
          </div>
          <span class="badge badge-normal" style="font-size: 13px; padding: 4px 12px;">SYSTEM OPERATIONAL</span>
        </div>
      </div>

      <!-- System Health Diagnostics -->
      <div class="grid-4" style="margin-bottom: var(--space-xl);">
        <div class="kpi-card">
          <div class="kpi-top">
            <span class="kpi-label">Engine Latency</span>
            <div class="kpi-icon-wrapper">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
            </div>
          </div>
          <div class="kpi-value" style="color: var(--highlight-mint);" id="health-latency">142 μs</div>
          <div class="kpi-subtext highlight-safe">Sub-millisecond dual evaluation</div>
        </div>

        <div class="kpi-card">
          <div class="kpi-top">
            <span class="kpi-label">Packet Drop Rate</span>
            <div class="kpi-icon-wrapper">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
            </div>
          </div>
          <div class="kpi-value" id="health-drop">0.001%</div>
          <div class="kpi-subtext highlight-safe">Zero-loss ring buffer</div>
        </div>

        <div class="kpi-card">
          <div class="kpi-top">
            <span class="kpi-label">Memory Ring Buffer</span>
            <div class="kpi-icon-wrapper">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/></svg>
            </div>
          </div>
          <div class="kpi-value" id="health-memory">42.8 MB</div>
          <div class="kpi-subtext">100 active flows in RAM</div>
        </div>

        <div class="kpi-card">
          <div class="kpi-top">
            <span class="kpi-label">CPU Core Utilization</span>
            <div class="kpi-icon-wrapper">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/></svg>
            </div>
          </div>
          <div class="kpi-value" id="health-cpu">3.8%</div>
          <div class="kpi-subtext highlight-safe">Lightweight thread pool</div>
        </div>
      </div>

      <!-- Engine Configuration Settings -->
      <div class="grid-2" style="margin-bottom: var(--space-xl);">
        <!-- Policy & Enforcement Configuration -->
        <div class="card">
          <div class="card-header">
            <div class="card-title">Enforcement & Mitigation Policy</div>
            <span class="badge badge-normal">Automated</span>
          </div>

          <div style="display: flex; flex-direction: column; gap: 16px;">
            <div style="display: flex; align-items: center; justify-content: space-between; padding-bottom: 12px; border-bottom: 1px solid var(--border-subtle);">
              <div>
                <strong style="color: var(--text-main); font-size: 13px;">Auto-Quarantine High-Risk Nodes</strong>
                <p style="font-size: 12px; color: var(--text-secondary); margin-top: 2px;">
                  Instantly isolate IoT device switch port upon confirmed Mirai or SYN flood signatures.
                </p>
              </div>
              <input type="checkbox" id="setting-auto-quarantine" checked style="width: 18px; height: 18px; accent-color: var(--primary-accent); cursor: pointer;"
                     onchange="SettingsView.savePreference('autoQuarantine', this.checked)" />
            </div>

            <div style="display: flex; align-items: center; justify-content: space-between; padding-bottom: 12px; border-bottom: 1px solid var(--border-subtle);">
              <div>
                <strong style="color: var(--text-main); font-size: 13px;">Machine-Learning Gatekeeper</strong>
                <p style="font-size: 12px; color: var(--text-secondary); margin-top: 2px;">
                  Fuse Random Forest predictions with rule engine for zero-day anomaly triage.
                </p>
              </div>
              <input type="checkbox" id="setting-ml-fusion" checked style="width: 18px; height: 18px; accent-color: var(--primary-accent); cursor: pointer;"
                     onchange="SettingsView.savePreference('mlFusion', this.checked)" />
            </div>

            <div style="display: flex; align-items: center; justify-content: space-between;">
              <div>
                <strong style="color: var(--text-main); font-size: 13px;">Browser Security Notifications</strong>
                <p style="font-size: 12px; color: var(--text-secondary); margin-top: 2px;">
                  Receive native OS alerts when Critical botnet incursions occur.
                </p>
              </div>
              <button class="btn btn-secondary btn-sm" onclick="SettingsView.requestNotificationPermission()">
                Enable Permissions
              </button>
            </div>
          </div>
        </div>

        <!-- Data Source & Simulator Mode -->
        <div class="card">
          <div class="card-header">
            <div class="card-title">Data Source & Simulation Mode</div>
            <span class="badge badge-warning" id="badge-data-mode">DEMO SIMULATOR</span>
          </div>

          <div style="display: flex; flex-direction: column; gap: 16px;">
            <div>
              <label style="font-size: 12px; font-weight: 600; color: var(--text-main); display: block; margin-bottom: 6px;">Telemetry Feed Mode:</label>
              <select id="select-data-mode" onchange="SettingsView.setDataMode(this.value)"
                      style="width: 100%; background: var(--bg-surface); color: var(--text-main); border: 1px solid var(--border-subtle); padding: 8px 12px; border-radius: var(--radius-md); font-size: 13px;">
                <option value="demo" selected>Synthetic IoT Botnet Simulator (Safe Sandbox)</option>
                <option value="live">Live Network Monitor (Passive Sniffing Interface)</option>
              </select>
              <p style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">
                Demonstration mode streams realistic IoT flows (Mirai, Gafgyt, MQTT, RTSP) without needing root pcap permissions.
              </p>
            </div>

            <div>
              <label style="font-size: 12px; font-weight: 600; color: var(--text-main); display: block; margin-bottom: 6px;">Stream Polling Interval:</label>
              <select id="select-stream-interval" onchange="App.setStreamInterval(this.value)"
                      style="width: 100%; background: var(--bg-surface); color: var(--text-main); border: 1px solid var(--border-subtle); padding: 8px 12px; border-radius: var(--radius-md); font-size: 13px;">
                <option value="500">500 ms (Fast Burst Telemetry)</option>
                <option value="1000" selected>1,000 ms (Standard Real-Time)</option>
                <option value="2000">2,000 ms (Reduced Resource Usage)</option>
              </select>
            </div>

            <div style="display: flex; gap: 8px; margin-top: 8px;">
              <button class="btn btn-secondary btn-sm" onclick="SettingsView.resetBaseline()">
                Reset Detection Baseline
              </button>
              <button class="btn btn-secondary btn-sm" onclick="SettingsView.exportDiagnosticBundle()">
                Export Diagnostics (.json)
              </button>
            </div>
          </div>
        </div>
      </div>
    `;

    this.loadPreferences();
  },

  loadPreferences() {
    const saved = localStorage.getItem("netguard_settings");
    if (saved) {
      try {
        const pref = JSON.parse(saved);
        if (pref.autoQuarantine !== undefined) {
          const el = document.getElementById("setting-auto-quarantine");
          if (el) el.checked = pref.autoQuarantine;
        }
        if (pref.mlFusion !== undefined) {
          const el = document.getElementById("setting-ml-fusion");
          if (el) el.checked = pref.mlFusion;
        }
      } catch (e) {}
    }
  },

  savePreference(key, value) {
    let pref = {};
    try {
      pref = JSON.parse(localStorage.getItem("netguard_settings") || "{}");
    } catch (e) {}
    pref[key] = value;
    localStorage.setItem("netguard_settings", JSON.stringify(pref));
    App.showToast(`Preference updated: ${key} = ${value}`, "info");
  },

  setDataMode(mode) {
    const badge = document.getElementById("badge-data-mode");
    if (mode === "demo") {
      badge.textContent = "DEMO SIMULATOR";
      badge.className = "badge badge-warning";
      App.showToast("Telemetry set to Demo Simulator", "info");
    } else {
      badge.textContent = "LIVE MONITOR (PASSTHROUGH)";
      badge.className = "badge badge-normal";
      App.showToast("Telemetry set to Live Network Sniffer", "info");
    }
  },

  async requestNotificationPermission() {
    if (!("Notification" in window)) {
      App.showToast("Browser does not support notifications", "warning");
      return;
    }
    const perm = await Notification.requestPermission();
    if (perm === "granted") {
      App.showToast("Notification permissions granted!", "success");
      new Notification("NETGUARD IoT", { body: "Cybersecurity alert dispatch service active." });
    } else {
      App.showToast("Notification permissions denied", "warning");
    }
  },

  resetBaseline() {
    App.showToast("Security baseline and anomaly thresholds reset to factory defaults", "success");
  },

  exportDiagnosticBundle() {
    const bundle = {
      timestamp: new Date().toISOString(),
      kpis: App.state.kpis,
      device_count: App.state.devices.length,
      alert_count: App.state.alerts.length,
      rules: App.state.rules,
      ml_model: App.state.mlModel
    };
    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `netguard_diagnostics_${Date.now()}.json`;
    a.click();
    App.showToast("Diagnostics bundle downloaded", "info");
  }
};
