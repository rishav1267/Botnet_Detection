/**
 * IoT Botnet Detection System — Threat Detection & Rule-Based Heuristics View
 */

window.ThreatsView = {
  render(container) {
    const rules = App.state.rules || (window.IOT_FALLBACK_DATA ? window.IOT_FALLBACK_DATA.rules : []);

    container.innerHTML = `
      <!-- View Header Intro -->
      <div class="card" style="margin-bottom: var(--space-xl); padding: 18px 24px; background: linear-gradient(135deg, rgba(16, 53, 38, 0.9), rgba(11, 38, 27, 0.9));">
        <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 16px;">
          <div>
            <h2 style="font-size: 18px; margin-bottom: 4px; display: flex; align-items: center; gap: 8px;">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
              Dual-Tier Heuristic Signature & Threshold Engine
            </h2>
            <p style="font-size: 13px; color: var(--text-secondary);">
              Deterministic rules analyze packet rates, port targets, TCP flag ratios, and connection entropy to identify known IoT botnet signatures before ML inference.
            </p>
          </div>
          <div style="display: flex; gap: 12px; align-items: center;">
            <div style="text-align: right;">
              <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase;">Active Rules</div>
              <div style="font-size: 18px; font-weight: 700; color: var(--highlight-mint); font-family: var(--font-mono);">${rules.filter(r => r.enabled).length} / ${rules.length}</div>
            </div>
          </div>
        </div>
      </div>

      <!-- Rule Grid & Interactive Threshold Tuning -->
      <div class="grid-2" style="margin-bottom: var(--space-xl);">
        <!-- Active Rules Cards -->
        <div style="display: flex; flex-direction: column; gap: var(--space-md);">
          <div style="font-size: 14px; font-weight: 600; color: var(--text-main); display: flex; justify-content: space-between; align-items: center;">
            <span>Configured Detection Signatures</span>
            <span style="font-size: 12px; color: var(--text-muted);">Real-time rule hits</span>
          </div>

          ${rules.map(r => `
            <div class="card" style="padding: 16px 20px; border-color: ${r.enabled ? 'var(--border-subtle)' : 'rgba(255,255,255,0.05)'}; opacity: ${r.enabled ? 1 : 0.6};">
              <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
                <div>
                  <div style="display: flex; align-items: center; gap: 8px;">
                    <span class="mono" style="font-size: 11px; background: rgba(34,197,94,0.1); color: var(--highlight-mint); padding: 2px 6px; border-radius: 4px;">${r.id}</span>
                    <strong style="font-size: 14px; color: var(--text-main);">${r.name}</strong>
                  </div>
                  <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">Category: ${r.category}</div>
                </div>
                <div style="display: flex; align-items: center; gap: 8px;">
                  <span class="badge ${r.severity === 'High-Risk' ? 'badge-high-risk' : 'badge-suspicious'}">${r.severity}</span>
                  <button class="btn btn-secondary btn-sm" onclick="ThreatsView.toggleRule('${r.id}')" style="padding: 2px 8px; font-size: 11px;">
                    ${r.enabled ? 'Enabled' : 'Disabled'}
                  </button>
                </div>
              </div>

              <p style="font-size: 12px; color: var(--text-secondary); margin-bottom: 12px;">${r.description}</p>

              <div style="display: flex; justify-content: space-between; align-items: center; font-size: 12px; pt-2; border-top: 1px solid var(--border-subtle); padding-top: 10px;">
                <span style="color: var(--text-muted);">Total Detections Logged:</span>
                <span class="mono" style="font-weight: 700; color: ${r.severity === 'High-Risk' ? 'var(--state-danger)' : 'var(--state-warning)'};">${r.hit_count} hits</span>
              </div>
            </div>
          `).join("")}
        </div>

        <!-- Dynamic Sensitivity Tuner & Rule Test Bench -->
        <div>
          <!-- Sensitivity Sliders -->
          <div class="card" style="margin-bottom: var(--space-xl);">
            <div class="card-header">
              <div class="card-title">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
                Dynamic Heuristic Threshold Calibration
              </div>
              <span class="badge badge-normal">Adaptive</span>
            </div>

            <!-- Slider 1: SYN Flood PPS -->
            <div class="slider-group">
              <div class="slider-header">
                <span class="slider-label">R02: SYN Flood Trigger Threshold (PPS)</span>
                <span class="slider-value" id="val-thresh-pps">350 pps</span>
              </div>
              <input type="range" class="cyber-slider" min="100" max="800" step="25" value="350"
                     oninput="ThreatsView.updateThreshold('R02', 'threshold_pps', this.value, 'val-thresh-pps', ' pps')" />
            </div>

            <!-- Slider 2: Telnet Conn Freq -->
            <div class="slider-group">
              <div class="slider-header">
                <span class="slider-label">R01: Telnet Brute Force Rate (Conn / 10s)</span>
                <span class="slider-value" id="val-thresh-conn">15 conn</span>
              </div>
              <input type="range" class="cyber-slider" min="5" max="40" step="1" value="15"
                     oninput="ThreatsView.updateThreshold('R01', 'threshold_conn_freq', this.value, 'val-thresh-conn', ' conn')" />
            </div>

            <!-- Slider 3: Port Sweep Distinct Targets -->
            <div class="slider-group">
              <div class="slider-header">
                <span class="slider-label">R05: Port Sweep Unique Target Limit</span>
                <span class="slider-value" id="val-thresh-ips">12 IPs</span>
              </div>
              <input type="range" class="cyber-slider" min="4" max="30" step="1" value="12"
                     oninput="ThreatsView.updateThreshold('R05', 'threshold_unique_ips', this.value, 'val-thresh-ips', ' IPs')" />
            </div>

            <!-- Slider 4: Payload Entropy -->
            <div class="slider-group">
              <div class="slider-header">
                <span class="slider-label">R06: C2 Payload Anomaly Max Entropy</span>
                <span class="slider-value" id="val-thresh-entropy">7.60</span>
              </div>
              <input type="range" class="cyber-slider" min="6.0" max="7.9" step="0.05" value="7.60"
                     oninput="ThreatsView.updateThreshold('R06', 'threshold_entropy_max', this.value, 'val-thresh-entropy', '')" />
            </div>
          </div>

          <!-- Rule Verification Test Bench -->
          <div class="card">
            <div class="card-header">
              <div class="card-title">Instant Rule Engine Verification Bench</div>
              <button class="btn btn-secondary btn-sm" onclick="ThreatsView.loadPresetTest('mirai')">Load Mirai Vector</button>
            </div>
            <p style="font-size: 12px; margin-bottom: 12px;">Simulate flow parameters against configured rules to verify triggered heuristics:</p>

            <div class="grid-2" style="gap: 10px; margin-bottom: 12px;">
              <div>
                <label style="font-size: 11px; color: var(--text-muted);">Target Port:</label>
                <input type="number" id="test-port" value="23" style="width: 100%; background: var(--bg-surface); color: #fff; border: 1px solid var(--border-subtle); padding: 6px; border-radius: 4px; font-family: var(--font-mono); font-size: 12px;" />
              </div>
              <div>
                <label style="font-size: 11px; color: var(--text-muted);">Packet Rate (pps):</label>
                <input type="number" id="test-pps" value="480" style="width: 100%; background: var(--bg-surface); color: #fff; border: 1px solid var(--border-subtle); padding: 6px; border-radius: 4px; font-family: var(--font-mono); font-size: 12px;" />
              </div>
              <div>
                <label style="font-size: 11px; color: var(--text-muted);">SYN Ratio (0-1):</label>
                <input type="number" step="0.05" id="test-syn" value="0.92" style="width: 100%; background: var(--bg-surface); color: #fff; border: 1px solid var(--border-subtle); padding: 6px; border-radius: 4px; font-family: var(--font-mono); font-size: 12px;" />
              </div>
              <div>
                <label style="font-size: 11px; color: var(--text-muted);">Conn Freq (/10s):</label>
                <input type="number" id="test-conn" value="28" style="width: 100%; background: var(--bg-surface); color: #fff; border: 1px solid var(--border-subtle); padding: 6px; border-radius: 4px; font-family: var(--font-mono); font-size: 12px;" />
              </div>
            </div>

            <button class="btn btn-primary" style="width: 100%; margin-bottom: 12px;" onclick="ThreatsView.evaluateTestFlow()">
              Run Rule Verification Now
            </button>

            <div id="test-bench-output" style="background: var(--bg-surface); padding: 12px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle); font-size: 12px;">
              Ready. Click "Run Rule Verification Now" or "Load Mirai Vector".
            </div>
          </div>
        </div>
      </div>
    `;
  },

  async toggleRule(ruleId) {
    const rules = App.state.rules || [];
    const target = rules.find(r => r.id === ruleId);
    if (target) {
      target.enabled = !target.enabled;
      App.showToast(`Rule ${ruleId} ${target.enabled ? 'enabled' : 'disabled'}`, "info");
      this.render(document.getElementById("view-threats"));
      // Sync with server if online
      try {
        await window.ApiClient.detection.updateRule(ruleId, { enabled: target.enabled });
      } catch (e) { /* offline ok */ }
    }
  },

  async updateThreshold(ruleId, field, val, displayId, unit) {
    const el = document.getElementById(displayId);
    if (el) el.textContent = `${val}${unit}`;

    // Sync with server
    try {
      await window.ApiClient.detection.updateRule(ruleId, { threshold: parseFloat(val) });
    } catch (e) { /* offline ok */ }
  },

  loadPresetTest(preset) {
    if (preset === 'mirai') {
      document.getElementById("test-port").value = 23;
      document.getElementById("test-pps").value = 520;
      document.getElementById("test-syn").value = 0.94;
      document.getElementById("test-conn").value = 32;
    }
    this.evaluateTestFlow();
  },

  evaluateTestFlow() {
    const port = parseInt(document.getElementById("test-port").value, 10);
    const pps = parseFloat(document.getElementById("test-pps").value);
    const syn = parseFloat(document.getElementById("test-syn").value);
    const conn = parseFloat(document.getElementById("test-conn").value);

    const matches = [];
    if (port === 23 && conn >= 15) {
      matches.push({ id: "R01", name: "Telnet/SSH Brute Force Sweep", reason: `High connection frequency (${conn}/10s) to port ${port}` });
    }
    if (pps >= 350 && syn >= 0.80) {
      matches.push({ id: "R02", name: "TCP SYN Volumetric Flood", reason: `PPS (${pps}) and SYN ratio (${syn}) indicate volumetric exhaustion attack.` });
    }

    const out = document.getElementById("test-bench-output");
    if (!out) return;

    if (matches.length === 0) {
      out.innerHTML = `<span style="color: var(--highlight-mint); font-weight: 600;">✓ Pass:</span> Flow satisfies current baseline thresholds. No rules triggered.`;
    } else {
      out.innerHTML = `
        <div style="color: var(--state-danger); font-weight: 700; margin-bottom: 6px;">
          ⚠️ ${matches.length} Violation(s) Detected (High-Risk):
        </div>
        ${matches.map(m => `
          <div style="margin-bottom: 4px; padding-left: 8px; border-left: 2px solid var(--state-danger);">
            <strong>[${m.id}] ${m.name}</strong>: ${m.reason}
          </div>
        `).join("")}
      `;
    }
  }
};
