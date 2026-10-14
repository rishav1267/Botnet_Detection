/**
 * IoT Botnet Detection System — Overview Dashboard View
 * Complete Part 2 Implementation:
 * - 6 KPI Cards with smooth count-up animations and interval comparisons
 * - Distinctive Animated Network Topology Canvas (Interactive Nodes, Particles, Pulse, Detail Panel)
 * - 4 Responsive Interactive Charts with working time filters (5m, 1h, 24h, 7d):
 *   1. Network Traffic Over Time & Normal vs Suspicious Flows
 *   2. IoT Device Risk Spectrum (Interactive Donut with Legend)
 *   3. Alert Frequency Timeline
 *   4. Traffic Volume by Protocol & Targeted Ports
 * - Hover tooltips, legends, axes, and empty states
 */

window.OverviewView = {
  topologyCanvas: null,
  topologyCtx: null,
  topologyAnimationId: null,
  topologyNodes: [],
  topologyParticles: [],
  hoveredNode: null,
  selectedNode: null,
  activeTimeframe: "1h",
  activeChartTab: "traffic", // traffic | risk | alerts | protocols
  chartHoverIndex: -1,

  // Multi-Timeframe Comprehensive Dataset Model
  timeframeData: {
    "5m": {
      label: "Last 5 Minutes",
      labels: ["4m ago", "3m ago", "2m ago", "1m ago", "Just Now"],
      normalPps: [380, 410, 420, 440, 465],
      suspiciousPps: [30, 45, 52, 60, 68],
      highRiskPps: [10, 25, 38, 180, 540],
      totalMb: "482 MB",
      avgPps: 1073,
      peakPps: 1240,
      alertsCrit: [0, 1, 0, 1, 2],
      alertsWarn: [1, 0, 1, 1, 1],
      protocols: [
        { name: "TCP", pct: 54, mb: "260 MB", color: "#22C55E" },
        { name: "UDP", pct: 26, mb: "125 MB", color: "#F59E0B" },
        { name: "MQTT", pct: 11, mb: "53 MB", color: "#38BDF8" },
        { name: "RTSP", pct: 7, mb: "34 MB", color: "#A78BFA" },
        { name: "CoAP", pct: 2, mb: "10 MB", color: "#94A3B8" }
      ],
      ports: [
        { port: 23, name: "Telnet (Mirai)", count: 1420, risk: "High-Risk" },
        { port: 80, name: "HTTP", count: 740, risk: "Suspicious" },
        { port: 53, name: "DNS Amplification", count: 420, risk: "High-Risk" },
        { port: 554, name: "RTSP Stream", count: 280, risk: "Normal" }
      ]
    },
    "1h": {
      label: "Last 1 Hour",
      labels: ["50m ago", "40m ago", "30m ago", "20m ago", "10m ago", "Just Now"],
      normalPps: [2600, 2750, 2680, 2800, 2980, 3200],
      suspiciousPps: [180, 240, 210, 320, 380, 450],
      highRiskPps: [70, 110, 90, 330, 760, 890],
      totalMb: "5.92 GB",
      avgPps: 1240,
      peakPps: 4540,
      alertsCrit: [1, 2, 1, 3, 4, 6],
      alertsWarn: [2, 3, 2, 4, 3, 5],
      protocols: [
        { name: "TCP", pct: 52, mb: "3.08 GB", color: "#22C55E" },
        { name: "UDP", pct: 28, mb: "1.66 GB", color: "#F59E0B" },
        { name: "MQTT", pct: 10, mb: "592 MB", color: "#38BDF8" },
        { name: "RTSP", pct: 7, mb: "414 MB", color: "#A78BFA" },
        { name: "CoAP", pct: 3, mb: "178 MB", color: "#94A3B8" }
      ],
      ports: [
        { port: 23, name: "Telnet (Mirai)", count: 9840, risk: "High-Risk" },
        { port: 80, name: "HTTP", count: 4310, risk: "Suspicious" },
        { port: 53, name: "DNS Amplification", count: 2420, risk: "High-Risk" },
        { port: 554, name: "RTSP Stream", count: 1680, risk: "Normal" }
      ]
    },
    "24h": {
      label: "Last 24 Hours",
      labels: ["00:00", "04:00", "08:00", "12:00", "16:00", "20:00", "Now"],
      normalPps: [12000, 11500, 16800, 24500, 23000, 19500, 18200],
      suspiciousPps: [850, 790, 1420, 2100, 1980, 1650, 1540],
      highRiskPps: [220, 190, 890, 2840, 3420, 2980, 2450],
      totalMb: "64.2 GB",
      avgPps: 980,
      peakPps: 29440,
      alertsCrit: [4, 2, 8, 19, 24, 18, 14],
      alertsWarn: [8, 6, 14, 28, 22, 16, 12],
      protocols: [
        { name: "TCP", pct: 51, mb: "32.7 GB", color: "#22C55E" },
        { name: "UDP", pct: 30, mb: "19.3 GB", color: "#F59E0B" },
        { name: "MQTT", pct: 9, mb: "5.8 GB", color: "#38BDF8" },
        { name: "RTSP", pct: 7, mb: "4.5 GB", color: "#A78BFA" },
        { name: "CoAP", pct: 3, mb: "1.9 GB", color: "#94A3B8" }
      ],
      ports: [
        { port: 23, name: "Telnet (Mirai)", count: 14205, risk: "High-Risk" },
        { port: 80, name: "HTTP", count: 7430, risk: "Suspicious" },
        { port: 53, name: "DNS Amplification", count: 4210, risk: "High-Risk" },
        { port: 554, name: "RTSP Stream", count: 3120, risk: "Normal" }
      ]
    },
    "7d": {
      label: "Last 7 Days",
      labels: ["Day 1", "Day 2", "Day 3", "Day 4", "Day 5", "Day 6", "Today"],
      normalPps: [82000, 85000, 91000, 88000, 94000, 96000, 99000],
      suspiciousPps: [5800, 6200, 7100, 6900, 8400, 9100, 8800],
      highRiskPps: [1200, 1450, 2900, 4100, 8900, 12400, 14200],
      totalMb: "418.5 GB",
      avgPps: 1120,
      peakPps: 122000,
      alertsCrit: [18, 22, 35, 48, 84, 112, 126],
      alertsWarn: [45, 52, 60, 72, 88, 94, 89],
      protocols: [
        { name: "TCP", pct: 53, mb: "221.8 GB", color: "#22C55E" },
        { name: "UDP", pct: 27, mb: "113.0 GB", color: "#F59E0B" },
        { name: "MQTT", pct: 10, mb: "41.8 GB", color: "#38BDF8" },
        { name: "RTSP", pct: 7, mb: "29.3 GB", color: "#A78BFA" },
        { name: "CoAP", pct: 3, mb: "12.6 GB", color: "#94A3B8" }
      ],
      ports: [
        { port: 23, name: "Telnet (Mirai)", count: 68400, risk: "High-Risk" },
        { port: 80, name: "HTTP", count: 38200, risk: "Suspicious" },
        { port: 53, name: "DNS Amplification", count: 21900, risk: "High-Risk" },
        { port: 554, name: "RTSP Stream", count: 15400, risk: "Normal" }
      ]
    }
  },

  render(container) {
    container.innerHTML = `
      <!-- Active High-Priority Alert Banner if any threats -->
      <div id="overview-alert-banner" class="alert-banner" style="display: none;">
        <div class="alert-banner-left">
          <div class="kpi-icon-wrapper danger">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          </div>
          <div>
            <div style="font-weight: 700; color: #F0FDF4; font-size: 14px;" id="alert-banner-title">Critical Botnet Incursion Detected</div>
            <div style="font-size: 12px; color: var(--text-secondary);" id="alert-banner-desc">Analyzing high packet rate flood...</div>
          </div>
        </div>
        <div style="display: flex; gap: 8px;">
          <button class="btn btn-danger btn-sm" id="btn-banner-quarantine">Isolate Asset</button>
          <button class="btn btn-secondary btn-sm" onclick="App.navigateTo('alerts')">Review Alert</button>
        </div>
      </div>

      <!-- Quick Attack Simulation Controls -->
      <div class="card" style="margin-bottom: var(--space-xl); padding: 14px 20px; background: rgba(16, 53, 38, 0.6);">
        <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px;">
          <div style="display: flex; align-items: center; gap: 10px;">
            <span class="pulse-indicator"></span>
            <span style="font-size: 13px; font-weight: 600; color: var(--text-main);">Demonstration Traffic Generator:</span>
            <span style="font-size: 12px; color: var(--text-secondary);">(Live attack injection & feature evaluation)</span>
          </div>
          <div style="display: flex; gap: 8px; flex-wrap: wrap;">
            <button class="btn btn-secondary btn-sm" onclick="OverviewView.triggerScenario('mirai_telnet')">⚡ Simulate Mirai Scan</button>
            <button class="btn btn-secondary btn-sm" onclick="OverviewView.triggerScenario('syn_flood')">💥 Simulate SYN Flood</button>
            <button class="btn btn-secondary btn-sm" onclick="OverviewView.triggerScenario('c2_beacon')">🛰️ Simulate C2 Beacon</button>
            <button class="btn btn-primary btn-sm" onclick="OverviewView.triggerScenario('reset')">✓ Benign Baseline</button>
          </div>
        </div>
      </div>

      <!-- 6 MANDATORY KPI CARDS WITH COUNT-UP & INTERVAL COMPARISONS -->
      <div class="grid-3" style="margin-bottom: var(--space-xl); display: grid; grid-template-columns: repeat(6, 1fr); gap: 14px;" id="kpi-cards-row">
        <!-- 1. Total Connected Devices -->
        <div class="kpi-card" style="padding: 16px;">
          <div class="kpi-top">
            <span class="kpi-label">Total Connected</span>
            <div class="kpi-icon-wrapper">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
            </div>
          </div>
          <div class="kpi-value" id="kpi-total-devices" data-val="8">8</div>
          <div class="kpi-subtext highlight-safe">
            <span>↑ +1 vs last interval</span>
          </div>
        </div>

        <!-- 2. Normal Devices -->
        <div class="kpi-card" style="padding: 16px;">
          <div class="kpi-top">
            <span class="kpi-label">Normal Devices</span>
            <div class="kpi-icon-wrapper">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            </div>
          </div>
          <div class="kpi-value" id="kpi-normal-count" data-val="5" style="color: var(--primary-accent);">5</div>
          <div class="kpi-subtext highlight-safe">
            <span id="kpi-normal-pct-sub">62.5% fleet healthy</span>
          </div>
        </div>

        <!-- 3. Suspicious Devices -->
        <div class="kpi-card" style="padding: 16px;">
          <div class="kpi-top">
            <span class="kpi-label">Suspicious</span>
            <div class="kpi-icon-wrapper warning">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            </div>
          </div>
          <div class="kpi-value" id="kpi-suspicious-count" data-val="1" style="color: var(--state-warning);">1</div>
          <div class="kpi-subtext highlight-warn">
            <span id="kpi-susp-pct-sub">12.5% anomalous</span>
          </div>
        </div>

        <!-- 4. High-Risk Devices -->
        <div class="kpi-card" style="padding: 16px;">
          <div class="kpi-top">
            <span class="kpi-label">High-Risk Devices</span>
            <div class="kpi-icon-wrapper danger">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"><polygon points="12 2 2 22 22 22 12 2"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            </div>
          </div>
          <div class="kpi-value" id="kpi-high-risk" data-val="2" style="color: var(--state-danger);">2</div>
          <div class="kpi-subtext highlight-danger">
            <span id="kpi-high-pct-sub">25.0% botnet vectors</span>
          </div>
        </div>

        <!-- 5. Network Packets per Second -->
        <div class="kpi-card" style="padding: 16px;">
          <div class="kpi-top">
            <span class="kpi-label">Network PPS</span>
            <div class="kpi-icon-wrapper">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
            </div>
          </div>
          <div class="kpi-value" id="kpi-current-pps" data-val="1073" style="font-size: 22px;">1,073</div>
          <div class="kpi-subtext">
            <span>Live packet velocity</span>
          </div>
        </div>

        <!-- 6. Total Data Transferred -->
        <div class="kpi-card" style="padding: 16px;">
          <div class="kpi-top">
            <span class="kpi-label">Data Transferred</span>
            <div class="kpi-icon-wrapper">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
            </div>
          </div>
          <div class="kpi-value" id="kpi-total-bytes" style="font-size: 22px;">5.92 GB</div>
          <div class="kpi-subtext highlight-safe">
            <span>Cumulative telemetry</span>
          </div>
        </div>
      </div>

      <!-- ANIMATED NETWORK TOPOLOGY MAP (Distinctive Section) -->
      <div class="card" style="margin-bottom: var(--space-xl); position: relative; overflow: hidden; padding: 0;">
        <div style="padding: 16px 20px; border-bottom: 1px solid var(--border-subtle); display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px;">
          <div>
            <div class="card-title" style="display: flex; align-items: center; gap: 8px;">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="4"/><line x1="4.93" y1="4.93" x2="9.17" y2="9.17"/><line x1="14.83" y1="14.83" x2="19.07" y2="19.07"/><line x1="14.83" y1="9.17" x2="19.07" y2="4.93"/><line x1="4.93" y1="19.07" x2="9.17" y2="14.83"/></svg>
              Live IoT Network Topology Map
            </div>
            <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">
              DEMONSTRATION TOPOLOGY: Central NETGUARD hub with orbiting device telemetry & real-time packet flow particles
            </div>
          </div>

          <!-- Topology Legend & Controls -->
          <div style="display: flex; align-items: center; gap: 14px; font-size: 12px;">
            <div class="legend-item"><span class="legend-dot safe"></span> <span>Normal (Green)</span></div>
            <div class="legend-item"><span class="legend-dot warn"></span> <span>Suspicious (Amber)</span></div>
            <div class="legend-item"><span class="legend-dot danger"></span> <span>High-Risk (Red)</span></div>
            <span class="ip-chip" style="cursor: default;">Click node to inspect</span>
          </div>
        </div>

        <div style="position: relative; width: 100%; height: 380px; background: radial-gradient(circle at center, rgba(16, 53, 38, 0.9) 0%, rgba(7, 27, 19, 0.95) 70%, #071B13 100%);">
          <canvas id="network-topology-canvas" style="width: 100%; height: 100%; display: block; cursor: pointer;"></canvas>

          <!-- Interactive Node Hover Tooltip -->
          <div id="topology-tooltip" style="position: absolute; display: none; pointer-events: none; background: rgba(7, 27, 19, 0.95); border: 1px solid var(--border-medium); border-radius: 6px; padding: 8px 12px; font-size: 11px; z-index: 10; box-shadow: 0 4px 16px rgba(0,0,0,0.5);">
            <!-- Rendered on hover -->
          </div>
        </div>
      </div>

      <!-- TIMEFRAME CONTROLS TOOLBAR -->
      <div class="card" style="margin-bottom: var(--space-lg); padding: 12px 20px;">
        <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px;">
          <div style="display: flex; align-items: center; gap: 10px;">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
            <strong style="color: var(--text-main); font-size: 13px;">Historical Telemetry Window:</strong>
            <span style="font-size: 12px; color: var(--text-secondary);" id="active-timeframe-label">Last 1 Hour</span>
          </div>

          <!-- Working Timeframe Filter Buttons -->
          <div style="display: flex; gap: 6px; background: var(--bg-surface); padding: 4px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle);">
            <button class="timeframe-tab ${this.activeTimeframe === '5m' ? 'active' : ''}" onclick="OverviewView.setTimeframe('5m')">5 Minutes</button>
            <button class="timeframe-tab ${this.activeTimeframe === '1h' ? 'active' : ''}" onclick="OverviewView.setTimeframe('1h')">1 Hour</button>
            <button class="timeframe-tab ${this.activeTimeframe === '24h' ? 'active' : ''}" onclick="OverviewView.setTimeframe('24h')">24 Hours</button>
            <button class="timeframe-tab ${this.activeTimeframe === '7d' ? 'active' : ''}" onclick="OverviewView.setTimeframe('7d')">7 Days</button>
          </div>
        </div>
      </div>

      <!-- INTERACTIVE CHARTS 2x2 GRID (All 5 Required Charts) -->
      <div class="grid-2" style="margin-bottom: var(--space-xl);">
        <!-- CHART 1: Network Traffic Over Time & Normal vs Suspicious Flow -->
        <div class="card">
          <div class="card-header">
            <div>
              <div class="card-title">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
                Network Traffic Over Time (Normal vs Suspicious)
              </div>
              <span class="card-subtitle">Real-time packet rates across security classifications</span>
            </div>
            <div style="display: flex; gap: 10px; font-size: 11px;">
              <span style="display: flex; align-items: center; gap: 4px;"><span class="legend-dot safe"></span> Normal</span>
              <span style="display: flex; align-items: center; gap: 4px;"><span class="legend-dot warn"></span> Suspicious</span>
              <span style="display: flex; align-items: center; gap: 4px;"><span class="legend-dot danger"></span> High-Risk</span>
            </div>
          </div>

          <div style="width: 100%; height: 210px; position: relative;">
            <canvas id="chart-traffic-timeline" style="width: 100%; height: 100%; display: block; cursor: crosshair;"></canvas>
            <div id="chart-traffic-tooltip" class="chart-tooltip"></div>
          </div>

          <div style="display: flex; justify-content: space-between; margin-top: 10px; font-size: 11px; color: var(--text-secondary); pt-2; border-top: 1px solid var(--border-subtle); padding-top: 8px;">
            <span>Peak Velocity: <strong style="color: var(--highlight-mint); font-family: var(--font-mono);" id="chart-peak-pps">4,540 pps</strong></span>
            <span>Interval Volume: <strong style="color: var(--text-main); font-family: var(--font-mono);" id="chart-total-mb">5.92 GB</strong></span>
          </div>
        </div>

        <!-- CHART 2: Risk Distribution Across Devices (Interactive Donut) -->
        <div class="card">
          <div class="card-header">
            <div>
              <div class="card-title">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10"/><path d="M12 2a10 10 0 0 1 10 10"/></svg>
                IoT Device Risk Distribution Spectrum
              </div>
              <span class="card-subtitle">Classification ratio across 8 managed endpoints</span>
            </div>
            <span class="badge badge-normal" id="risk-donut-total-badge">8 Endpoints</span>
          </div>

          <div style="display: flex; align-items: center; justify-content: space-around; height: 210px;">
            <div style="position: relative; width: 170px; height: 170px;">
              <canvas id="chart-risk-donut" style="width: 170px; height: 170px; display: block; cursor: pointer;"></canvas>
              <div style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); text-align: center; pointer-events: none;">
                <div style="font-size: 22px; font-weight: 700; font-family: var(--font-mono); color: var(--text-main);" id="donut-center-total">8</div>
                <div style="font-size: 10px; text-transform: uppercase; color: var(--text-secondary);">Devices</div>
              </div>
            </div>

            <div style="display: flex; flex-direction: column; gap: 10px; font-size: 12px;" id="risk-donut-legend">
              <div style="display: flex; align-items: center; justify-content: space-between; gap: 14px;">
                <span style="display: flex; align-items: center; gap: 6px;"><span class="legend-dot safe"></span> Normal:</span>
                <strong class="mono" style="color: var(--primary-accent);" id="donut-legend-norm">5 (62.5%)</strong>
              </div>
              <div style="display: flex; align-items: center; justify-content: space-between; gap: 14px;">
                <span style="display: flex; align-items: center; gap: 6px;"><span class="legend-dot warn"></span> Suspicious:</span>
                <strong class="mono" style="color: var(--state-warning);" id="donut-legend-susp">1 (12.5%)</strong>
              </div>
              <div style="display: flex; align-items: center; justify-content: space-between; gap: 14px;">
                <span style="display: flex; align-items: center; gap: 6px;"><span class="legend-dot danger"></span> High-Risk:</span>
                <strong class="mono" style="color: var(--state-danger);" id="donut-legend-high">2 (25.0%)</strong>
              </div>
            </div>
          </div>

          <div style="margin-top: 10px; font-size: 11px; color: var(--text-muted); text-align: center; pt-2; border-top: 1px solid var(--border-subtle); padding-top: 8px;">
            Hover slices to inspect risk category breakdown
          </div>
        </div>

        <!-- CHART 3: Alert Frequency Over Time (Timeline Bars) -->
        <div class="card">
          <div class="card-header">
            <div>
              <div class="card-title">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
                Security Alert Frequency Over Time
              </div>
              <span class="card-subtitle">Critical incursion spikes & warning anomaly frequency</span>
            </div>
            <div style="display: flex; gap: 8px; font-size: 11px;">
              <span style="display: flex; align-items: center; gap: 4px;"><span class="legend-dot danger"></span> Critical</span>
              <span style="display: flex; align-items: center; gap: 4px;"><span class="legend-dot warn"></span> Warning</span>
            </div>
          </div>

          <div style="width: 100%; height: 210px; position: relative;">
            <canvas id="chart-alerts-timeline" style="width: 100%; height: 100%; display: block; cursor: pointer;"></canvas>
            <div id="chart-alerts-tooltip" class="chart-tooltip"></div>
          </div>

          <div style="display: flex; justify-content: space-between; margin-top: 10px; font-size: 11px; color: var(--text-secondary); pt-2; border-top: 1px solid var(--border-subtle); padding-top: 8px;">
            <span>Unresolved Incidents: <strong style="color: var(--state-danger);" id="alerts-freq-unresolved">3</strong></span>
            <span>Historical Spike: <strong style="color: var(--highlight-mint);" id="alerts-freq-peak">10 / slice</strong></span>
          </div>
        </div>

        <!-- CHART 4: Traffic Volume by Protocol & Targeted Ports -->
        <div class="card">
          <div class="card-header">
            <div>
              <div class="card-title">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
                Traffic Volume by Protocol & Target Ports
              </div>
              <span class="card-subtitle">Layer 4/7 distribution and targeted IoT attack vectors</span>
            </div>
            <span class="ip-chip" id="proto-total-bytes-chip">5.92 GB</span>
          </div>

          <div style="height: 210px; display: flex; flex-direction: column; justify-content: space-around;" id="chart-protocols-bars">
            <!-- Rendered dynamically -->
          </div>

          <div style="display: flex; justify-content: space-between; margin-top: 10px; font-size: 11px; color: var(--text-secondary); pt-2; border-top: 1px solid var(--border-subtle); padding-top: 8px;">
            <span>Top Attack Vector: <strong style="color: var(--state-danger);">Port 23 Telnet (Mirai)</strong></span>
            <span>Encrypted Streams: <strong style="color: var(--highlight-mint);">TLS / MQTT (21%)</strong></span>
          </div>
        </div>
      </div>

      <!-- DEVICE DETAIL PANEL (Slide-in drawer / modal from topology node click) -->
      <div id="device-detail-drawer" class="modal-backdrop">
        <div class="cyber-modal" id="device-detail-drawer-content">
          <!-- Filled dynamically -->
        </div>
      </div>
    `;

    // Initialize Canvas & All 4 Charts
    this.initTopology();
    this.renderAllCharts();
    this.updateData();
  },

  setTimeframe(tf) {
    this.activeTimeframe = tf;

    // Update tab classes
    document.querySelectorAll(".timeframe-tab").forEach(tab => {
      tab.classList.toggle("active", tab.textContent.toLowerCase().includes(tf));
    });

    const labelEl = document.getElementById("active-timeframe-label");
    if (labelEl && this.timeframeData[tf]) {
      labelEl.textContent = this.timeframeData[tf].label;
    }

    // Smoothly redraw all 4 charts without rebuilding whole DOM
    this.renderAllCharts();
    App.showToast(`Updated charts to: ${this.timeframeData[tf].label}`, "info");
  },

  renderAllCharts() {
    this.renderTrafficTimeline();
    this.renderRiskDonut();
    this.renderAlertsTimeline();
    this.renderProtocolBars();
  },

  // 1. Network Traffic Timeline Area Chart
  renderTrafficTimeline() {
    const canvas = document.getElementById("chart-traffic-timeline");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);

    const data = this.timeframeData[this.activeTimeframe] || this.timeframeData["1h"];
    const tooltip = document.getElementById("chart-traffic-tooltip");

    const peakEl = document.getElementById("chart-peak-pps");
    if (peakEl) peakEl.textContent = `${data.peakPps.toLocaleString()} pps`;

    const totalEl = document.getElementById("chart-total-mb");
    if (totalEl) totalEl.textContent = data.totalMb;

    ctx.clearRect(0, 0, rect.width, rect.height);

    const padLeft = 45;
    const padRight = 15;
    const padTop = 15;
    const padBottom = 25;
    const w = rect.width - padLeft - padRight;
    const h = rect.height - padTop - padBottom;

    const n = data.labels.length;
    const maxVal = Math.max(...data.normalPps, ...data.suspiciousPps, ...data.highRiskPps) * 1.25;

    // Grid lines
    ctx.strokeStyle = "rgba(34, 197, 94, 0.08)";
    ctx.lineWidth = 1;
    for (let i = 0; i <= 3; i++) {
      const y = padTop + (h / 3) * i;
      ctx.beginPath();
      ctx.moveTo(padLeft, y);
      ctx.lineTo(rect.width - padRight, y);
      ctx.stroke();

      ctx.fillStyle = "#5F7A6E";
      ctx.font = "9px JetBrains Mono, monospace";
      ctx.textAlign = "right";
      const valLabel = Math.round(maxVal - (maxVal / 3) * i);
      ctx.fillText(valLabel.toLocaleString(), padLeft - 6, y + 3);
    }

    // Helper to draw series line + fill
    const drawSeries = (seriesData, color, fillColor) => {
      ctx.beginPath();
      for (let i = 0; i < n; i++) {
        const x = padLeft + (w / (n - 1)) * i;
        const y = padTop + h - (seriesData[i] / maxVal) * h;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.strokeStyle = color;
      ctx.lineWidth = 2;
      ctx.shadowColor = color;
      ctx.shadowBlur = 6;
      ctx.stroke();
      ctx.shadowBlur = 0;

      // Fill area under curve
      ctx.lineTo(padLeft + w, padTop + h);
      ctx.lineTo(padLeft, padTop + h);
      ctx.closePath();
      ctx.fillStyle = fillColor;
      ctx.fill();
    };

    // Draw High-Risk, Suspicious, Normal
    drawSeries(data.highRiskPps, "#EF4444", "rgba(239, 68, 68, 0.12)");
    drawSeries(data.suspiciousPps, "#F59E0B", "rgba(245, 158, 11, 0.12)");
    drawSeries(data.normalPps, "#22C55E", "rgba(34, 197, 94, 0.18)");

    // X Axis Labels
    ctx.fillStyle = "#8FA89B";
    ctx.font = "10px Inter, sans-serif";
    ctx.textAlign = "center";
    for (let i = 0; i < n; i++) {
      const x = padLeft + (w / (n - 1)) * i;
      ctx.fillText(data.labels[i], x, rect.height - 6);
    }

    // Interactive Mousemove Crosshair & Tooltip
    canvas.onmousemove = (e) => {
      const b = canvas.getBoundingClientRect();
      const mx = e.clientX - b.left;
      const my = e.clientY - b.top;

      if (mx >= padLeft && mx <= rect.width - padRight) {
        const step = w / (n - 1);
        const idx = Math.min(n - 1, Math.max(0, Math.round((mx - padLeft) / step)));
        const cx = padLeft + idx * step;

        // Draw crosshair
        this.renderTrafficTimeline(); // clean redraw
        ctx.strokeStyle = "rgba(134, 239, 172, 0.4)";
        ctx.setLineDash([3, 3]);
        ctx.beginPath();
        ctx.moveTo(cx, padTop);
        ctx.lineTo(cx, padTop + h);
        ctx.stroke();
        ctx.setLineDash([]);

        // Show Tooltip
        if (tooltip) {
          tooltip.style.display = "block";
          tooltip.style.left = `${Math.min(rect.width - 150, cx + 10)}px`;
          tooltip.style.top = `${my - 20}px`;
          tooltip.innerHTML = `
            <div style="font-weight: 700; color: #fff; margin-bottom: 2px;">${data.labels[idx]}</div>
            <div style="color: #22C55E;">● Normal: <strong>${data.normalPps[idx]} pps</strong></div>
            <div style="color: #F59E0B;">● Suspicious: <strong>${data.suspiciousPps[idx]} pps</strong></div>
            <div style="color: #EF4444;">● High-Risk: <strong>${data.highRiskPps[idx]} pps</strong></div>
          `;
        }
      }
    };

    canvas.onmouseleave = () => {
      if (tooltip) tooltip.style.display = "none";
    };
  },

  // 2. Risk Distribution Donut Chart
  renderRiskDonut() {
    const canvas = document.getElementById("chart-risk-donut");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const dpr = window.devicePixelRatio || 1;
    canvas.width = 170 * dpr;
    canvas.height = 170 * dpr;
    ctx.scale(dpr, dpr);

    const kpis = App.state.kpis || { total_devices: 8, normal_count: 5, suspicious_count: 1, high_risk_count: 2 };
    const total = kpis.total_devices || 8;
    const normal = kpis.normal_count || 5;
    const susp = kpis.suspicious_count || 1;
    const high = kpis.high_risk_count || 2;

    const segments = [
      { label: "Normal", count: normal, color: "#22C55E" },
      { label: "Suspicious", count: susp, color: "#F59E0B" },
      { label: "High-Risk", count: high, color: "#EF4444" }
    ];

    ctx.clearRect(0, 0, 170, 170);

    const cx = 85;
    const cy = 85;
    const outerR = 72;
    const innerR = 48;

    let startAngle = -Math.PI / 2;

    segments.forEach(seg => {
      const sliceAngle = (seg.count / total) * (Math.PI * 2);
      ctx.beginPath();
      ctx.arc(cx, cy, outerR, startAngle, startAngle + sliceAngle);
      ctx.arc(cx, cy, innerR, startAngle + sliceAngle, startAngle, true);
      ctx.closePath();
      ctx.fillStyle = seg.color;
      ctx.shadowColor = seg.color;
      ctx.shadowBlur = 8;
      ctx.fill();
      ctx.shadowBlur = 0;

      // Divider gap
      ctx.strokeStyle = "#071B13";
      ctx.lineWidth = 2;
      ctx.stroke();

      startAngle += sliceAngle;
    });

    // Update legend values
    const legNorm = document.getElementById("donut-legend-norm");
    const legSusp = document.getElementById("donut-legend-susp");
    const legHigh = document.getElementById("donut-legend-high");
    if (legNorm) legNorm.textContent = `${normal} (${((normal / total) * 100).toFixed(1)}%)`;
    if (legSusp) legSusp.textContent = `${susp} (${((susp / total) * 100).toFixed(1)}%)`;
    if (legHigh) legHigh.textContent = `${high} (${((high / total) * 100).toFixed(1)}%)`;
  },

  // 3. Alert Frequency Timeline
  renderAlertsTimeline() {
    const canvas = document.getElementById("chart-alerts-timeline");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);

    const data = this.timeframeData[this.activeTimeframe] || this.timeframeData["1h"];
    const tooltip = document.getElementById("chart-alerts-tooltip");

    ctx.clearRect(0, 0, rect.width, rect.height);

    const padLeft = 35;
    const padRight = 15;
    const padTop = 15;
    const padBottom = 25;
    const w = rect.width - padLeft - padRight;
    const h = rect.height - padTop - padBottom;

    const n = data.labels.length;
    const maxVal = Math.max(...data.alertsCrit.map((c, i) => c + data.alertsWarn[i]), 6) * 1.2;

    // Grid lines
    ctx.strokeStyle = "rgba(34, 197, 94, 0.08)";
    ctx.lineWidth = 1;
    for (let i = 0; i <= 3; i++) {
      const y = padTop + (h / 3) * i;
      ctx.beginPath();
      ctx.moveTo(padLeft, y);
      ctx.lineTo(rect.width - padRight, y);
      ctx.stroke();

      ctx.fillStyle = "#5F7A6E";
      ctx.font = "9px JetBrains Mono, monospace";
      ctx.textAlign = "right";
      ctx.fillText(Math.round(maxVal - (maxVal / 3) * i).toString(), padLeft - 6, y + 3);
    }

    // Stacked Bars
    const groupW = w / n;
    const barW = Math.max(12, groupW * 0.45);

    for (let i = 0; i < n; i++) {
      const x = padLeft + i * groupW + (groupW - barW) / 2;
      const hCrit = (data.alertsCrit[i] / maxVal) * h;
      const hWarn = (data.alertsWarn[i] / maxVal) * h;

      // Warning Bar (top)
      ctx.fillStyle = "#F59E0B";
      ctx.fillRect(x, padTop + h - hCrit - hWarn, barW, hWarn);

      // Critical Bar (base)
      ctx.fillStyle = "#EF4444";
      ctx.fillRect(x, padTop + h - hCrit, barW, hCrit);

      // X Label
      ctx.fillStyle = "#8FA89B";
      ctx.font = "10px Inter, sans-serif";
      ctx.textAlign = "center";
      ctx.fillText(data.labels[i], x + barW / 2, rect.height - 6);
    }

    // Canvas Hover
    canvas.onmousemove = (e) => {
      const b = canvas.getBoundingClientRect();
      const mx = e.clientX - b.left;
      const my = e.clientY - b.top;

      if (mx >= padLeft && mx <= rect.width - padRight) {
        const idx = Math.min(n - 1, Math.max(0, Math.floor((mx - padLeft) / (w / n))));
        if (tooltip) {
          tooltip.style.display = "block";
          tooltip.style.left = `${Math.min(rect.width - 140, mx + 10)}px`;
          tooltip.style.top = `${my - 20}px`;
          tooltip.innerHTML = `
            <div style="font-weight: 700; color: #fff;">${data.labels[idx]}</div>
            <div style="color: #EF4444;">● Critical Alerts: <strong>${data.alertsCrit[idx]}</strong></div>
            <div style="color: #F59E0B;">● Warning Anomalies: <strong>${data.alertsWarn[idx]}</strong></div>
          `;
        }
      }
    };

    canvas.onmouseleave = () => {
      if (tooltip) tooltip.style.display = "none";
    };
  },

  // 4. Traffic Volume by Protocol & Top Ports
  renderProtocolBars() {
    const container = document.getElementById("chart-protocols-bars");
    if (!container) return;

    const data = this.timeframeData[this.activeTimeframe] || this.timeframeData["1h"];
    const chip = document.getElementById("proto-total-bytes-chip");
    if (chip) chip.textContent = data.totalMb;

    container.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: 8px;">
        ${data.protocols.map(p => `
          <div>
            <div style="display: flex; justify-content: space-between; font-size: 11px; margin-bottom: 2px;">
              <span style="font-weight: 600; color: var(--text-main);">${p.name} Protocol</span>
              <span class="mono" style="color: ${p.color};">${p.pct}% (${p.mb})</span>
            </div>
            <div style="height: 6px; background: var(--bg-surface); border-radius: var(--radius-full); overflow: hidden;">
              <div style="width: ${p.pct}%; height: 100%; background: ${p.color}; border-radius: var(--radius-full); transition: width 0.4s ease;"></div>
            </div>
          </div>
        `).join("")}
      </div>

      <div style="margin-top: 10px; padding-top: 8px; border-top: 1px solid var(--border-subtle);">
        <div style="font-size: 10px; text-transform: uppercase; color: var(--text-muted); margin-bottom: 4px;">Top Probed IoT Ports:</div>
        <div style="display: flex; gap: 6px; flex-wrap: wrap;">
          ${data.ports.map(pt => `
            <span class="badge ${pt.risk === 'High-Risk' ? 'badge-high-risk' : 'badge-normal'}" style="font-size: 10px;">
              Port ${pt.port}: ${pt.count.toLocaleString()} probes
            </span>
          `).join("")}
        </div>
      </div>
    `;
  },

  initTopology() {
    const canvas = document.getElementById("network-topology-canvas");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);

    this.topologyCanvas = canvas;
    this.topologyCtx = ctx;

    const centerX = rect.width / 2;
    const centerY = rect.height / 2;
    const radius = Math.min(centerX, centerY) * 0.72;

    const devices = App.state.devices || (window.IOT_FALLBACK_DATA ? window.IOT_FALLBACK_DATA.devices : []);

    // Empty state check
    if (devices.length === 0) {
      ctx.clearRect(0, 0, rect.width, rect.height);
      ctx.fillStyle = "#8FA89B";
      ctx.font = "14px Inter, sans-serif";
      ctx.textAlign = "center";
      ctx.fillText("No IoT nodes currently detected on local subnet.", centerX, centerY - 10);
      ctx.font = "12px Inter, sans-serif";
      ctx.fillStyle = "#5F7A6E";
      ctx.fillText("Please connect hardware or trigger demonstration mode.", centerX, centerY + 14);
      return;
    }

    // Create Hub + Orbiting Nodes
    this.topologyNodes = [
      {
        id: "HUB-MASTER",
        name: "NETGUARD Gateway Core",
        type: "Master Monitoring Controller",
        ip: "192.168.1.1 (Gateway)",
        status: "Normal",
        pps: 1073.0,
        x: centerX,
        y: centerY,
        r: 24,
        isHub: true
      }
    ];

    devices.forEach((d, i) => {
      const angle = (i / devices.length) * (Math.PI * 2) - Math.PI / 2;
      const x = centerX + Math.cos(angle) * radius;
      const y = centerY + Math.sin(angle) * radius;
      this.topologyNodes.push({
        id: d.id,
        name: d.name,
        type: d.category,
        ip: d.ip,
        mac: d.mac,
        status: d.status,
        pps: d.pps,
        quarantined: d.quarantined,
        vulnerabilities: d.vulnerabilities,
        x,
        y,
        r: 14,
        isHub: false,
        angle
      });
    });

    // Create animated flowing particles along spokes
    this.topologyParticles = [];
    for (let i = 0; i < 40; i++) {
      const targetNode = this.topologyNodes[1 + Math.floor(Math.random() * (this.topologyNodes.length - 1))];
      this.topologyParticles.push({
        targetNode,
        progress: Math.random(),
        speed: 0.005 + Math.random() * 0.01,
        color: targetNode.status === 'High-Risk' ? '#EF4444' : (targetNode.status === 'Suspicious' ? '#F59E0B' : '#22C55E')
      });
    }

    // Canvas Mouse Listeners
    canvas.onmousemove = (e) => {
      const b = canvas.getBoundingClientRect();
      const mx = e.clientX - b.left;
      const my = e.clientY - b.top;

      let found = null;
      for (const node of this.topologyNodes) {
        const dist = Math.hypot(node.x - mx, node.y - my);
        if (dist <= node.r + 6) {
          found = node;
          break;
        }
      }
      this.hoveredNode = found;

      const tip = document.getElementById("topology-tooltip");
      if (tip) {
        if (found) {
          tip.style.display = "block";
          tip.style.left = `${Math.min(rect.width - 180, mx + 15)}px`;
          tip.style.top = `${my - 15}px`;
          tip.innerHTML = `
            <div style="font-weight: 700; color: #fff;">${found.name}</div>
            <div class="mono" style="color: var(--highlight-mint);">${found.ip}</div>
            <div style="margin-top: 4px;">Status: <span class="badge ${found.status === 'High-Risk' ? 'badge-high-risk' : (found.status === 'Suspicious' ? 'badge-suspicious' : 'badge-normal')}">${found.status}</span></div>
            <div style="font-size: 10px; color: var(--text-muted); margin-top: 2px;">Throughput: ${found.pps.toFixed(1)} pps</div>
          `;
        } else {
          tip.style.display = "none";
        }
      }
    };

    canvas.onclick = () => {
      if (this.hoveredNode) {
        this.openDeviceDetail(this.hoveredNode);
      }
    };

    let tick = 0;

    const animateTopo = () => {
      if (!document.getElementById("network-topology-canvas")) return;
      ctx.clearRect(0, 0, rect.width, rect.height);
      tick += 0.03;

      const hub = this.topologyNodes[0];

      // Draw subtle orbital guide circles
      ctx.strokeStyle = "rgba(34, 197, 94, 0.08)";
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.arc(hub.x, hub.y, radius, 0, Math.PI * 2);
      ctx.stroke();

      // Draw lines between hub and nodes
      for (let i = 1; i < this.topologyNodes.length; i++) {
        const n = this.topologyNodes[i];
        ctx.beginPath();
        ctx.moveTo(hub.x, hub.y);
        ctx.lineTo(n.x, n.y);
        ctx.strokeStyle = n.status === 'High-Risk' ? 'rgba(239, 68, 68, 0.35)' : (n.status === 'Suspicious' ? 'rgba(245, 158, 11, 0.25)' : 'rgba(34, 197, 94, 0.15)');
        ctx.lineWidth = n.status === 'High-Risk' ? 2 : 1;
        ctx.stroke();
      }

      // Update & Draw Flow Particles
      for (const p of this.topologyParticles) {
        p.progress += p.speed;
        if (p.progress >= 1.0) p.progress = 0;

        const nx = hub.x + (p.targetNode.x - hub.x) * p.progress;
        const ny = hub.y + (p.targetNode.y - hub.y) * p.progress;

        ctx.beginPath();
        ctx.arc(nx, ny, 2.5, 0, Math.PI * 2);
        ctx.fillStyle = p.color;
        ctx.shadowColor = p.color;
        ctx.shadowBlur = 6;
        ctx.fill();
        ctx.shadowBlur = 0;
      }

      // Draw Device Nodes with Gentle Pulse
      for (const n of this.topologyNodes) {
        const isHovered = this.hoveredNode && this.hoveredNode.id === n.id;
        const color = n.status === 'High-Risk' ? '#EF4444' : (n.status === 'Suspicious' ? '#F59E0B' : '#22C55E');

        // Gentle node pulse
        const pulseR = n.r + (Math.sin(tick + (n.angle || 0)) + 1) * 2;

        ctx.beginPath();
        ctx.arc(n.x, n.y, isHovered ? n.r + 6 : pulseR, 0, Math.PI * 2);
        ctx.fillStyle = n.status === 'High-Risk' ? 'rgba(239, 68, 68, 0.22)' : (n.status === 'Suspicious' ? 'rgba(245, 158, 11, 0.18)' : 'rgba(34, 197, 94, 0.18)');
        ctx.fill();

        // Node circle
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
        ctx.fillStyle = n.isHub ? '#071B13' : (n.quarantined ? '#334155' : '#103526');
        ctx.fill();
        ctx.strokeStyle = color;
        ctx.lineWidth = isHovered ? 3 : 2;
        ctx.stroke();

        // Center dot / icon
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.isHub ? 6 : 4, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.fill();

        // Label below node
        ctx.fillStyle = isHovered ? '#F0FDF4' : '#8FA89B';
        ctx.font = n.isHub ? 'bold 11px Inter, sans-serif' : '10px Inter, sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(n.name.split(' ')[0], n.x, n.y + n.r + 14);
      }

      this.topologyAnimationId = requestAnimationFrame(animateTopo);
    };

    if (this.topologyAnimationId) cancelAnimationFrame(this.topologyAnimationId);
    this.topologyAnimationId = requestAnimationFrame(animateTopo);
  },

  openDeviceDetail(node) {
    if (node.isHub) return;
    const modal = document.getElementById("device-detail-drawer");
    const content = document.getElementById("device-detail-drawer-content");
    if (!modal || !content) return;

    const isHigh = node.status === "High-Risk";

    content.innerHTML = `
      <div class="modal-header">
        <div>
          <h2 style="font-size: 18px; display: flex; align-items: center; gap: 8px;">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>
            IoT Device Telemetry & Forensic Dossier
          </h2>
          <span class="mono" style="color: var(--highlight-mint); font-size: 12px;">${node.id} — ${node.name}</span>
        </div>
        <button class="close-btn" onclick="document.getElementById('device-detail-drawer').classList.remove('open')">×</button>
      </div>

      <div class="grid-2" style="background: var(--bg-surface); padding: 14px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle); margin-bottom: 16px; font-size: 12px;">
        <div><span style="color: var(--text-muted);">IP Address:</span> <strong class="mono" style="color: var(--highlight-mint);">${node.ip}</strong></div>
        <div><span style="color: var(--text-muted);">MAC Address:</span> <span class="mono">${node.mac || '00:12:17:84:3B:11'}</span></div>
        <div><span style="color: var(--text-muted);">Device Category:</span> <span>${node.type}</span></div>
        <div><span style="color: var(--text-muted);">Security Classification:</span> <span class="badge ${isHigh ? 'badge-high-risk' : (node.status === 'Suspicious' ? 'badge-suspicious' : 'badge-normal')}">${node.status}</span></div>
      </div>

      <div style="margin-bottom: 16px;">
        <h4 style="font-size: 13px; margin-bottom: 8px;">Observed Network Behavior:</h4>
        <div style="background: var(--bg-card); padding: 12px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle); font-size: 12px;">
          <p style="margin-bottom: 6px;">
            ${isHigh 
              ? 'Volumetric packet burst detected targeting external destinations. Abnormal SYN packet ratio >0.85 with repeated connection frequency.' 
              : (node.status === 'Suspicious' 
                ? 'Elevated connection frequency to atypical local gateway ports. Marked for heuristic observation.' 
                : 'Consistent periodic telemetry conforming to standard manufacturer baseline profiles.')}
          </p>
          <div style="display: flex; gap: 14px; font-family: var(--font-mono); font-size: 11px; color: var(--text-secondary); margin-top: 8px;">
            <span>Current PPS: <strong style="color: #fff;">${node.pps.toFixed(1)}</strong></span>
            <span>Quarantined: <strong style="color: ${node.quarantined ? 'var(--state-danger)' : 'var(--primary-accent)'};">${node.quarantined ? 'YES' : 'NO'}</strong></span>
          </div>
        </div>
      </div>

      <div style="display: flex; justify-content: flex-end; gap: 8px;">
        <button class="btn btn-secondary" onclick="document.getElementById('device-detail-drawer').classList.remove('open')">Close</button>
        <button class="btn ${node.quarantined ? 'btn-primary' : (isHigh ? 'btn-danger' : 'btn-secondary')}" onclick="App.quarantineDevice('${node.id}', ${!node.quarantined}); document.getElementById('device-detail-drawer').classList.remove('open');">
          ${node.quarantined ? 'Reconnect Device' : 'Isolate Device Port'}
        </button>
      </div>
    `;

    modal.classList.add("open");
  },

  updateData() {
    const kpis = App.state.kpis;
    if (!kpis) return;

    // Use smooth count-up animations for all 6 KPI cards
    App.animateCountUp("kpi-total-devices", kpis.total_devices || 8);
    App.animateCountUp("kpi-normal-count", kpis.normal_count || 5);
    App.animateCountUp("kpi-suspicious-count", kpis.suspicious_count || 1);
    App.animateCountUp("kpi-high-risk", kpis.high_risk_count || 2);
    App.animateCountUp("kpi-current-pps", Math.round(kpis.current_pps || 1073));

    const total = kpis.total_devices || 8;
    const normPct = ((kpis.normal_count / total) * 100).toFixed(1);
    const suspPct = ((kpis.suspicious_count / total) * 100).toFixed(1);
    const highPct = ((kpis.high_risk_count / total) * 100).toFixed(1);

    const normSub = document.getElementById("kpi-normal-pct-sub");
    if (normSub) normSub.textContent = `${normPct}% fleet healthy`;

    const suspSub = document.getElementById("kpi-susp-pct-sub");
    if (suspSub) suspSub.textContent = `${suspPct}% anomalous`;

    const highSub = document.getElementById("kpi-high-pct-sub");
    if (highSub) highSub.textContent = `${highPct}% botnet vectors`;

    // Redraw risk donut with updated values
    this.renderRiskDonut();

    // Check high priority alert banner
    const alertBanner = document.getElementById("overview-alert-banner");
    const highAlert = (App.state.alerts || []).find(a => a.severity === "Critical" && !a.resolved);
    if (alertBanner && highAlert) {
      alertBanner.style.display = "flex";
      const bTitle = document.getElementById("alert-banner-title");
      const bDesc = document.getElementById("alert-banner-desc");
      if (bTitle) bTitle.textContent = highAlert.title;
      if (bDesc) bDesc.textContent = `${highAlert.device_name} — ${highAlert.details}`;
      const bQuar = document.getElementById("btn-banner-quarantine");
      if (bQuar) {
        bQuar.onclick = () => {
          App.quarantineDevice(highAlert.device_id, true);
        };
      }
    } else if (alertBanner) {
      alertBanner.style.display = "none";
    }
  },

  async triggerScenario(name) {
    App.showToast(`Simulating Attack Profile: ${name.replace('_', ' ').toUpperCase()}`, "info");
    try {
      const data = await window.ApiClient.traffic.triggerAttack(name);
      if (data && data.kpis) {
        App.state.kpis = data.kpis;
        OverviewView.updateData();
      }
      if (data && data.generated_burst) {
        App.state.flows = [...data.generated_burst, ...App.state.flows].slice(0, 100);
      }
      this.initTopology();
      this.renderAllCharts();
    } catch (e) {
      App.tickOfflineFlow(name);
      this.initTopology();
      this.renderAllCharts();
    }
  }
};
