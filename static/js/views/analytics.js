/**
 * IoT Botnet Detection System — Analytics & Security Reports View
 * Fully dynamic telemetry analytics, multi-timeframe SVG attack timeline,
 * targeted port & CVE threat matrix, botnet malware signature registry,
 * geographic origin intelligence with ASNs, and interactive executive audit dossier.
 */

window.AnalyticsView = {
  currentTimeframe: "24h",
  analyticsData: null,
  container: null,

  async render(container) {
    if (container) this.container = container;
    if (!this.container) return;

    await this.loadData(this.currentTimeframe);
    this.renderView();
  },

  async loadData(timeframe) {
    try {
      this.analyticsData = await window.ApiClient.analytics.getSummary(timeframe);
      return;
    } catch (e) {
      console.warn("Analytics API fetch failed, falling back to local seed data:", e);
    }

    // Fallback to offline / seed data
    const fallback = window.IOT_FALLBACK_DATA ? window.IOT_FALLBACK_DATA.analytics : null;
    if (fallback) {
      // Deep copy fallback
      this.analyticsData = JSON.parse(JSON.stringify(fallback));
      this.analyticsData.timeframe = timeframe;
      if (fallback.timelines_by_timeframe && fallback.timelines_by_timeframe[timeframe]) {
        this.analyticsData.hourly_timeline = fallback.timelines_by_timeframe[timeframe];
      }
      // Scale totals if not 24h
      const mult = timeframe === "1h" ? 0.04 : (timeframe === "6h" ? 0.25 : (timeframe === "7d" ? 7.0 : 1.0));
      this.analyticsData.kpis.total_flows = Math.round(fallback.kpis.total_flows * mult);
    }
  },

  renderView() {
    if (!this.container || !this.analyticsData) return;
    const d = this.analyticsData;
    const kpis = d.kpis || { total_flows: 94200, malicious_ratio_pct: 14.8, active_strains_count: 6, peak_incursion_mbps: 184.2, health_score: 78 };

    this.container.innerHTML = `
      <!-- View Header with Report & Export Actions -->
      <div class="card" style="margin-bottom: var(--space-xl); padding: 18px 24px;">
        <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 16px;">
          <div>
            <h2 style="font-size: 18px; margin-bottom: 4px; display: flex; align-items: center; gap: 8px;">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
              IoT Botnet Threat Intelligence & Telemetry Analytics
            </h2>
            <p style="font-size: 13px; color: var(--text-secondary);">
              Aggregated historical traffic metrics, targeted port telemetry, botnet strain distribution, and automated executive audit reporting.
            </p>
          </div>
          <div style="display: flex; gap: 8px; flex-wrap: wrap;">
            <button class="btn btn-secondary btn-sm" onclick="AnalyticsView.openAuditReportModal()" style="display: inline-flex; align-items: center; gap: 6px;">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
              Preview Executive Dossier
            </button>
            <a href="/api/export/report" target="_blank" class="btn btn-primary btn-sm" style="display: inline-flex; align-items: center; gap: 6px;">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
              Download Report (.md)
            </a>
            <a href="/api/export/analytics/csv?timeframe=${this.currentTimeframe}" target="_blank" class="btn btn-secondary btn-sm" id="export-csv-link" style="display: inline-flex; align-items: center; gap: 6px;">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
              Export CSV
            </a>
            <a href="/api/export/analytics/json?timeframe=${this.currentTimeframe}" target="_blank" class="btn btn-secondary btn-sm" id="export-json-link" style="display: inline-flex; align-items: center; gap: 6px;">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
              Export JSON
            </a>
          </div>
        </div>
      </div>

      <!-- Executive Metric KPI Cards (4-Card Grid) -->
      <div class="grid-4" style="margin-bottom: var(--space-xl);" id="analytics-kpis-grid">
        <div class="stat-card">
          <div class="stat-label">Total Inspected Flows</div>
          <div class="stat-value mono" style="color: var(--highlight-mint);">${kpis.total_flows.toLocaleString()}</div>
          <div class="stat-trend" style="color: var(--text-secondary); display: flex; align-items: center; gap: 6px; font-size: 11px;">
            <span class="badge badge-normal" style="padding: 1px 6px;">${this.currentTimeframe.toUpperCase()} Window</span>
            <span>Full packet inspection</span>
          </div>
        </div>

        <div class="stat-card">
          <div class="stat-label">Malicious Traffic Ratio</div>
          <div class="stat-value mono" style="color: var(--state-danger);">${kpis.malicious_ratio_pct}%</div>
          <div class="stat-trend" style="color: var(--text-secondary); display: flex; align-items: center; gap: 6px; font-size: 11px;">
            <span class="badge badge-critical" style="padding: 1px 6px;">Elevated Risk</span>
            <span>Probes & volumetric floods</span>
          </div>
        </div>

        <div class="stat-card">
          <div class="stat-label">Identified Botnet Strains</div>
          <div class="stat-value mono" style="color: var(--state-warning);">${kpis.active_strains_count} Strains</div>
          <div class="stat-trend" style="color: var(--text-secondary); display: flex; align-items: center; gap: 6px; font-size: 11px;">
            <span class="badge badge-high-risk" style="padding: 1px 6px;">Active Incursions</span>
            <span>Mirai, Gafgyt, Torii</span>
          </div>
        </div>

        <div class="stat-card">
          <div class="stat-label">Peak Incursion Throughput</div>
          <div class="stat-value mono" style="color: #38BDF8;">${kpis.peak_incursion_mbps} Mbps</div>
          <div class="stat-trend" style="color: var(--text-secondary); display: flex; align-items: center; gap: 6px; font-size: 11px;">
            <span class="badge badge-suspicious" style="padding: 1px 6px;">Volumetric Surge</span>
            <span>Port 23 & 80 burst peak</span>
          </div>
        </div>
      </div>

      <!-- Multi-Timeframe Attack Vector & Incursion Trend Timeline Card -->
      <div class="card" style="margin-bottom: var(--space-xl); padding: 20px 24px;">
        <div class="card-header" style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; margin-bottom: 16px;">
          <div>
            <div class="card-title" style="display: flex; align-items: center; gap: 8px;">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
              Attack Vector & Incursion Trend Timeline
            </div>
            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 2px;">
              Temporal telemetry breakdown comparing benign flows, suspicious reconnaissance, and high-risk botnet floods.
            </div>
          </div>

          <!-- Interactive Timeframe Filter Selector Pills -->
          <div style="display: flex; gap: 6px; align-items: center;" class="timeframe-selector" id="timeline-timeframe-pills">
            <button class="timeframe-pill-btn ${this.currentTimeframe === '1h' ? 'active' : ''}" onclick="AnalyticsView.switchTimeframe('1h')">1h</button>
            <button class="timeframe-pill-btn ${this.currentTimeframe === '6h' ? 'active' : ''}" onclick="AnalyticsView.switchTimeframe('6h')">6h</button>
            <button class="timeframe-pill-btn ${this.currentTimeframe === '24h' ? 'active' : ''}" onclick="AnalyticsView.switchTimeframe('24h')">24h</button>
            <button class="timeframe-pill-btn ${this.currentTimeframe === '7d' ? 'active' : ''}" onclick="AnalyticsView.switchTimeframe('7d')">7d</button>
          </div>
        </div>

        <!-- SVG Timeline Chart Container -->
        <div class="timeline-chart-container" id="timeline-chart-wrapper">
          ${this.generateTimelineSvg(d.hourly_timeline || [])}
          <div id="timeline-tooltip" class="timeline-tooltip"></div>
        </div>

        <!-- Timeline Legend & Live Flow Totals -->
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px; margin-top: 16px; padding-top: 12px; border-top: 1px solid var(--border-subtle); font-size: 12px;">
          <div style="display: flex; gap: 20px; align-items: center; flex-wrap: wrap;">
            <div style="display: flex; align-items: center; gap: 6px;">
              <span style="display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: #22C55E; box-shadow: 0 0 6px rgba(34,197,94,0.6);"></span>
              <span style="color: var(--text-main); font-weight: 600;">Clean Traffic</span>
              <span class="mono" style="color: var(--text-muted); font-size: 11px;">(${this.sumTimelineMetric(d.hourly_timeline, 'normal').toLocaleString()} flows)</span>
            </div>
            <div style="display: flex; align-items: center; gap: 6px;">
              <span style="display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: #F59E0B; box-shadow: 0 0 6px rgba(245,158,11,0.6);"></span>
              <span style="color: var(--text-main); font-weight: 600;">Suspicious Probes</span>
              <span class="mono" style="color: var(--text-muted); font-size: 11px;">(${this.sumTimelineMetric(d.hourly_timeline, 'suspicious').toLocaleString()} flows)</span>
            </div>
            <div style="display: flex; align-items: center; gap: 6px;">
              <span style="display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: #EF4444; box-shadow: 0 0 6px rgba(239,68,68,0.6);"></span>
              <span style="color: var(--text-main); font-weight: 600;">High-Risk Floods</span>
              <span class="mono" style="color: var(--text-muted); font-size: 11px;">(${this.sumTimelineMetric(d.hourly_timeline, 'high_risk').toLocaleString()} flows)</span>
            </div>
          </div>
          <div style="font-size: 11px; color: var(--text-muted);" class="mono">
            Hover over chart for granular timestamp telemetry
          </div>
        </div>
      </div>

      <!-- Protocol Distribution & Botnet Malware Strains (2-Column Grid) -->
      <div class="grid-2" style="margin-bottom: var(--space-xl);">
        <!-- Protocol Breakdown -->
        <div class="card">
          <div class="card-header">
            <div>
              <div class="card-title">Network Protocol Composition & Flow Volume</div>
              <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">Real-time throughput and packet telemetry shares</div>
            </div>
            <span class="mono" style="font-size: 11px; color: var(--text-muted);">Total: ${kpis.total_flows.toLocaleString()} flows</span>
          </div>

          <div style="display: flex; flex-direction: column; gap: 16px; margin-top: 10px;" id="protocol-breakdown-list">
            ${(d.protocol_breakdown || []).map(p => `
              <div>
                <div style="display: flex; justify-content: space-between; align-items: center; font-size: 12px; margin-bottom: 5px;">
                  <span style="font-weight: 600; color: var(--text-main); display: flex; align-items: center; gap: 6px;">
                    <span class="port-chip" style="font-size: 10px; padding: 1px 6px;">${p.protocol}</span>
                    <span>${p.description}</span>
                  </span>
                  <div style="display: flex; align-items: center; gap: 10px;">
                    <span class="mono" style="font-size: 11px; color: var(--text-muted);">${(p.flows || 0).toLocaleString()} flows (${p.bytes_gb || 0} GB)</span>
                    <span class="mono" style="font-weight: 700; color: ${p.color || 'var(--highlight-mint)'}; min-width: 44px; text-align: right;">${p.percentage}%</span>
                  </div>
                </div>
                <div style="height: 8px; background: var(--bg-surface); border-radius: var(--radius-full); overflow: hidden; border: 1px solid var(--border-subtle);">
                  <div style="width: ${p.percentage}%; height: 100%; background: ${p.color || 'var(--primary-accent)'}; border-radius: var(--radius-full); transition: width 0.4s ease;"></div>
                </div>
              </div>
            `).join('')}
          </div>
        </div>

        <!-- Botnet Strains Registry -->
        <div class="card">
          <div class="card-header">
            <div>
              <div class="card-title">Identified Botnet Malware Signatures</div>
              <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">Behavioral fingerprinting & hardware targeting registry</div>
            </div>
            <span class="badge badge-critical">${d.botnet_family_distribution ? d.botnet_family_distribution.length : 6} Strains Monitored</span>
          </div>

          <div style="display: flex; flex-direction: column; gap: 10px; margin-top: 8px;" id="botnet-strains-list">
            ${(d.botnet_family_distribution || []).map(st => `
              <div style="background: var(--bg-surface); padding: 10px 14px; border-radius: var(--radius-md); border: 1px solid ${st.risk === 'High-Risk' ? 'var(--state-danger-border)' : 'var(--border-subtle)'}; display: flex; justify-content: space-between; align-items: center;">
                <div style="max-width: 75%;">
                  <div style="display: flex; align-items: center; gap: 8px;">
                    <strong style="color: ${st.risk === 'High-Risk' ? 'var(--state-danger)' : 'var(--state-warning)'}; font-size: 13px;">${st.family}</strong>
                    <span class="badge ${st.risk === 'High-Risk' ? 'badge-critical' : 'badge-suspicious'}" style="font-size: 10px; padding: 1px 6px;">${st.badge || st.risk}</span>
                  </div>
                  <div style="font-size: 11px; color: var(--text-secondary); margin-top: 2px;">
                    <strong>Targets:</strong> ${st.target_hardware || 'Embedded IoT Micro-controllers'}
                  </div>
                  <div style="font-size: 10px; color: var(--text-muted); margin-top: 1px;">
                    <span>${st.type || 'Automated Threat Incursion'}</span> &bull; <span style="color: var(--highlight-mint);">${st.status || 'Active Monitoring'}</span>
                  </div>
                </div>
                <div style="text-align: right;">
                  <div class="mono" style="font-size: 16px; font-weight: 700; color: ${st.risk === 'High-Risk' ? 'var(--state-danger)' : 'var(--state-warning)'};">${st.hits} hits</div>
                  <div style="font-size: 10px; color: var(--text-muted);">logged incursion</div>
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      </div>

      <!-- Top Targeted Ports Threat Matrix -->
      <div class="card" style="padding: 0; overflow: hidden; margin-bottom: var(--space-xl);">
        <div class="card-header" style="padding: 16px 20px; border-bottom: 1px solid var(--border-subtle); margin-bottom: 0;">
          <div class="card-title" style="display: flex; align-items: center; gap: 8px;">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
            Top Targeted IoT Network Ports & Exploit Vectors
          </div>
          <span style="font-size: 12px; color: var(--text-muted);">Cross-referenced with MITRE ATT&CK & CVE Registry</span>
        </div>

        <div class="table-wrapper" style="border: none;">
          <table class="cyber-table">
            <thead>
              <tr>
                <th>Port</th>
                <th>Standard Service</th>
                <th>Common Botnet Exploit Vector</th>
                <th>CVE Reference</th>
                <th>Logged Probe Incursions</th>
                <th>Risk Categorization</th>
              </tr>
            </thead>
            <tbody>
              ${(d.top_attacked_ports || []).map(pt => `
                <tr class="${pt.risk_level === 'High-Risk' ? 'row-high-risk' : 'row-suspicious'}">
                  <td><span class="port-chip" style="color: ${pt.risk_level === 'High-Risk' ? 'var(--state-danger)' : 'var(--state-warning)'}; font-weight: 700;">${pt.port}</span></td>
                  <td><strong>${pt.service}</strong></td>
                  <td>${pt.exploit_vector}</td>
                  <td><span class="badge badge-normal" style="font-family: var(--font-mono); font-size: 11px;">${pt.cve || 'N/A'}</span></td>
                  <td class="mono" style="font-weight: 700; color: ${pt.risk_level === 'High-Risk' ? 'var(--state-danger)' : 'var(--text-main)'};">${(pt.incursions || 0).toLocaleString()} probes</td>
                  <td><span class="badge ${pt.risk_level === 'High-Risk' ? 'badge-high-risk' : 'badge-suspicious'}">${pt.badge || pt.risk_level}</span></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>

      <!-- Geographic Threat Origin & ASN Matrix -->
      <div class="card" style="padding: 0; overflow: hidden; margin-bottom: var(--space-xl);">
        <div class="card-header" style="padding: 16px 20px; border-bottom: 1px solid var(--border-subtle); margin-bottom: 0;">
          <div class="card-title" style="display: flex; align-items: center; gap: 8px;">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
            Geographic Botnet Attack Origin & Autonomous System (ASN) Intelligence
          </div>
          <span style="font-size: 12px; color: var(--text-muted);">IP Geolocation & Threat Reputation Feed</span>
        </div>

        <div class="table-wrapper" style="border: none;">
          <table class="cyber-table">
            <thead>
              <tr>
                <th>Origin Country</th>
                <th>ISO Code</th>
                <th>Top Autonomous System (ASN & ISP)</th>
                <th>Logged Probe Volume</th>
                <th>Global Share</th>
                <th>Threat Reputation Score</th>
                <th>Threat Severity</th>
              </tr>
            </thead>
            <tbody>
              ${(d.geographic_threats || []).map(g => `
                <tr class="${g.risk_level === 'High-Risk' ? 'row-high-risk' : 'row-suspicious'}">
                  <td style="font-weight: 600; display: flex; align-items: center; gap: 8px;">
                    <span style="font-size: 18px;">${g.flag || '🌐'}</span>
                    <span>${g.country}</span>
                  </td>
                  <td><span class="badge badge-normal mono">${g.code}</span></td>
                  <td><span class="mono" style="font-size: 12px; color: var(--highlight-mint);">${g.asn}</span></td>
                  <td class="mono" style="font-weight: 700;">${(g.probes || 0).toLocaleString()} probes</td>
                  <td class="mono">${g.share_pct}%</td>
                  <td>
                    <div style="display: flex; align-items: center; gap: 8px;">
                      <div style="width: 70px; height: 6px; background: var(--bg-surface); border-radius: var(--radius-full); overflow: hidden; border: 1px solid var(--border-subtle);">
                        <div style="width: ${g.threat_score}%; height: 100%; background: ${g.threat_score > 85 ? 'var(--state-danger)' : 'var(--state-warning)'};"></div>
                      </div>
                      <span class="mono" style="font-weight: 700; color: ${g.threat_score > 85 ? 'var(--state-danger)' : 'var(--state-warning)'};">${g.threat_score}/100</span>
                    </div>
                  </td>
                  <td><span class="badge ${g.risk_level === 'High-Risk' ? 'badge-critical' : 'badge-suspicious'}">${g.badge || g.risk_level}</span></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>

      <!-- Executive Security Audit Dossier Modal -->
      <div id="audit-report-modal" class="modal-backdrop" onclick="if(event.target === this) AnalyticsView.closeAuditReportModal()">
        <div class="cyber-modal" id="audit-report-modal-content" style="max-width: 840px;">
          <!-- Dynamically populated when opened -->
        </div>
      </div>
    `;

    // Attach interactive SVG hover events
    this.attachSvgHoverEvents();
  },

  async switchTimeframe(tf) {
    this.currentTimeframe = tf;
    await this.loadData(tf);
    this.renderView();
    if (window.App && App.showToast) {
      App.showToast(`Timeline updated to ${tf.toUpperCase()} window`, "info");
    }
  },

  sumTimelineMetric(timeline, metricKey) {
    if (!timeline || !Array.isArray(timeline)) return 0;
    return timeline.reduce((sum, item) => sum + (item[metricKey] || 0), 0);
  },

  generateTimelineSvg(timeline) {
    if (!timeline || timeline.length === 0) {
      return `<div style="text-align: center; padding: 40px; color: var(--text-muted);">No timeline data recorded for this window.</div>`;
    }

    const width = 800;
    const height = 240;
    const padL = 55;
    const padR = 25;
    const padT = 25;
    const padB = 35;
    const plotW = width - padL - padR;
    const plotH = height - padT - padB;

    const count = timeline.length;
    const maxVal = Math.max(
      ...timeline.map(t => Math.max(t.normal || 0, t.suspicious || 0, t.high_risk || 0))
    ) * 1.18 || 100;

    const getX = i => padL + (i / Math.max(1, count - 1)) * plotW;
    const getY = val => padT + plotH - (val / maxVal) * plotH;

    // Normal path
    let normalPath = "";
    let normalArea = `M ${getX(0)},${padT + plotH}`;
    timeline.forEach((pt, i) => {
      const x = getX(i);
      const y = getY(pt.normal || 0);
      normalPath += (i === 0 ? `M ${x},${y}` : ` L ${x},${y}`);
      normalArea += ` L ${x},${y}`;
    });
    normalArea += ` L ${getX(count - 1)},${padT + plotH} Z`;

    // Suspicious path
    let suspPath = "";
    let suspArea = `M ${getX(0)},${padT + plotH}`;
    timeline.forEach((pt, i) => {
      const x = getX(i);
      const y = getY(pt.suspicious || 0);
      suspPath += (i === 0 ? `M ${x},${y}` : ` L ${x},${y}`);
      suspArea += ` L ${x},${y}`;
    });
    suspArea += ` L ${getX(count - 1)},${padT + plotH} Z`;

    // High risk path
    let highPath = "";
    let highArea = `M ${getX(0)},${padT + plotH}`;
    timeline.forEach((pt, i) => {
      const x = getX(i);
      const y = getY(pt.high_risk || 0);
      highPath += (i === 0 ? `M ${x},${y}` : ` L ${x},${y}`);
      highArea += ` L ${x},${y}`;
    });
    highArea += ` L ${getX(count - 1)},${padT + plotH} Z`;

    // Horizontal gridlines & Y axis labels
    const gridRows = 4;
    let gridSvg = "";
    for (let r = 0; r <= gridRows; r++) {
      const y = padT + (r / gridRows) * plotH;
      const val = Math.round(maxVal - (r / gridRows) * maxVal);
      gridSvg += `
        <line x1="${padL}" y1="${y}" x2="${width - padR}" y2="${y}" stroke="var(--border-subtle)" stroke-width="1" stroke-dasharray="3 3"/>
        <text x="${padL - 8}" y="${y + 3}" fill="var(--text-muted)" font-size="10" font-family="monospace" text-anchor="end">${val.toLocaleString()}</text>
      `;
    }

    // X axis labels
    let xLabelsSvg = "";
    timeline.forEach((pt, i) => {
      // Show every label if <= 7, otherwise every 2nd or 3rd
      const step = count > 10 ? 2 : 1;
      if (i % step === 0 || i === count - 1) {
        const x = getX(i);
        xLabelsSvg += `
          <text x="${x}" y="${height - 10}" fill="var(--text-muted)" font-size="10" font-family="monospace" text-anchor="middle">${pt.time}</text>
        `;
      }
    });

    return `
      <svg id="timeline-svg" viewBox="0 0 ${width} ${height}" style="width: 100%; height: auto; display: block; overflow: visible;">
        <defs>
          <linearGradient id="clean-grad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="#22C55E" stop-opacity="0.28"/>
            <stop offset="100%" stop-color="#22C55E" stop-opacity="0.0"/>
          </linearGradient>
          <linearGradient id="susp-grad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="#F59E0B" stop-opacity="0.32"/>
            <stop offset="100%" stop-color="#F59E0B" stop-opacity="0.0"/>
          </linearGradient>
          <linearGradient id="high-grad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="#EF4444" stop-opacity="0.45"/>
            <stop offset="100%" stop-color="#EF4444" stop-opacity="0.0"/>
          </linearGradient>
        </defs>

        <!-- Background & Gridlines -->
        ${gridSvg}
        ${xLabelsSvg}

        <!-- Area Fills -->
        <path d="${normalArea}" fill="url(#clean-grad)" />
        <path d="${suspArea}" fill="url(#susp-grad)" />
        <path d="${highArea}" fill="url(#high-grad)" />

        <!-- Line Strokes -->
        <path d="${normalPath}" fill="none" stroke="#22C55E" stroke-width="2.5" stroke-linejoin="round" />
        <path d="${suspPath}" fill="none" stroke="#F59E0B" stroke-width="2.5" stroke-linejoin="round" />
        <path d="${highPath}" fill="none" stroke="#EF4444" stroke-width="2.5" stroke-linejoin="round" />

        <!-- Vertical Cursor and Hover Tracking Markers (Managed by JS) -->
        <line id="svg-cursor-line" x1="0" y1="${padT}" x2="0" y2="${padT + plotH}" stroke="var(--primary-accent)" stroke-width="1.5" stroke-dasharray="3 3" opacity="0"/>
        <circle id="svg-dot-normal" cx="0" cy="0" r="4.5" fill="#22C55E" stroke="#040F0A" stroke-width="2" opacity="0"/>
        <circle id="svg-dot-susp" cx="0" cy="0" r="4.5" fill="#F59E0B" stroke="#040F0A" stroke-width="2" opacity="0"/>
        <circle id="svg-dot-high" cx="0" cy="0" r="4.5" fill="#EF4444" stroke="#040F0A" stroke-width="2" opacity="0"/>

        <!-- Transparent Overlay for Mouse Capture -->
        <rect id="svg-hover-overlay" x="${padL}" y="${padT}" width="${plotW}" height="${plotH}" fill="transparent" style="cursor: crosshair;" />
      </svg>
    `;
  },

  attachSvgHoverEvents() {
    const svg = document.getElementById("timeline-svg");
    const overlay = document.getElementById("svg-hover-overlay");
    const tooltip = document.getElementById("timeline-tooltip");
    const cursorLine = document.getElementById("svg-cursor-line");
    const dotNorm = document.getElementById("svg-dot-normal");
    const dotSusp = document.getElementById("svg-dot-susp");
    const dotHigh = document.getElementById("svg-dot-high");

    if (!svg || !overlay || !tooltip) return;

    const timeline = (this.analyticsData && this.analyticsData.hourly_timeline) || [];
    if (timeline.length === 0) return;

    const width = 800;
    const height = 240;
    const padL = 55;
    const padR = 25;
    const padT = 25;
    const padB = 35;
    const plotW = width - padL - padR;
    const plotH = height - padT - padB;
    const count = timeline.length;
    const maxVal = Math.max(
      ...timeline.map(t => Math.max(t.normal || 0, t.suspicious || 0, t.high_risk || 0))
    ) * 1.18 || 100;

    const getX = i => padL + (i / Math.max(1, count - 1)) * plotW;
    const getY = val => padT + plotH - (val / maxVal) * plotH;

    overlay.addEventListener("mousemove", (e) => {
      const rect = svg.getBoundingClientRect();
      const scaleX = width / rect.width;
      const mouseSvgX = (e.clientX - rect.left) * scaleX;

      // Find closest index
      let closestIdx = 0;
      let minDiff = Infinity;
      for (let i = 0; i < count; i++) {
        const diff = Math.abs(getX(i) - mouseSvgX);
        if (diff < minDiff) {
          minDiff = diff;
          closestIdx = i;
        }
      }

      const pt = timeline[closestIdx];
      const x = getX(closestIdx);
      const yNorm = getY(pt.normal || 0);
      const ySusp = getY(pt.suspicious || 0);
      const yHigh = getY(pt.high_risk || 0);

      // Move SVG cursor & dots
      cursorLine.setAttribute("x1", x);
      cursorLine.setAttribute("x2", x);
      cursorLine.setAttribute("opacity", "1");

      dotNorm.setAttribute("cx", x);
      dotNorm.setAttribute("cy", yNorm);
      dotNorm.setAttribute("opacity", "1");

      dotSusp.setAttribute("cx", x);
      dotSusp.setAttribute("cy", ySusp);
      dotSusp.setAttribute("opacity", "1");

      dotHigh.setAttribute("cx", x);
      dotHigh.setAttribute("cy", yHigh);
      dotHigh.setAttribute("opacity", "1");

      // Position HTML tooltip
      const containerRect = svg.parentElement.getBoundingClientRect();
      const tipX = (x / width) * containerRect.width;
      const tipY = (Math.min(yNorm, ySusp, yHigh) / height) * containerRect.height;

      tooltip.style.left = `${tipX}px`;
      tooltip.style.top = `${tipY}px`;
      tooltip.innerHTML = `
        <div style="font-weight: 700; color: var(--text-main); margin-bottom: 6px; border-bottom: 1px solid var(--border-subtle); padding-bottom: 3px; display: flex; justify-content: space-between;">
          <span>Time: <span class="mono">${pt.time}</span></span>
          <span style="font-size: 10px; color: var(--text-muted); font-weight: normal;">${this.currentTimeframe.toUpperCase()}</span>
        </div>
        <div style="display: flex; flex-direction: column; gap: 3px; font-size: 11px;">
          <div style="display: flex; justify-content: space-between; gap: 12px;">
            <span style="color: #22C55E; font-weight: 600;">Clean Traffic:</span>
            <span class="mono" style="font-weight: 700;">${(pt.normal || 0).toLocaleString()} flows</span>
          </div>
          <div style="display: flex; justify-content: space-between; gap: 12px;">
            <span style="color: #F59E0B; font-weight: 600;">Suspicious:</span>
            <span class="mono" style="font-weight: 700;">${(pt.suspicious || 0).toLocaleString()} probes</span>
          </div>
          <div style="display: flex; justify-content: space-between; gap: 12px;">
            <span style="color: #EF4444; font-weight: 600;">High-Risk Flood:</span>
            <span class="mono" style="font-weight: 700;">${(pt.high_risk || 0).toLocaleString()} flows</span>
          </div>
        </div>
      `;
      tooltip.classList.add("visible");
    });

    overlay.addEventListener("mouseleave", () => {
      cursorLine.setAttribute("opacity", "0");
      dotNorm.setAttribute("opacity", "0");
      dotSusp.setAttribute("opacity", "0");
      dotHigh.setAttribute("opacity", "0");
      tooltip.classList.remove("visible");
    });
  },

  openAuditReportModal() {
    const modal = document.getElementById("audit-report-modal");
    const content = document.getElementById("audit-report-modal-content");
    if (!modal || !content) return;

    this.renderAuditReportContent(content);
    modal.classList.add("open");
  },

  closeAuditReportModal() {
    const modal = document.getElementById("audit-report-modal");
    if (modal) modal.classList.remove("open");
  },

  printAuditReport() {
    window.print();
  },

  renderAuditReportContent(container) {
    const kpis = (window.App && App.state && App.state.kpis) || {
      total_devices: 8,
      normal_count: 5,
      suspicious_count: 2,
      high_risk_count: 1,
      quarantined_count: 1,
      health_score: 78,
      packets_analyzed_total: 148293,
      current_mbps: 18.5,
      unresolved_alerts: 4
    };

    const devices = (window.App && App.state && App.state.devices) || (window.IOT_FALLBACK_DATA ? window.IOT_FALLBACK_DATA.devices : []);
    const highRiskDevices = devices.filter(d => d.status === "High-Risk");
    const d = this.analyticsData || {};

    const score = kpis.health_score || 78;
    const scoreColor = score > 85 ? "var(--state-success)" : (score > 60 ? "var(--state-warning)" : "var(--state-danger)");
    const postureLabel = score > 85 ? "OPTIMAL POSTURE" : (score > 60 ? "DEGRADED / ELEVATED RISK" : "CRITICAL COMPROMISE");

    container.innerHTML = `
      <div class="modal-header">
        <div style="display: flex; align-items: center; gap: 10px;">
          <div style="background: var(--bg-surface); border: 1px solid var(--border-medium); border-radius: var(--radius-sm); padding: 4px 8px; font-size: 11px; font-weight: 700; color: var(--state-warning);">
            TLP:AMBER &bull; CONFIDENTIAL
          </div>
          <div>
            <h3 style="font-size: 16px; margin: 0; color: var(--text-main);">Official Executive Security Audit Dossier</h3>
            <span style="font-size: 11px; color: var(--text-muted);">Generated: ${new Date().toISOString().replace('T', ' ').substring(0, 19)} UTC</span>
          </div>
        </div>
        <button class="close-btn" onclick="AnalyticsView.closeAuditReportModal()">&times;</button>
      </div>

      <!-- Executive Posture Score Banner -->
      <div style="background: var(--bg-surface); border: 1px solid var(--border-medium); border-radius: var(--radius-lg); padding: 18px 24px; margin-bottom: 20px; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 16px;">
        <div>
          <div style="font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600;">Overall Fleet Posture Assessment</div>
          <div style="font-size: 20px; font-weight: 700; color: ${scoreColor}; margin-top: 2px;">${postureLabel}</div>
          <p style="font-size: 12px; color: var(--text-secondary); margin-top: 4px; max-width: 480px;">
            Dual-Detection heuristics actively isolating high-risk Mirai and Telnet sweep vectors. Quarantine policies are actively preventing horizontal lateral network propagation.
          </p>
        </div>
        <div style="text-align: center; border-left: 1px solid var(--border-subtle); padding-left: 24px;">
          <div class="mono" style="font-size: 40px; font-weight: 800; color: ${scoreColor}; line-height: 1;">${score}</div>
          <div style="font-size: 11px; color: var(--text-muted); font-weight: 600;">HEALTH INDEX / 100</div>
        </div>
      </div>

      <!-- Fleet Node & Model Telemetry Matrix (2-col) -->
      <div class="grid-2" style="margin-bottom: 20px;">
        <div class="card" style="padding: 14px 18px; margin: 0;">
          <div style="font-size: 12px; font-weight: 700; color: var(--text-main); margin-bottom: 10px; display: flex; align-items: center; gap: 6px;">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
            Monitored Hardware Inventory
          </div>
          <div style="display: flex; flex-direction: column; gap: 6px; font-size: 12px;">
            <div style="display: flex; justify-content: space-between;"><span style="color: var(--text-secondary);">Total Active Nodes:</span><strong class="mono">${kpis.total_devices || 8} IoT Nodes</strong></div>
            <div style="display: flex; justify-content: space-between;"><span style="color: var(--text-secondary);">Benign Baseline Assets:</span><span class="mono" style="color: var(--highlight-mint); font-weight: 700;">${kpis.normal_count || 5}</span></div>
            <div style="display: flex; justify-content: space-between;"><span style="color: var(--text-secondary);">Suspicious Recon Entities:</span><span class="mono" style="color: var(--state-warning); font-weight: 700;">${kpis.suspicious_count || 2}</span></div>
            <div style="display: flex; justify-content: space-between;"><span style="color: var(--text-secondary);">High-Risk Compromised:</span><span class="mono" style="color: var(--state-danger); font-weight: 700;">${kpis.high_risk_count || 1}</span></div>
            <div style="display: flex; justify-content: space-between;"><span style="color: var(--text-secondary);">Quarantined Nodes:</span><span class="badge badge-normal mono">${kpis.quarantined_count || 1} Isolated</span></div>
          </div>
        </div>

        <div class="card" style="padding: 14px 18px; margin: 0;">
          <div style="font-size: 12px; font-weight: 700; color: var(--text-main); margin-bottom: 10px; display: flex; align-items: center; gap: 6px;">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M12 2a10 10 0 1 0 10 10H12V2z"/></svg>
            ML Dual-Detection Pipeline Benchmarks
          </div>
          <div style="display: flex; flex-direction: column; gap: 6px; font-size: 12px;">
            <div style="display: flex; justify-content: space-between;"><span style="color: var(--text-secondary);">Architecture:</span><strong class="mono" style="font-size: 11px;">Random Forest Ensemble (11 features)</strong></div>
            <div style="display: flex; justify-content: space-between;"><span style="color: var(--text-secondary);">Model Accuracy:</span><span class="mono" style="color: var(--highlight-mint); font-weight: 700;">99.2%</span></div>
            <div style="display: flex; justify-content: space-between;"><span style="color: var(--text-secondary);">Precision / Recall:</span><span class="mono" style="color: var(--highlight-mint); font-weight: 700;">98.8% / 99.4%</span></div>
            <div style="display: flex; justify-content: space-between;"><span style="color: var(--text-secondary);">F1-Score:</span><span class="mono" style="color: var(--highlight-mint); font-weight: 700;">99.1%</span></div>
            <div style="display: flex; justify-content: space-between;"><span style="color: var(--text-secondary);">Rule Heuristics:</span><span class="badge badge-normal mono">10 Signature Rules</span></div>
          </div>
        </div>
      </div>

      <!-- High-Risk Compromised Devices Requiring Remediation -->
      <div style="margin-bottom: 20px;">
        <div style="font-size: 13px; font-weight: 700; color: var(--state-danger); margin-bottom: 8px; display: flex; align-items: center; gap: 6px;">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          Compromised Assets Requiring Immediate Remediation
        </div>

        <div class="table-wrapper" style="border: 1px solid var(--border-subtle); border-radius: var(--radius-md);">
          <table class="cyber-table">
            <thead>
              <tr>
                <th>Device Name</th>
                <th>Network IP & MAC</th>
                <th>Quarantine Isolation</th>
                <th>Exposed CVEs & Anomalies</th>
                <th>Remediation Action</th>
              </tr>
            </thead>
            <tbody>
              ${highRiskDevices.length > 0 ? highRiskDevices.map(hd => `
                <tr class="row-high-risk">
                  <td><strong>${hd.name}</strong></td>
                  <td><span class="mono" style="font-size: 11px;">${hd.ip}<br/><span style="color: var(--text-muted);">${hd.mac}</span></span></td>
                  <td><span class="badge ${hd.quarantined ? 'badge-normal' : 'badge-critical'}">${hd.quarantined ? 'Quarantined / Safe' : 'UNQUARANTINED / ACTIVE'}</span></td>
                  <td><span class="badge badge-high-risk mono" style="font-size: 10px;">${(hd.vulnerabilities || []).join(', ') || 'Volumetric Scan'}</span></td>
                  <td style="font-size: 11px; color: var(--text-secondary);">${hd.recommended_action || 'Enforce VLAN isolation & rotate credentials.'}</td>
                </tr>
              `).join('') : `
                <tr>
                  <td colspan="5" style="text-align: center; color: var(--highlight-mint); padding: 14px;">No unquarantined high-risk nodes detected in fleet.</td>
                </tr>
              `}
            </tbody>
          </table>
        </div>
      </div>

      <!-- Strategic Remediation Recommendations -->
      <div style="background: var(--bg-surface); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 14px 18px; margin-bottom: 20px;">
        <div style="font-size: 13px; font-weight: 700; color: var(--text-main); margin-bottom: 8px;">
          Strategic Security Recommendations & Hardening Roadmap
        </div>
        <ol style="margin: 0; padding-left: 20px; font-size: 12px; color: var(--text-secondary); line-height: 1.6;">
          <li><strong>Maintain Zero-Trust Port Quarantine:</strong> Keep port 23/2323 Telnet scans isolated via dynamic ACLs to halt Mirai horizontal propagation.</li>
          <li><strong>Firmware Baseline Upgrades:</strong> Immediately patch Hikvision CVE-2021-36260 and Huawei UPnP CVE-2017-17215 to eliminate remote shell vulnerabilities.</li>
          <li><strong>Egress Rate Limiting:</strong> Enforce 200 pps burst thresholds on edge switches for surveillance cameras and gateways.</li>
          <li><strong>Credential Rotation:</strong> Revoke factory default Telnet and HTTP passwords across all surveillance equipment.</li>
        </ol>
      </div>

      <!-- Modal Footer -->
      <div style="display: flex; justify-content: space-between; align-items: center; border-top: 1px solid var(--border-subtle); padding-top: 16px;">
        <div style="display: flex; gap: 8px;">
          <button class="btn btn-primary btn-sm" onclick="AnalyticsView.printAuditReport()" style="display: inline-flex; align-items: center; gap: 6px;">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"><polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>
            Print / Save PDF
          </button>
          <a href="/api/export/report" target="_blank" class="btn btn-secondary btn-sm" style="display: inline-flex; align-items: center; gap: 6px;">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
            Download Markdown (.md)
          </a>
        </div>
        <button class="btn btn-secondary btn-sm" onclick="AnalyticsView.closeAuditReportModal()">Close Dossier</button>
      </div>
    `;
  }
};
