/**
 * NETGUARD IoT Cybersecurity — Centralized API Client
 * Enterprise REST client with token auth, loading states, error handling, and offline resilience.
 */

(function (window) {
  "use strict";

  class NetGuardApiClient {
    constructor() {
      this.baseUrl = "";
      this.tokenKey = "netguard_jwt_token";
      this.apiKey = "netguard-sensor-key-2026";
      this.activeRequests = 0;
      this.listeners = new Set();
    }

    /**
     * Subscribe to API client network state changes (loading, online/offline)
     */
    onStateChange(callback) {
      this.listeners.add(callback);
      return () => this.listeners.delete(callback);
    }

    _notify(state) {
      this.listeners.forEach((fn) => {
        try { fn(state); } catch (e) { console.error(e); }
      });
    }

    getToken() {
      try {
        return localStorage.getItem(this.tokenKey);
      } catch (e) {
        return null;
      }
    }

    setToken(token) {
      try {
        if (token) {
          localStorage.setItem(this.tokenKey, token);
        } else {
          localStorage.removeItem(this.tokenKey);
        }
      } catch (e) {}
    }

    /**
     * Core Fetch wrapper with timeout, token injection, and structured error handling
     */
    async request(endpoint, options = {}) {
      this.activeRequests++;
      this._notify({ loading: true, activeCount: this.activeRequests });

      const url = `${this.baseUrl}${endpoint}`;
      const headers = {
        "Accept": "application/json",
        ...options.headers,
      };

      // Add auth token if present
      const token = this.getToken();
      if (token && !headers["Authorization"]) {
        headers["Authorization"] = `Bearer ${token}`;
      }

      // Add default sensor API key for traffic ingestion if missing
      if (endpoint.startsWith("/api/traffic/events") && !headers["X-API-Key"] && !headers["Authorization"]) {
        headers["X-API-Key"] = this.apiKey;
      }

      if (options.body && typeof options.body === "object" && !(options.body instanceof FormData)) {
        headers["Content-Type"] = "application/json";
        options.body = JSON.stringify(options.body);
      }

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), options.timeout || 15000);

      try {
        const response = await fetch(url, {
          ...options,
          headers,
          signal: controller.signal,
        });

        clearTimeout(timeoutId);

        // Check if response is raw file export
        const contentType = response.headers.get("Content-Type") || "";
        if (contentType.includes("text/markdown") || contentType.includes("text/csv")) {
          return await response.text();
        }

        let json;
        try {
          json = await response.json();
        } catch (e) {
          json = { success: response.ok, rawText: await response.text().catch(() => "") };
        }

        if (!response.ok) {
          const errMsg = (json && (json.message || (json.error && json.error.message))) || `HTTP Error ${response.status}`;
          const err = new Error(errMsg);
          err.status = response.status;
          err.code = (json && (json.error_code || (json.error && json.error.code))) || `HTTP_${response.status}`;
          err.data = json;

          if (response.status === 401) {
            console.warn("[ApiClient] Unauthorized request (401). Invalid or expired token.");
          }

          throw err;
        }

        return json;
      } catch (err) {
        if (err.name === "AbortError") {
          const timeoutErr = new Error(`Request timed out for ${endpoint}`);
          timeoutErr.status = 408;
          throw timeoutErr;
        }
        throw err;
      } finally {
        this.activeRequests = Math.max(0, this.activeRequests - 1);
        this._notify({ loading: this.activeRequests > 0, activeCount: this.activeRequests });
      }
    }

    // =========================================================================
    // 1. DASHBOARD
    // =========================================================================
    dashboard = {
      getSummary: () => this.request("/api/dashboard/summary"),
      getTraffic: () => this.request("/api/dashboard/traffic"),
      getRiskDistribution: () => this.request("/api/dashboard/risk-distribution"),
      getAlertTrends: () => this.request("/api/dashboard/alert-trends"),
      getTopRiskDevices: (limit = 5) => this.request(`/api/dashboard/top-risk-devices?limit=${limit}`),
    };

    // =========================================================================
    // 2. DEVICES
    // =========================================================================
    devices = {
      list: (params = {}) => {
        const q = new URLSearchParams();
        if (params.page) q.set("page", params.page);
        if (params.limit) q.set("limit", params.limit);
        if (params.search) q.set("search", params.search);
        if (params.risk_level) q.set("risk_level", params.risk_level);
        if (params.protocol) q.set("protocol", params.protocol);
        if (params.device_type) q.set("device_type", params.device_type);
        if (params.sort_by) q.set("sort_by", params.sort_by);
        if (params.sort_order) q.set("sort_order", params.sort_order);
        const qs = q.toString();
        return this.request(`/api/devices${qs ? `?${qs}` : ""}`);
      },
      get: (id) => this.request(`/api/devices/${encodeURIComponent(id)}`),
      getTraffic: (id, params = {}) => {
        const q = new URLSearchParams(params).toString();
        return this.request(`/api/devices/${encodeURIComponent(id)}/traffic${q ? `?${q}` : ""}`);
      },
      getAlerts: (id) => this.request(`/api/devices/${encodeURIComponent(id)}/alerts`),
      create: (deviceData) => this.request("/api/devices", { method: "POST", body: deviceData }),
      update: (id, updates) => this.request(`/api/devices/${encodeURIComponent(id)}`, { method: "PATCH", body: updates }),
      delete: (id, force = false) => this.request(`/api/devices/${encodeURIComponent(id)}?force=${force}`, { method: "DELETE" }),
      quarantine: (id, quarantined) => this.request("/api/devices/quarantine", {
        method: "POST",
        body: { device_id: id, quarantined: Boolean(quarantined) }
      }),
      getRiskConfig: () => this.request("/api/risk/config"),
      updateRiskConfig: (config) => this.request("/api/risk/config", { method: "POST", body: config }),
    };

    // =========================================================================
    // 3. TRAFFIC
    // =========================================================================
    traffic = {
      getEvents: (params = {}) => {
        const q = new URLSearchParams(params).toString();
        return this.request(`/api/traffic/events${q ? `?${q}` : ""}`);
      },
      getStats: () => this.request("/api/traffic/stats"),
      getProtocols: () => this.request("/api/traffic/protocols"),
      getRecentFlows: (limit = 50) => this.request(`/api/traffic?limit=${limit}`),
      tickStream: (scenario) => {
        const qs = scenario ? `?scenario=${encodeURIComponent(scenario)}` : "";
        return this.request(`/api/traffic/tick${qs}`);
      },
      ingestEvent: (eventData) => this.request("/api/traffic/events", { method: "POST", body: eventData }),
      ingestBatch: (batchData) => this.request("/api/traffic/events/batch", { method: "POST", body: batchData }),
      triggerAttack: (scenario) => this.request("/api/simulation/attack", {
        method: "POST",
        body: { scenario }
      }),
    };

    // =========================================================================
    // 4. DETECTION & CONFIGURABLE RULES
    // =========================================================================
    detection = {
      analyze: (payload) => this.request("/api/detection/analyze", { method: "POST", body: payload }),
      getResults: (params = {}) => {
        const q = new URLSearchParams(params).toString();
        return this.request(`/api/detection/results${q ? `?${q}` : ""}`);
      },
      getResult: (id) => this.request(`/api/detection/results/${encodeURIComponent(id)}`),
      getStatus: () => this.request("/api/detection/status"),
      getRules: () => this.request("/api/detection/rules"),
      updateRule: (ruleId, updates) => this.request(`/api/detection/rules/${encodeURIComponent(ruleId)}`, {
        method: "PATCH",
        body: updates
      }),
    };

    // =========================================================================
    // 4B. REPRODUCIBLE DEMO SCENARIOS
    // =========================================================================
    demo = {
      listScenarios: () => this.request("/api/demo/scenarios"),
      runScenario: (scenario, deviceId = null) => this.request("/api/demo/scenario", {
        method: "POST",
        body: { scenario, device_id: deviceId }
      }),
    };

    // =========================================================================
    // 4C. REAL-TIME SERVER-SENT EVENTS (SSE) STREAM
    // =========================================================================
    stream = {
      connect: (onEvent, onError) => {
        const token = this.getToken() || "demo-token";
        const url = `${this.baseUrl}/api/stream/events?token=${encodeURIComponent(token)}`;
        const es = new EventSource(url);

        es.addEventListener("connected", (e) => {
          try { onEvent("connected", JSON.parse(e.data)); } catch (err) { onEvent("connected", e.data); }
        });
        es.addEventListener("traffic_aggregate", (e) => {
          try { onEvent("traffic_aggregate", JSON.parse(e.data)); } catch (err) { onEvent("traffic_aggregate", e.data); }
        });
        es.addEventListener("detection", (e) => {
          try { onEvent("detection", JSON.parse(e.data)); } catch (err) { onEvent("detection", e.data); }
        });
        es.addEventListener("risk_change", (e) => {
          try { onEvent("risk_change", JSON.parse(e.data)); } catch (err) { onEvent("risk_change", e.data); }
        });
        es.addEventListener("alert", (e) => {
          try { onEvent("alert", JSON.parse(e.data)); } catch (err) { onEvent("alert", e.data); }
        });
        es.addEventListener("incident_status", (e) => {
          try { onEvent("incident_status", JSON.parse(e.data)); } catch (err) { onEvent("incident_status", e.data); }
        });

        es.onerror = (err) => {
          if (onError) onError(err);
        };

        return {
          close: () => es.close()
        };
      }
    };

    // =========================================================================
    // 5. ALERTS
    // =========================================================================
    alerts = {
      list: (params = {}) => {
        const q = new URLSearchParams(params).toString();
        return this.request(`/api/alerts${q ? `?${q}` : ""}`);
      },
      get: (id) => this.request(`/api/alerts/${encodeURIComponent(id)}`),
      updateStatus: (id, status, reason = "") => this.request(`/api/alerts/${encodeURIComponent(id)}/status`, {
        method: "PATCH",
        body: { status, reason }
      }),
      acknowledge: (id, analyst = "SecOps Analyst", note = "") => this.request(`/api/alerts/${encodeURIComponent(id)}/acknowledge`, {
        method: "PATCH",
        body: { analyst, note }
      }),
      getUnreadCount: () => this.request("/api/alerts/unread-count"),
      addNote: (id, note, author = "SecOps Analyst") => this.request("/api/alerts/note", {
        method: "POST",
        body: { alert_id: id, note, author }
      }),
      bulkAction: (ids, action) => this.request("/api/alerts/bulk", {
        method: "POST",
        body: { alert_ids: ids, action }
      }),
    };

    // =========================================================================
    // 6. ANALYTICS
    // =========================================================================
    analytics = {
      getTraffic: () => this.request("/api/analytics/traffic"),
      getDevices: () => this.request("/api/analytics/devices"),
      getThreats: () => this.request("/api/analytics/threats"),
      getIncidents: () => this.request("/api/analytics/incidents"),
      getSummary: (timeframe = "24h") => this.request(`/api/analytics?timeframe=${encodeURIComponent(timeframe)}`),
    };

    // =========================================================================
    // 7. HEALTH
    // =========================================================================
    health = {
      get: () => this.request("/api/health"),
      getDatabase: () => this.request("/api/health/database"),
      getKPIs: () => this.request("/api/kpi"),
    };

    // =========================================================================
    // 8. ML & AUTH
    // =========================================================================
    ml = {
      getModel: () => this.request("/api/ml/model"),
      getStatus: () => this.request("/api/ml/status"),
      getFeatures: () => this.request("/api/ml/features"),
      getEvaluation: () => this.request("/api/ml/evaluation"),
      retrain: (params = {}) => this.request("/api/ml/retrain", { method: "POST", body: params }),
      predict: (features) => this.request("/api/ml/predict", { method: "POST", body: { features } }),
      predictFlow: (flow) => this.request("/api/ml/predict", { method: "POST", body: { flow } }),
    };

    auth = {
      login: async (username, password) => {
        const res = await this.request("/api/auth/login", {
          method: "POST",
          body: { username, password }
        });
        if (res.token) {
          this.setToken(res.token);
        }
        return res;
      },
      me: () => this.request("/api/auth/me"),
      logout: () => this.setToken(null),
    };
  }

  // Attach global singleton
  window.ApiClient = new NetGuardApiClient();
})(window);
