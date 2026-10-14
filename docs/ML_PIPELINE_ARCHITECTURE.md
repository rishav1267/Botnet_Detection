# Machine Learning Pipeline Architecture & Engineering Specification

## 1. Executive Overview
The **NETGUARD IoT Botnet Detection ML Pipeline** provides continuous, real-time telemetry classification for connected IoT devices. It employs a supervised ensemble model (**Random Forest Classifier**) combined with an 11-dimensional feature extractor to distinguish between **Normal IoT Profiles**, **Suspicious Anomalies**, and **High-Risk Botnet Incursions** (such as Mirai, Torii, Gafgyt/Bashlite, and volumetric DoS/DDoS attacks).

---

## 2. Feature Schema & Engineering Decisions

The pipeline extracts an 11-dimensional numerical feature vector per network flow:

| # | Feature Name | Category | Unit | Transform / Formula | Operational Rationale |
|---|---|---|---|---|---|
| 1 | `packet_rate` | Volume | pps | Total Packets / Flow Duration | High packet velocity distinguishes flood attacks from sensor telemetry. |
| 2 | `byte_rate` | Volume | B/s | Total Bytes / Flow Duration | Bandwidth consumption and exfiltration spike detection. |
| 3 | `conn_freq` | Timing | conn/10s | Handshakes in 10-second rolling window | Detects high-frequency brute-force sweeps (e.g. Telnet/SSH). |
| 4 | `dest_port_norm` | Protocol | norm | `dest_port / 65535.0` | Normalizes 16-bit port space into $[0.0, 1.0]$ range for tree splits. |
| 5 | `unique_dest_ips` | Recon | IPs | Distinct destination IPs contacted | High target dispersion indicates horizontal network scanning. |
| 6 | `syn_ratio` | Protocol | ratio | SYN flags / Total packets | Elevated SYN ratio ($>0.70$) without completions flags SYN flood attacks. |
| 7 | `flow_duration` | Timing | seconds | Flow End Time - Flow Start Time | Ephemeral rapid-fire flows vs. persistent stateful streams. |
| 8 | `payload_entropy` | Payload | bits/byte | Shannon Entropy: $-\sum p(x) \log_2 p(x)$ | Encrypted C2 communications or packed payloads exhibit entropy $>7.0$. |
| 9 | `fwd_packets` | Direction | pkts | Client $\rightarrow$ Target packet count | Forward unidirectional burst identification. |
| 10 | `bwd_packets` | Direction | pkts | Target $\rightarrow$ Client response packet count | Asymmetry indicator ($fwd \gg bwd$ indicates unanswered attacks). |
| 11 | `mean_pkt_len` | Payload | bytes | Total Bytes / Total Packets | Micro-packets ($<64$ bytes) characterize ACK/SYN floods. |

---

## 3. Preprocessing & Normalization Strategy
* **Feature Schema Parity**: Both simulated training flows (modeled on IoT-23 and N-BaIoT benchmarks) and external NetFlow/Zeek probes execute the exact same `extract_vector()` transformation.
* **Deterministic Scaling**: MinMax normalization is used for bounded dimensions (ports, flag ratios, entropy) to preserve exact boundary behaviors without skewing standard deviations.
* **Missing Value Imputation**: Default fallback baselines are provided for partial packet flows (e.g. default HTTP port 80, benign entropy baseline 4.2).

---

## 4. Model Architecture & Hyperparameter Selection
* **Classifier**: `RandomForestClassifier` (Scikit-Learn).
* **Ensemble Strategy**: Bootstrap aggregation with balanced class weighting (`class_weight="balanced"`).
* **Configurable Hyperparameters**:
  * `n_estimators`: Default 45 (range 10 to 100). Balances inference speed ($<1$ ms) and decision tree variance reduction.
  * `max_depth`: Default 9 (range 3 to 20). Prevents overfitting on synthetic data while capturing non-linear feature interactions.
  * `test_split_pct`: Default 25% (stratified test holdout).
* **Dual-Tier Heuristic Fallback**: In non-Python or non-scikit environments, a deterministic multi-factor scoring function (`_heuristic_fallback`) guarantees uninterrupted classification with zero downtime.

---

## 5. Model Evaluation Metrics
* **Accuracy**: Weighted multi-class test accuracy ($>99.0\%$).
* **Precision & Recall**: Evaluated per class to maintain low false positive rates ($<1\%$) while achieving near-zero false negatives for critical incursions.
* **ROC & PR Curves**: Real-time 15-point sampled curve interpolation providing smooth SVG visual representations in the Security Operations Center dashboard.
* **Multi-Class Confusion Matrix**: 3-class matrix mapping predictions across Normal, Suspicious, and High-Risk.

---

## 6. Operational Trade-Offs & Known Limitations
1. **Payload Encryption (TLS/QUIC)**: Deep packet payload inspection cannot inspect application plaintext over HTTPS/TLS; the pipeline compensates by relying heavily on volumetric, directional, and timing features.
2. **Concept Drift & Zero-Day Botnets**: Botnets that intentionally throttle their connection cadence to emulate human sensor behavior may score as "Suspicious" rather than "High-Risk".
3. **Synthetic Demonstration Mode**: All simulated data is clearly badged in the UI to ensure compliance and transparency.
