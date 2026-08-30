# 🔬 CampusShield AI — 20 Unidirectional Feature Specification

This technical specification details the **20 Passive Unidirectional Features** used by CampusShield AI (SIH26145) to detect anomalous network traffic, DDoS attacks, port sweeps, and data exfiltration through one-way data diodes and passive optical taps.

---

## 🎯 Unidirectional Ground Rules

1. **Strict One-Way Observability**: No TCP handshake round-trip timing, ACK correlation, or return path requirements.
2. **Zero Response Packet Dependency**: Every metric is calculated solely from frames flowing in the forward direction ($A \to B$).
3. **Passive Wire Tap Safety**: Processing can occur directly on mirror ports or optical splitters without injecting packets.

---

## 📋 Feature Catalog

| ID | Feature Name | Category | Unit | Mathematical Definition & Physical Proof |
| :---: | :--- | :---: | :---: | :--- |
| **1** | `packet_count` | Volume | pkts | Total observed packet frames in sliding window $\Delta W = 1.0\text{s}$. Direct count of one-way frame headers. |
| **2** | `total_bytes` | Volume | bytes | Sum of observed frame lengths: $\sum_{i=1}^{N} \text{len}(P_i)$. Derived from passive wire length. |
| **3** | `bytes_per_second` | Rate | B/s | Throughput bandwidth velocity: $\frac{\sum \text{len}(P_i)}{\Delta W}$. |
| **4** | `packets_per_second` | Rate | req/s | Ingress packet arrival velocity: $\frac{N}{\Delta W}$. Key metric for volumetric flood detection. |
| **5** | `min_packet_size` | Size | bytes | $\min_{i} \text{len}(P_i)$. Identifies SYN floods (40–60 bytes) vs small probes. |
| **6** | `max_packet_size` | Size | bytes | $\max_{i} \text{len}(P_i)$. Detects Jumbo frames and raw data dumps (1,420–1,500 bytes). |
| **7** | `mean_packet_size` | Size | bytes | First statistical moment: $\mu = \frac{1}{N}\sum_{i=1}^N \text{len}(P_i)$. |
| **8** | `std_packet_size` | Size | bytes | Second statistical moment (dispersion): $\sigma = \sqrt{\frac{1}{N}\sum (x_i - \mu)^2}$. |
| **9** | `packet_size_skewness` | Size | skew | Third standardized moment: $\gamma_1 = \frac{\frac{1}{N}\sum(x_i - \mu)^3}{\sigma^3}$. Measures distribution asymmetry. |
| **10** | `min_iat` | Timing | ms | $\min(\Delta t_i)$ where $\Delta t_i = t_i - t_{i-1}$. Detects microsecond packet bursts. |
| **11** | `max_iat` | Timing | ms | $\max(\Delta t_i)$. Identifies idle gaps between command pulses. |
| **12** | `mean_iat` | Timing | ms | Average inter-arrival cadence: $\overline{\Delta t} = \frac{1}{N-1}\sum_{i=2}^N (t_i - t_{i-1})$. |
| **13** | `std_iat` | Timing | ms | Arrival jitter / dispersion: $\sigma_{\text{IAT}}$. Flags automated botnet beacons (fixed $\Delta t$). |
| **14** | `burst_count` | Timing | count | Count of packet pairs where $\Delta t_i < 1.0\text{ms}$. Signals high-rate flood bursts. |
| **15** | `unique_dst_ports` | Port | count | $|\{ \text{dst\_port}_i \}|$. Detects sequential port scans and multi-service sweeps. |
| **16** | `dst_port_entropy` | Port | bits | Shannon entropy across target ports: $H(D) = -\sum p_j \log_2(p_j)$. |
| **17** | `protocol_entropy` | Protocol | bits | Shannon entropy across transport protocols (TCP/UDP/ICMP): $H(\text{Proto})$. |
| **18** | `tcp_ratio` | Protocol | ratio | Fraction of frames utilizing TCP transport: $\frac{N_{\text{TCP}}}{N}$. |
| **19** | `udp_ratio` | Protocol | ratio | Fraction of frames utilizing UDP transport: $\frac{N_{\text{UDP}}}{N}$. |
| **20** | `payload_entropy` | Payload | bits/B | Shannon byte entropy of raw application payloads ($H > 7.4$ flags encrypted exfiltration). |

---

## 🧮 Isolation Forest Anomaly Scoring

Each 1.0-second feature vector $\mathbf{x} \in \mathbb{R}^{20}$ is evaluated across an ensemble of 150 Isolation Trees:

$$s(\mathbf{x}, n) = 2^{-\frac{\mathbb{E}(h(\mathbf{x}))}{c(n)}}$$

Where:
- $h(\mathbf{x})$ is the path length to isolate sample $\mathbf{x}$ in tree $T$.
- $c(n) = 2\left(\ln(n - 1) + 0.5772156649\right) - \frac{2(n - 1)}{n}$ is the average path length of unsuccessful search in a Binary Search Tree.
- Anomalies isolate near the root ($h(\mathbf{x}) \ll c(n)$), yielding scores approaching $1.0$ ($100\%$).
