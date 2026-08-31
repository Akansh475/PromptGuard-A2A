# ProvGuard-MAS: Architectural Specification & Security Model

## 1. Executive Overview

**ProvGuard-MAS** is a provenance-aware runtime defense system engineered for multi-agent artificial intelligence networks. It prevents, detects, and contains indirect prompt injections, confused deputy exploits, delimiter smuggling, and privilege escalation attempts across collaborative AI workflows.

Unlike conventional defenses that inspect prompts solely at perimeter boundaries, ProvGuard-MAS maintains **causal provenance lineage DAGs** across inter-agent communications, dynamically computes **taint propagation**, enforces **intent-permission conformance**, and applies **risk-adaptive quarantine** prior to sensitive tool execution.

---

## 2. System Architecture

```
                                  +---------------------------------------+
                                  |              User Proxy               |
                                  |        (Root Trust: 1.0/System)       |
                                  +-------------------+-------------------+
                                                      | User Task
                                                      v
                                  +---------------------------------------+
                                  |            Planning Agent             |
                                  |        (Trust: 0.85/Internal)         |
                                  +---------+-------------------+---------+
                                            |                   |
                     Query External Doc     |                   | Delegate Synthesis
                                            v                   v
+-----------------------+         +---------+---------+   +-----+---------+
| Untrusted Web / Docs  | ======> |  Retrieval Agent  |   |   Summarizer  |
| (Trust: 0.10/External)|         | (Trust: 0.10 Taint|   |  (Trust: 0.60)|
+-----------------------+         +---------+---------+   +-----+---------+
                                            |                   |
                                            +---------+---------+
                                                      | Ingest / Transmit Payload
                                                      v
                                        +===========================+
                                        |   ProvGuard Message Bus   |
                                        +===========================+
                                                      |
                                        +-------------v-------------+
                                        | Provenance Tracker (DAG)  |
                                        | - Origin Identity Tracking|
                                        | - Taint Propagation Score |
                                        | - Transformation History  |
                                        +-------------+-------------+
                                                      |
                                        +-------------v-------------+
                                        |    Conformance Engine     |
                                        | - Intent Injection Scan   |
                                        | - Role Capability Matrix  |
                                        | - Origin-Based Auth Check |
                                        +-------------+-------------+
                                                      |
                             +------------------------+------------------------+
                             |                        |                        |
                   [ Risk < 0.25 ]          [ 0.25 <= Risk < 0.50 ]     [ Risk >= 0.50 ]
                             |                        |                        |
                             v                        v                        v
                         [ ALLOW ]              [ SANITIZE ]             [ QUARANTINE ]
                             |                        |                        |
                             v                        v                        x (Halted)
                   +---------+------------------------+---------+        +-------------+
                   |           Tool Execution Agent             |        | Quarantine  |
                   | (Privileged Sink: Shell, DB, Files, Funds) |        |    Vault    |
                   +--------------------------------------------+        +-------------+
```

---

## 3. Core Mathematical & Security Models

### 3.1 Provenance Lineage & Taint Propagation Model

Every message $m_i$ transmitted in the agent network carries an immutable Provenance Record $P(m_i)$:

$$P(m_i) = \langle \text{id}, \text{parents}, O_{\text{root}}, \tau_{\text{root}}, h, \mathcal{T}, H(c), T(m_i) \rangle$$

Where:
- $O_{\text{root}}$: Root origin identifier.
- $\tau_{\text{root}} \in [0.1, 1.0]$: Trust level of root origin.
- $h \in \mathbb{N}$: Hop count from root ingestion.
- $\mathcal{T} = [t_1, t_2, \dots, t_k]$: Chronological sequence of transformations.
- $H(c)$: SHA-256 cryptographic content digest.
- $T(m_i) \in [0.0, 1.0]$: Accumulated taint index.

The taint score $T(m_i)$ is recursively calculated as:

$$T(m_i) = \min\left(1.0, \; (1.0 - \tau_{\text{root}}) + \alpha \ln(1 + h) + \beta (1 - \bar{\tau}_{\text{relay}}) + \gamma |\mathcal{T}|\right)$$

Where $\alpha = 0.05, \beta = 0.20, \gamma = 0.02$, and $\bar{\tau}_{\text{relay}}$ is the average trust level of intermediate relay nodes.

---

### 3.2 Composite Risk Score Formulation

When an agent requests tool invocation or message routing, the Conformance Engine evaluates a multi-factor risk function:

$$R(m_i) = w_1 \cdot S_{\text{intent}}(m_i) + w_2 \cdot T(m_i) + w_3 \cdot \mathbb{I}_{\text{priv\_violation}}(m_i) + w_4 \cdot \Delta_{\text{grad}}(m_i)$$

Where:
- $S_{\text{intent}} \in [0, 1]$: Semantic & delimiter injection score (regex scanning, delimiter smuggling, base64 payload decoding, Shannon entropy).
- $T(m_i) \in [0, 1]$: Provenance taint propagation index.
- $\mathbb{I}_{\text{priv\_violation}} \in \{0, 1\}$: Binary indicator whether requested capability violates Role-Based Access Control or Minimum Trust requirements.
- $\Delta_{\text{grad}}$: Privilege gradient disparity between untrusted origin and target privileged sink.
- Weights: $w_1 = 0.40, w_2 = 0.35, w_3 = 0.25$.

---

### 3.3 Principle of Origin-Based Authorization (OBA)

Standard multi-agent systems suffer from **Confused Deputy vulnerabilities**: when a trusted internal agent (e.g. `PlanningAgent`) forwards a tool request originally inspired by external untrusted text, the downstream `ToolExecutionAgent` treats the request as trusted because the immediate sender is `PlanningAgent`.

ProvGuard enforces **Origin-Based Authorization (OBA)**:
$$\text{Authorize}(m_i, C_k) \iff (\tau(O_{\text{root}}) \ge \tau_{\min}(C_k)) \land (T(m_i) \le T_{\max}(C_k)) \land (\text{Role}(A_{\text{target}}) \in \mathcal{A}(C_k))$$

Even if `PlanningAgent` generates `EXEC_SHELL`, if $O_{\text{root}} = \text{UNTRUSTED\_EXTERNAL}$ ($\tau = 0.10 < 0.95$), the request is immediately flagged, blocked, and quarantined.

---

## 4. Multi-Tier Defense State Machine

| Risk Tier | Composite Score $R(m_i)$ | Defense Action | Runtime Handling |
| :--- | :---: | :---: | :--- |
| **BENIGN** | $[0.00, 0.25)$ | `ALLOW` | Delivered directly to recipient; zero latency penalty. |
| **LOW** | $[0.25, 0.50)$ | `SANITIZE` | Delimiters stripped, HTML comments neutralised, wrapped in safe data boundary. |
| **MEDIUM** | $[0.50, 0.75)$ | `QUARANTINE` | Isolated in `QuarantineVault`; downstream tool execution halted; forensic trace logged. |
| **HIGH** | $[0.75, 0.90)$ | `BLOCK` | Message dropped; security alert dispatched to User Proxy. |
| **CRITICAL** | $[0.90, 1.00]$ | `CIRCUIT_BREAK` | Session communication frozen; agent cascade halted to prevent viral propagation. |
