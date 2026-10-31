# VELTRIX: 5-Minute Live Competition Demonstration Script
### *Beyond Detection. Into Defense.*

---

## Act 1: The Problem & Architecture (0:00 - 1:00)
- **Speaker:** *"Judges, modern security teams are drowning in alert fatigue. Disparate monitoring tools fire isolated warnings without correlating whether an alert is a random scanner or part of an active multi-stage breach. Furthermore, most systems stop at detection, leaving responders to manually contain threats.*
- *Welcome to **VELTRIX**: an autonomous cyber threat detection and controlled response platform built entirely on cloud-native AWS serverless architecture."*
- **Visual Action:** Open **SOC Overview** dashboard. Point to the live pipeline status, telemetry velocity charts, MTTD/MTTR metrics, and MITRE ATT&CK tactic distribution.

---

## Act 2: Threat Detection & Sigma Rules (1:00 - 2:00)
- **Speaker:** *"VELTRIX is powered by 10 configurable Sigma-inspired detection rules evaluated against incoming telemetry in real-time. Notice how each rule defines sliding temporal windows, thresholds, and precise MITRE ATT&CK mappings.*
- *Let's navigate to the **Threat Detection** view. Analysts can dynamically tune thresholds, toggle rules, or customize recommended response policies on the fly without restarting any services."*
- **Visual Action:** Navigate to **Threat Detection**. Demonstrate toggling a rule or adjusting a threshold slider.

---

## Act 3: Live Attack Simulation (2:00 - 3:15)
- **Speaker:** *"To demonstrate VELTRIX under live fire, we built a sandboxed **Simulation Lab** with 6 automated adversary scenarios. Let's trigger our signature breach scenario: **Multi-Stage Account Compromise & Exfiltration**."*
- **Visual Action:** 
  1. Click **Simulation Lab**.
  2. Locate Scenario 3: *Multi-Stage Account Compromise & Exfiltration*.
  3. Click **Execute Simulation**.
  4. Watch the Live Telemetry Terminal stream 8 synthetic security events:
     - 5 failed logins from `198.51.100.42` targeting `sarah.connors` (Brute Force)
     - 1 successful login (Credential Compromise)
     - 1 unauthorized IAM AdministratorAccess assumption attempt (Privilege Escalation)
     - 1 bulk query extracting 15,000 customer PII records (Data Exfiltration).
  5. The terminal confirms: Ingestion complete $\to$ Detection rules fired $\to$ Correlation linked $\to$ Risk score calculated.

---

## Act 4: Correlated Incident Dossier & Explainable Risk Scoring (3:15 - 4:15)
- **Speaker:** *"Instead of spamming the analyst with 8 separate alerts, VELTRIX's Correlation Engine links every action across time, IP, and user identity into a single unified incident.*
- *Notice the calculated Risk Score: **94/100 (CRITICAL)**. VELTRIX provides full mathematical transparency: the score is deconstructed into base severity, frequency multiplier, asset privilege multiplier, threat intel reputation, and an attack sequence bonus across 4 MITRE tactics."*
- **Visual Action:**
  1. Click **Inspect Correlated Incident**.
  2. Review the formula factor cards.
  3. Walk through the interactive **Attack Sequence Progression** timeline (Credential Access $\to$ Valid Accounts $\to$ Privilege Escalation $\to$ Exfiltration).

---

## Act 5: Controlled SOAR Defense & Cryptographic Audit (4:15 - 5:00)
- **Speaker:** *"Now into defense: High-severity incidents queue controlled containment actions into our Response Center. Because blocking an IP or suspending an account is disruptive, VELTRIX enforces a human-in-the-loop approval gate.*
- *Let's navigate to **Response Center**, review the queued action, click **Approve & Execute**, and observe the simulated firewall policy update.*
- *Finally, in **Audit Ledger**, every single action is secured in an append-only chain with SHA-256 integrity fingerprints. Clicking **Verify Ledger Integrity** proves zero tampering has occurred across the entire chain."*
- **Visual Action:**
  1. Navigate to **Response Center** $\to$ Click **Approve & Execute**.
  2. Observe active IP block added to registry.
  3. Navigate to **Audit Ledger** $\to$ Click **Verify Ledger Integrity** $\to$ Observe green verified banner!
- **Concluding Line:** *"Beyond Detection. Into Defense. That is VELTRIX. Thank you."*
