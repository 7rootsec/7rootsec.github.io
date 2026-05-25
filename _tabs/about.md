---
# the default layout is 'page'
icon: fas fa-info-circle
order: 4
---

<div class="dossier-wrapper">
  <div class="dossier-header">
    <div class="classification-stamp">TOP SECRET // NOFORN</div>
    <div class="dossier-title">OPERATOR DOSSIER: 7ROOTSEC</div>
    <div class="dossier-id">ID: 0x7R00T // CLEARANCE: L4</div>
  </div>

  <div class="dossier-body">
    <div class="profile-section">
      <div class="avatar-container">
        <div class="scanner-line"></div>
        <img src="{{ site.avatar | relative_url }}" alt="7rootsec Avatar" class="target-img">
        <div class="crosshair">
          <div class="hline"></div>
          <div class="vline"></div>
        </div>
      </div>
      <div class="intel-data">
        <table class="intel-table">
          <tr><td class="label">ALIAS:</td><td class="value highlight">7ROOTSEC</td></tr>
          <tr><td class="label">STATUS:</td><td class="value">ACTIVE_DEPLOYMENT</td></tr>
          <tr><td class="label">ROLE:</td><td class="value">Offensive Security Engineer</td></tr>
          <tr><td class="label">SPECIALTY:</td><td class="value">IoT Exploitation, Web Hacking</td></tr>
          <tr><td class="label">LOCATION:</td><td class="value">[REDACTED]</td></tr>
        </table>
      </div>
    </div>

    <div class="data-panel">
      <h3 class="panel-title">>_ EXECUTIVE SUMMARY</h3>
      <div class="panel-content type-text">
        Subject is a highly skilled cybersecurity professional specializing in identifying and exploiting complex vulnerabilities in web applications, APIs, and distributed systems. 
        <br><br>
        Extensive background in <span class="redacted">Network Security</span> and <span class="redacted">System Hardening</span>. Operates globally in Threat Defense and Adversary Simulation.
      </div>
    </div>

    <div class="data-panel">
      <h3 class="panel-title">>_ EXPLOIT MODULES & SKILL MATRIX</h3>
      <div class="skills-grid">
        <div class="skill-item">
          <span class="skill-name">WEB_API_PENTESTING</span>
          <div class="progress-bar"><div class="fill" style="width: 90%;"></div></div>
        </div>
        <div class="skill-item">
          <span class="skill-name">IOT_HARDWARE_EXPLOIT</span>
          <div class="progress-bar"><div class="fill" style="width: 85%;"></div></div>
        </div>
        <div class="skill-item">
          <span class="skill-name">WINDOWS_INTERNALS</span>
          <div class="progress-bar"><div class="fill" style="width: 80%;"></div></div>
        </div>
        <div class="skill-item">
          <span class="skill-name">SEC_AUTOMATION</span>
          <div class="progress-bar"><div class="fill" style="width: 85%;"></div></div>
        </div>
      </div>
    </div>

    <div class="data-panel">
      <h3 class="panel-title">>_ KNOWN ARSENAL</h3>
      <div class="arsenal-tags">
        <span class="cyber-tag">Burp Suite Pro</span>
        <span class="cyber-tag">Nmap</span>
        <span class="cyber-tag">Wireshark</span>
        <span class="cyber-tag">Metasploit</span>
        <span class="cyber-tag">Python Scripting</span>
        <span class="cyber-tag">Ghidra</span>
      </div>
    </div>
  </div>
</div>

<style>
.dossier-wrapper {
  background: #0f111a;
  border: 1px solid #333;
  padding: 20px;
  font-family: 'Share Tech Mono', 'Courier New', Courier, monospace;
  color: #c5c8c6;
  position: relative;
  overflow: hidden;
  margin-top: 2rem;
}

.dossier-wrapper::before {
  content: '';
  position: absolute;
  top: 0; left: 0; width: 100%; height: 100%;
  background: repeating-linear-gradient(
    0deg,
    rgba(0, 0, 0, 0.15),
    rgba(0, 0, 0, 0.15) 1px,
    transparent 1px,
    transparent 2px
  );
  pointer-events: none;
  z-index: 10;
}

.dossier-header {
  border-bottom: 2px solid #ff4444;
  padding-bottom: 15px;
  margin-bottom: 25px;
  text-align: center;
  position: relative;
}

.classification-stamp {
  color: #ff4444;
  font-weight: bold;
  font-size: 1.5rem;
  letter-spacing: 5px;
  border: 2px solid #ff4444;
  display: inline-block;
  padding: 5px 15px;
  transform: rotate(-5deg);
  opacity: 0.8;
  position: absolute;
  top: -10px;
  right: 10px;
}

.dossier-title {
  font-size: 1.8rem;
  color: #fff;
  letter-spacing: 2px;
  margin-top: 20px;
}

.dossier-id {
  color: #888;
  font-size: 0.9rem;
  margin-top: 5px;
}

.profile-section {
  display: flex;
  gap: 30px;
  margin-bottom: 30px;
}

@media (max-width: 600px) {
  .profile-section {
    flex-direction: column;
    align-items: center;
  }
}

.avatar-container {
  width: 180px;
  height: 180px;
  position: relative;
  border: 1px solid var(--cyber-neon-green);
  overflow: hidden;
  background: rgba(0, 255, 102, 0.05);
}

.target-img {
  width: 100%;
  height: 100%;
  object-fit: cover;
  filter: grayscale(100%) contrast(120%);
  opacity: 0.8;
}

.scanner-line {
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 2px;
  background: var(--cyber-neon-green);
  box-shadow: 0 0 10px var(--cyber-neon-green);
  animation: scan 3s infinite linear;
  z-index: 5;
}

@keyframes scan {
  0% { top: 0; }
  50% { top: 100%; }
  100% { top: 0; }
}

.crosshair {
  position: absolute;
  top: 50%; left: 50%;
  transform: translate(-50%, -50%);
  width: 50px; height: 50px;
  z-index: 6;
}

.crosshair .hline {
  width: 100%; height: 1px; background: rgba(0,255,102,0.5); position: absolute; top: 50%; left: 0;
}

.crosshair .vline {
  width: 1px; height: 100%; background: rgba(0,255,102,0.5); position: absolute; top: 0; left: 50%;
}

.intel-data {
  flex: 1;
}

.intel-table {
  width: 100%;
  border-collapse: collapse;
}

.intel-table td {
  padding: 8px 0;
  border-bottom: 1px dashed #333;
}

.intel-table .label {
  color: #888;
  width: 120px;
}

.intel-table .value {
  color: #ddd;
}

.intel-table .value.highlight {
  color: var(--cyber-neon-green);
  font-weight: bold;
}

.data-panel {
  background: rgba(0, 0, 0, 0.4);
  border: 1px solid #333;
  padding: 15px;
  margin-bottom: 20px;
}

.panel-title {
  color: var(--cyber-neon-cyan);
  font-size: 1.1rem;
  margin-top: 0;
  margin-bottom: 15px;
  border-bottom: 1px solid #333;
  padding-bottom: 5px;
}

.redacted {
  background-color: #fff;
  color: #fff;
  padding: 0 5px;
  cursor: pointer;
  transition: all 0.3s ease;
}

.redacted:hover {
  background-color: transparent;
  color: #ff4444;
}

.skills-grid {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.skill-item {
  display: flex;
  align-items: center;
}

.skill-name {
  width: 180px;
  font-size: 0.85rem;
  color: #aaa;
}

.progress-bar {
  flex: 1;
  height: 8px;
  background: #222;
  border: 1px solid #444;
}

.progress-bar .fill {
  height: 100%;
  background: var(--cyber-neon-green);
  box-shadow: 0 0 5px var(--cyber-neon-green);
}

.arsenal-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
}

.cyber-tag {
  background: rgba(0, 229, 255, 0.1);
  color: var(--cyber-neon-cyan);
  border: 1px solid var(--cyber-neon-cyan);
  padding: 5px 10px;
  font-size: 0.8rem;
  border-radius: 2px;
}
</style>
