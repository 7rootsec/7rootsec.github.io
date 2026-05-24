---
# the default layout is 'page'
icon: fas fa-info-circle
order: 4
---

<div class="about-dashboard">

  <!-- 1. Operator Info & Radar Profile Picture -->
  <div class="profile-header cyber-panel">
    <div class="radar-container">
      <img src="{{ site.avatar | relative_url }}" alt="7rootsec Avatar">
    </div>
    <div class="profile-meta">
      <h2 style="font-family: 'Share Tech Mono', monospace; color: var(--cyber-neon-green); margin-bottom: 8px;">OPERATOR: 7ROOTSEC</h2>
      <span class="cyber-status-text">STATUS: ACTIVE // OFFENSIVE SECURITY DEPLOYED</span>
      <table style="font-family: 'Share Tech Mono', monospace; font-size: 0.8rem; width: 100%; border: none; margin-top: 10px;">
        <tr style="background: transparent;">
          <td style="padding: 2px 0; font-weight: bold; color: var(--cyber-neon-cyan);">Classification:</td>
          <td style="padding: 2px 0; color: #fff;">L4 Security Engineer</td>
        </tr>
        <tr style="background: transparent;">
          <td style="padding: 2px 0; font-weight: bold; color: var(--cyber-neon-cyan);">Core Focus:</td>
          <td style="padding: 2px 0; color: #fff;">IoT Exploitation, Web & Active Directory Hardening</td>
        </tr>
        <tr style="background: transparent;">
          <td style="padding: 2px 0; font-weight: bold; color: var(--cyber-neon-cyan);">Operational Exp:</td>
          <td style="padding: 2px 0; color: #fff;">4+ Years in Threat Defense & Adversary Simulation</td>
        </tr>
      </table>
    </div>
  </div>

  <!-- 2. Profile Summary -->
  <div class="cyber-panel" style="padding: 15px; font-family: 'Share Tech Mono', monospace; font-size: 0.85rem; line-height: 1.5;">
    <div style="border-bottom: 1px dashed rgba(0, 255, 102, 0.25); padding-bottom: 6px; margin-bottom: 10px; font-weight: bold; color: var(--cyber-neon-green); text-transform: uppercase;">
      // Executive Mission Summary
    </div>
    Cybersecurity professional with a strong track record of identifying, analyzing, and mitigating complex security vulnerabilities in web applications, APIs, and distributed systems (including OWASP Top 10 risks, business logic flaws, and advanced exploitation chains). Highly experienced in network security, system hardening, and Windows internals, working inside security operations and penetration testing teams to reduce attack surfaces at scale.
  </div>

  <!-- 3. Core Specialties (Skill Progress Bars) -->
  <div class="cyber-panel">
    <div style="border-bottom: 1px dashed rgba(0, 255, 102, 0.25); padding-bottom: 6px; margin-bottom: 12px; font-family: 'Share Tech Mono', monospace; font-weight: bold; color: var(--cyber-neon-green); text-transform: uppercase;">
      // Skill Matrix Loading...
    </div>
    <div class="skills-container">
      <div class="cyber-meter">
        <div class="meter-label">
          <span>Web & API Penetration Testing</span>
          <span>90%</span>
        </div>
        <div class="meter-track">
          <div class="meter-fill" data-width="90%"></div>
        </div>
      </div>
      <div class="cyber-meter">
        <div class="meter-label">
          <span>IoT & Hardware Exploitation</span>
          <span>85%</span>
        </div>
        <div class="meter-track">
          <div class="meter-fill" data-width="85%"></div>
        </div>
      </div>
      <div class="cyber-meter">
        <div class="meter-label">
          <span>Windows Internals & Privilege Escalation</span>
          <span>80%</span>
        </div>
        <div class="meter-track">
          <div class="meter-fill" data-width="80%"></div>
        </div>
      </div>
      <div class="cyber-meter">
        <div class="meter-label">
          <span>Security Automation (Python/Bash)</span>
          <span>85%</span>
        </div>
        <div class="meter-track">
          <div class="meter-fill" data-width="85%"></div>
        </div>
      </div>
    </div>
  </div>

  <!-- 4. The Arsenal (Tools Grid) -->
  <div class="cyber-panel">
    <div style="border-bottom: 1px dashed rgba(0, 255, 102, 0.25); padding-bottom: 6px; margin-bottom: 12px; font-family: 'Share Tech Mono', monospace; font-weight: bold; color: var(--cyber-neon-green); text-transform: uppercase;">
      // System Toolkit & Arsenal
    </div>
    <div class="tools-grid">
      <div class="tool-card">
        <i class="fas fa-spider"></i>
        <span class="tool-name">Burp Suite Pro</span>
      </div>
      <div class="tool-card">
        <i class="fas fa-radar"></i>
        <span class="tool-name">Nmap / Masscan</span>
      </div>
      <div class="tool-card">
        <i class="fas fa-project-diagram"></i>
        <span class="tool-name">Wireshark</span>
      </div>
      <div class="tool-card">
        <i class="fas fa-skull"></i>
        <span class="tool-name">Metasploit</span>
      </div>
      <div class="tool-card">
        <i class="fas fa-search-plus"></i>
        <span class="tool-name">ffuf / Gobuster</span>
      </div>
      <div class="tool-card">
        <i class="fab fa-python"></i>
        <span class="tool-name">Custom Python</span>
      </div>
    </div>
  </div>

  <!-- 5. Operational Feed (Experience Timeline) -->
  <div class="cyber-panel">
    <div style="border-bottom: 1px dashed rgba(0, 255, 102, 0.25); padding-bottom: 6px; margin-bottom: 12px; font-family: 'Share Tech Mono', monospace; font-weight: bold; color: var(--cyber-neon-green); text-transform: uppercase;">
      // Historical Operation Logs
    </div>
    <div class="timeline-logs">
      <div class="timeline-log success">
        <span class="log-time">[2022 - PRESENT]</span>
        Penetration Testing Specialist - Led Web & AD infrastructure assessments, resolving over 120 critical findings.
      </div>
      <div class="timeline-log success">
        <span class="log-time">[2020 - 2022]</span>
        Security Analyst - Handled SOC operations, incident response, network forensic traffic investigations, and log audits.
      </div>
      <div class="timeline-log">
        <span class="log-time">[2019 - 2020]</span>
        Systems & Security Engineer - Configured production firewalls, hardended server kernels, and set up network protocols.
      </div>
      <div class="timeline-log">
        <span class="log-time">[Threat Intel Feed]</span>
        Ongoing adversary simulation threat research, CVE analysis, and writeup publications on TryHackMe/HackTheBox.
      </div>
    </div>
  </div>

</div>
