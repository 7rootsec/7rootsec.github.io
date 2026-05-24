/**
 * 7rootsec Cybersecurity Blog Custom Script
 * Adds interactive retro terminal, Matrix rain, Particle Node Mesh,
 * scroll hex progress, and dynamic SecOps sidebar controls.
 */

document.addEventListener('DOMContentLoaded', () => {
  // ----------------------------------------------------
  // 1. DOM SELECTORS & INITIALIZATION
  // ----------------------------------------------------
  const sidebar = document.getElementById('sidebar');
  const siteTitle = document.querySelector('.site-title a') || document.querySelector('.site-title');
  const siteSubtitle = document.querySelector('.site-subtitle');

  if (siteTitle) {
    siteTitle.classList.add('glitch-hover');
  }

  // Apply card brackets styles to Chirpy post cards
  document.querySelectorAll('.post-preview, .card').forEach(card => {
    card.classList.add('cyber-panel');
  });

  // ----------------------------------------------------
  // 2. TAGLINE TYPEWRITER ANIMATION
  // ----------------------------------------------------
  if (siteSubtitle) {
    const phrases = [
      "IoT Exploitation & Hardware Hacking",
      "Web Application Penetration Testing",
      "Windows Internals & Privilege Escalation",
      "Red Teaming & Adversary Simulation",
      "Custom Automation Tooling (Python/Bash)"
    ];
    let phraseIndex = 0;
    let charIndex = 0;
    let isDeleting = false;
    let delay = 100;

    siteSubtitle.innerHTML = '<span class="typewriter-text"></span><span class="typewriter-cursor"></span>';
    const textSpan = siteSubtitle.querySelector('.typewriter-text');

    function typeEffect() {
      const currentPhrase = phrases[phraseIndex];
      
      if (isDeleting) {
        textSpan.textContent = currentPhrase.substring(0, charIndex - 1);
        charIndex--;
        delay = 40;
      } else {
        textSpan.textContent = currentPhrase.substring(0, charIndex + 1);
        charIndex++;
        delay = 80;
      }

      if (!isDeleting && charIndex === currentPhrase.length) {
        isDeleting = true;
        delay = 2000;
      } else if (isDeleting && charIndex === 0) {
        isDeleting = false;
        phraseIndex = (phraseIndex + 1) % phrases.length;
        delay = 500;
      }

      setTimeout(typeEffect, delay);
    }

    setTimeout(typeEffect, 1000);
  }

  // ----------------------------------------------------
  // 3. SECURE CONNECTION SIDEBAR WIDGET & CONTROLS
  // ----------------------------------------------------
  if (sidebar) {
    const randomIP = `10.24.${Math.floor(Math.random() * 254) + 1}.${Math.floor(Math.random() * 254) + 1}`;
    
    const widget = document.createElement('div');
    widget.className = 'connection-widget';
    widget.innerHTML = `
      <div class="widget-title">
        <span>SecOps Status</span>
        <div class="pulse-dot"></div>
      </div>
      <div class="widget-row">
        <span class="widget-label">Connection:</span>
        <span class="widget-value" id="widget-conn">SECURE (TLS)</span>
      </div>
      <div class="widget-row">
        <span class="widget-label">Tunnel IP:</span>
        <span class="widget-value">${randomIP}</span>
      </div>
      <div class="widget-row">
        <span class="widget-label">Proxy Node:</span>
        <span class="widget-value">CH_ZURICH_EXIT</span>
      </div>
      <div class="widget-row">
        <span class="widget-label">Uptime:</span>
        <span class="widget-value" id="session-timer">00:00:00</span>
      </div>
      <div class="widget-row" style="margin-top: 8px; border-top: 1px dashed rgba(0, 255, 102, 0.15); padding-top: 6px; justify-content: space-between; gap: 4px; flex-wrap: wrap;">
        <a href="#" id="widget-matrix-toggle" style="color: rgba(0, 255, 102, 0.6); text-decoration: none; border-bottom: 1px dotted; font-size: 0.65rem;">Matrix: OFF</a>
        <a href="#" id="widget-nodes-toggle" style="color: rgba(0, 255, 102, 0.6); text-decoration: none; border-bottom: 1px dotted; font-size: 0.65rem;">Nodes: OFF</a>
        <a href="#" id="widget-crt-toggle" style="color: rgba(0, 229, 255, 0.6); text-decoration: none; border-bottom: 1px dotted; font-size: 0.65rem;">CRT: OFF</a>
      </div>
    `;

    const profileWrapper = sidebar.querySelector('.profile-wrapper') || sidebar.firstElementChild;
    if (profileWrapper) {
      profileWrapper.parentNode.insertBefore(widget, profileWrapper.nextSibling);
    } else {
      sidebar.appendChild(widget);
    }

    let seconds = 0;
    setInterval(() => {
      seconds++;
      const hrs = String(Math.floor(seconds / 3600)).padStart(2, '0');
      const mins = String(Math.floor((seconds % 3600) / 60)).padStart(2, '0');
      const secs = String(seconds % 60).padStart(2, '0');
      const timerElement = document.getElementById('session-timer');
      if (timerElement) {
        timerElement.textContent = `${hrs}:${mins}:${secs}`;
      }
    }, 1000);
  }

  // ----------------------------------------------------
  // 4. SCROLL PROGRESS INDICATOR (HEX VALUE)
  // ----------------------------------------------------
  const progressContainer = document.createElement('div');
  progressContainer.id = 'scroll-progress-container';
  progressContainer.innerHTML = `<div id="scroll-progress-bar"></div>`;
  
  const progressText = document.createElement('div');
  progressText.id = 'scroll-progress-text';
  progressText.textContent = '[PROGRESS: 0x00/0xFF]';
  
  document.body.appendChild(progressContainer);
  document.body.appendChild(progressText);

  const progressBar = document.getElementById('scroll-progress-bar');

  window.addEventListener('scroll', () => {
    const docHeight = document.documentElement.scrollHeight - window.innerHeight;
    if (docHeight <= 0) {
      progressBar.style.width = '0%';
      progressText.textContent = '[PROGRESS: 0x00/0xFF]';
      return;
    }
    const scrollPercent = (window.scrollY / docHeight) * 100;
    progressBar.style.width = `${scrollPercent}%`;

    // Map 0-100% to 0-255 (0x00 - 0xFF)
    const hexVal = Math.round(scrollPercent * 2.55).toString(16).toUpperCase().padStart(2, '0');
    progressText.textContent = `[PROGRESS: 0x${hexVal}/0xFF]`;
  });

  // ----------------------------------------------------
  // 5. MATRIX & NODES BACKGROUND CANVAS GENERATORS
  // ----------------------------------------------------
  const canvas = document.createElement('canvas');
  canvas.id = 'matrix-canvas';
  document.body.appendChild(canvas);
  const ctx = canvas.getContext('2d');

  let canvasMode = 'none'; // 'none' | 'matrix' | 'nodes'
  let canvasAnimationId = null;

  // Matrix variables
  let columns = 0;
  let drops = [];
  const matrixChars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ01010101/*-+=%';
  const fontSize = 14;

  // Nodes variables
  let particles = [];
  const maxParticles = 60;
  let mouse = { x: null, y: null };

  window.addEventListener('mousemove', (e) => {
    mouse.x = e.clientX;
    mouse.y = e.clientY;
  });

  window.addEventListener('mouseout', () => {
    mouse.x = null;
    mouse.y = null;
  });

  class Particle {
    constructor() {
      this.x = Math.random() * canvas.width;
      this.y = Math.random() * canvas.height;
      this.vx = (Math.random() - 0.5) * 0.8;
      this.vy = (Math.random() - 0.5) * 0.8;
      this.radius = Math.random() * 2 + 1;
    }
    update() {
      this.x += this.vx;
      this.y += this.vy;

      if (this.x < 0 || this.x > canvas.width) this.vx *= -1;
      if (this.y < 0 || this.y > canvas.height) this.vy *= -1;

      // Mouse interaction (slight push away)
      if (mouse.x !== null && mouse.y !== null) {
        const dx = mouse.x - this.x;
        const dy = mouse.y - this.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 100) {
          const force = (100 - dist) / 100;
          this.x -= (dx / dist) * force * 2;
          this.y -= (dy / dist) * force * 2;
        }
      }
    }
    draw() {
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
      ctx.fillStyle = '#00ff66';
      ctx.fill();
    }
  }

  function resizeCanvas() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    
    // Reset Matrix
    columns = Math.floor(canvas.width / fontSize);
    drops = Array(columns).fill(1);

    // Reset Nodes
    particles = [];
    for (let i = 0; i < maxParticles; i++) {
      particles.push(new Particle());
    }
  }

  function loop() {
    if (canvasMode === 'matrix') {
      ctx.fillStyle = 'rgba(12, 14, 18, 0.08)'; // trails
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      ctx.fillStyle = '#00ff66';
      ctx.font = `${fontSize}px 'Share Tech Mono', monospace`;

      for (let i = 0; i < drops.length; i++) {
        const text = matrixChars.charAt(Math.floor(Math.random() * matrixChars.length));
        ctx.fillText(text, i * fontSize, drops[i] * fontSize);

        if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
          drops[i] = 0;
        }
        drops[i]++;
      }
    } else if (canvasMode === 'nodes') {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      
      // Update & Draw particles
      particles.forEach(p => {
        p.update();
        p.draw();
      });

      // Draw connections
      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const dx = particles[i].x - particles[j].x;
          const dy = particles[i].y - particles[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < 110) {
            const alpha = (110 - dist) / 110 * 0.15;
            ctx.strokeStyle = `rgba(0, 255, 102, ${alpha})`;
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.moveTo(particles[i].x, particles[i].y);
            ctx.lineTo(particles[j].x, particles[j].y);
            ctx.stroke();
          }
        }
      }

      // Draw connections to mouse
      if (mouse.x !== null && mouse.y !== null) {
        particles.forEach(p => {
          const dx = mouse.x - p.x;
          const dy = mouse.y - p.y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < 130) {
            const alpha = (130 - dist) / 130 * 0.22;
            ctx.strokeStyle = `rgba(0, 229, 255, ${alpha})`;
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.moveTo(mouse.x, mouse.y);
            ctx.lineTo(p.x, p.y);
            ctx.stroke();
          }
        });
      }
    }

    canvasAnimationId = requestAnimationFrame(loop);
  }

  function startCanvasEffect(mode) {
    if (canvasAnimationId) {
      cancelAnimationFrame(canvasAnimationId);
      canvasAnimationId = null;
    }
    
    canvasMode = mode;
    
    if (mode === 'none') {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      document.body.classList.remove('matrix-active');
      updateCanvasToggleTexts();
      return;
    }

    resizeCanvas();
    document.body.classList.add('matrix-active'); // makes canvas container visible
    loop();
    updateCanvasToggleTexts();
  }

  function updateCanvasToggleTexts() {
    const matrixBtn = document.getElementById('widget-matrix-toggle');
    const nodesBtn = document.getElementById('widget-nodes-toggle');

    if (matrixBtn) {
      const active = canvasMode === 'matrix';
      matrixBtn.textContent = active ? 'Matrix: ON' : 'Matrix: OFF';
      matrixBtn.style.color = active ? '#00ff66' : 'rgba(0, 255, 102, 0.6)';
    }

    if (nodesBtn) {
      const active = canvasMode === 'nodes';
      nodesBtn.textContent = active ? 'Nodes: ON' : 'Nodes: OFF';
      nodesBtn.style.color = active ? '#00ff66' : 'rgba(0, 255, 102, 0.6)';
    }
  }

  window.addEventListener('resize', () => {
    if (canvasMode !== 'none') {
      resizeCanvas();
    }
  });

  // Handle widget toggle clicks
  document.addEventListener('click', (e) => {
    if (!e.target) return;
    if (e.target.id === 'widget-matrix-toggle') {
      e.preventDefault();
      const nextMode = canvasMode === 'matrix' ? 'none' : 'matrix';
      startCanvasEffect(nextMode);
      localStorage.setItem('canvas-mode', nextMode);
    }
    if (e.target.id === 'widget-nodes-toggle') {
      e.preventDefault();
      const nextMode = canvasMode === 'nodes' ? 'none' : 'nodes';
      startCanvasEffect(nextMode);
      localStorage.setItem('canvas-mode', nextMode);
    }
  });

  // Load canvas mode preference
  const localCanvasMode = localStorage.getItem('canvas-mode') || 'none';
  if (localCanvasMode !== 'none') {
    startCanvasEffect(localCanvasMode);
  }

  // ----------------------------------------------------
  // 6. CRT MONITOR RETRO SIMULATOR
  // ----------------------------------------------------
  function toggleCRT() {
    const isCrt = document.body.classList.contains('crt-active');
    const crtToggleLink = document.getElementById('widget-crt-toggle');
    
    if (isCrt) {
      document.body.classList.remove('crt-active');
      localStorage.setItem('crt-active', 'false');
      if (crtToggleLink) {
        crtToggleLink.textContent = 'CRT: OFF';
        crtToggleLink.style.color = 'rgba(0, 229, 255, 0.6)';
      }
    } else {
      document.body.classList.add('crt-active');
      localStorage.setItem('crt-active', 'true');
      if (crtToggleLink) {
        crtToggleLink.textContent = 'CRT: ON';
        crtToggleLink.style.color = '#00e5ff';
      }
    }
  }

  if (localStorage.getItem('crt-active') === 'true') {
    document.body.classList.add('crt-active');
    setTimeout(() => {
      const crtToggleLink = document.getElementById('widget-crt-toggle');
      if (crtToggleLink) {
        crtToggleLink.textContent = 'CRT: ON';
        crtToggleLink.style.color = '#00e5ff';
      }
    }, 100);
  }

  document.addEventListener('click', (e) => {
    if (e.target && e.target.id === 'widget-crt-toggle') {
      e.preventDefault();
      toggleCRT();
    }
  });

  // ----------------------------------------------------
  // 7. SKILLS LOADING BAR ANIMATION (ABOUT PAGE)
  // ----------------------------------------------------
  function loadSkillsMeters() {
    const fills = document.querySelectorAll('.meter-fill');
    setTimeout(() => {
      fills.forEach(fill => {
        const targetWidth = fill.getAttribute('data-width') || '0%';
        fill.style.width = targetWidth;
      });
    }, 450);
  }
  
  loadSkillsMeters();

  // ----------------------------------------------------
  // 8. INTERACTIVE DRAGGABLE FLOATING TERMINAL OVERLAY
  // ----------------------------------------------------
  const termContainer = document.createElement('div');
  termContainer.className = 'cyber-terminal minimized';
  termContainer.id = 'cyber-terminal';
  termContainer.innerHTML = `
    <div class="terminal-header" id="terminal-header">
      <div class="terminal-title">
        <i class="fas fa-terminal"></i>
        <span>7rootsec@secops:~</span>
      </div>
      <div class="terminal-controls">
        <button class="control-dot close" id="term-close-btn" title="Close"></button>
        <button class="control-dot minimize" id="term-min-btn" title="Minimize"></button>
        <button class="control-dot maximize" id="term-max-btn" title="Toggle Size"></button>
      </div>
    </div>
    <div class="terminal-body" id="terminal-body">
      <div class="terminal-line system">[OK] SecOps Virtual Shell initialized.</div>
      <div class="terminal-line system">Type 'help' to display security operations tools.</div>
    </div>
    <div class="terminal-input-line">
      <span class="terminal-prompt">guest@7rootsec:~$</span>
      <input type="text" class="terminal-input" id="terminal-input" placeholder="Type a command..." autocomplete="off" spellcheck="false">
    </div>
  `;

  const termTrigger = document.createElement('div');
  termTrigger.className = 'terminal-trigger';
  termTrigger.id = 'terminal-trigger';
  termTrigger.innerHTML = `<i class="fas fa-terminal" style="font-size: 1.25rem;"></i>`;

  document.body.appendChild(termContainer);
  document.body.appendChild(termTrigger);

  const term = document.getElementById('cyber-terminal');
  const trigger = document.getElementById('terminal-trigger');
  const input = document.getElementById('terminal-input');
  const body = document.getElementById('terminal-body');
  
  trigger.addEventListener('click', () => {
    term.classList.remove('minimized');
    trigger.classList.add('active');
    input.focus();
  });

  document.getElementById('term-close-btn').addEventListener('click', () => {
    term.classList.add('minimized');
    trigger.classList.remove('active');
  });

  document.getElementById('term-min-btn').addEventListener('click', () => {
    term.classList.add('minimized');
    trigger.classList.remove('active');
  });

  let isExpanded = false;
  document.getElementById('term-max-btn').addEventListener('click', () => {
    if (!isExpanded) {
      term.style.width = '700px';
      term.style.height = '480px';
      isExpanded = true;
    } else {
      term.style.width = '';
      term.style.height = '';
      isExpanded = false;
    }
  });

  const header = document.getElementById('terminal-header');
  let isDragging = false;
  let offsetX = 0;
  let offsetY = 0;

  header.addEventListener('mousedown', (e) => {
    if (e.target.classList.contains('control-dot')) return;
    isDragging = true;
    offsetX = e.clientX - term.offsetLeft;
    offsetY = e.clientY - term.offsetTop;
    header.style.cursor = 'grabbing';
  });

  document.addEventListener('mousemove', (e) => {
    if (!isDragging) return;
    
    let x = e.clientX - offsetX;
    let y = e.clientY - offsetY;

    const maxX = window.innerWidth - term.offsetWidth - 10;
    const maxY = window.innerHeight - term.offsetHeight - 10;

    x = Math.max(10, Math.min(x, maxX));
    y = Math.max(10, Math.min(y, maxY));

    term.style.left = `${x}px`;
    term.style.top = `${y}px`;
    term.style.right = 'auto';
    term.style.bottom = 'auto';
  });

  document.addEventListener('mouseup', () => {
    isDragging = false;
    header.style.cursor = '';
  });

  header.addEventListener('touchstart', (e) => {
    if (e.target.classList.contains('control-dot')) return;
    const touch = e.touches[0];
    isDragging = true;
    offsetX = touch.clientX - term.offsetLeft;
    offsetY = touch.clientY - term.offsetTop;
  });

  document.addEventListener('touchmove', (e) => {
    if (!isDragging) return;
    const touch = e.touches[0];
    let x = touch.clientX - offsetX;
    let y = touch.clientY - offsetY;

    const maxX = window.innerWidth - term.offsetWidth - 10;
    const maxY = window.innerHeight - term.offsetHeight - 10;

    x = Math.max(10, Math.min(x, maxX));
    y = Math.max(10, Math.min(y, maxY));

    term.style.left = `${x}px`;
    term.style.top = `${y}px`;
    term.style.right = 'auto';
    term.style.bottom = 'auto';
  });

  document.addEventListener('touchend', () => {
    isDragging = false;
  });

  // ----------------------------------------------------
  // 9. SHELL COMMAND INTERPRETER LOGIC
  // ----------------------------------------------------
  function addTermLine(text, type = '') {
    const line = document.createElement('div');
    line.className = `terminal-line ${type}`;
    line.textContent = text;
    body.appendChild(line);
    body.scrollTop = body.scrollHeight;
  }

  const fallbackPosts = [
    "2026-05-24: IoT Botnet Analysis & C2 Infrastructure Study",
    "2025-12-02: Fileless Malware Internals & Process Hollowing Techniques",
    "2025-11-24: HackTheBox Mirage - Windows Active Directory Hard exploit",
    "2025-09-27: HackTheBox Puppy - Windows Privilege Escalation writeup",
    "2025-12-04: TryHackMe Ignite Writeup - Drupal Remote Code Execution",
    "2025-12-01: TryHackMe Printer Hacking 101 - RAW socket print poisoning",
    "2020-01-07: TryHackMe Mr. Robot writeup - Linux kernel privilege escalation"
  ];

  function runCommand(cmdText) {
    const trimmed = cmdText.trim();
    if (!trimmed) return;

    addTermLine(`guest@7rootsec:~$ ${trimmed}`, 'command');

    const parts = trimmed.split(' ');
    const command = parts[0].toLowerCase();
    const args = parts.slice(1);

    switch (command) {
      case 'help':
        addTermLine('Available tools & actions:', 'success');
        addTermLine('  about       - Displays details about 7rootsec experience');
        addTermLine('  posts       - Lists published blog writeups');
        addTermLine('  status      - Checks simulated firewall logs and system metrics');
        addTermLine('  matrix      - Toggle high-performance Matrix code rain waterfall');
        addTermLine('  nodes       - Toggle interactive network nodes floating mesh');
        addTermLine('  crt         - Toggle retro scanlines monitor layer');
        addTermLine('  hack [ip]   - Run a simulated SecOps penetration sequence on target');
        addTermLine('  clear       - Clears shell history');
        addTermLine('  help        - Displays this instructions grid');
        break;

      case 'clear':
        body.innerHTML = '';
        break;

      case 'about':
        addTermLine('=========================================', 'success');
        addTermLine('7rootsec - Offensive Security Specialist');
        addTermLine('=========================================', 'success');
        addTermLine('Over 4 years of expertise in application security, infrastructure protection, IoT analysis, and Active Directory exploitation.');
        addTermLine('Proficiencies: Custom exploit construction (Python/C), binary reverse engineering, system call hooking, proxy evasion, and traffic inspection.');
        break;

      case 'posts':
        addTermLine('Listing published writeups...', 'success');
        
        const foundPosts = [];
        document.querySelectorAll('.post-preview, h1 a, h2 a').forEach(el => {
          const txt = el.textContent.trim();
          if (txt && txt.length > 5 && !txt.includes('7root') && !txt.includes('Home') && !txt.includes('Categories') && !txt.includes('Tags') && !txt.includes('About')) {
            foundPosts.push(txt);
          }
        });

        const finalPosts = foundPosts.length > 0 ? foundPosts : fallbackPosts;
        finalPosts.forEach((post, i) => {
          addTermLine(` [${i+1}] ${post}`);
        });
        break;

      case 'status':
        addTermLine('--- SYSTEM METRICS ---', 'success');
        addTermLine(`SYSTEM STATUS: HEALTHY`);
        addTermLine(`FIREWALL LOGS: ACTIVE`);
        addTermLine(`ACTIVE PORTS: 22/tcp (ssh), 80/tcp (http), 443/tcp (https)`);
        addTermLine(`CPU LOAD: ${(Math.random() * 8 + 1).toFixed(2)}%`);
        addTermLine(`MEM USAGE: ${(Math.random() * 20 + 40).toFixed(1)}%`);
        addTermLine('---------------------', 'success');
        break;

      case 'matrix':
        const nextMode = canvasMode === 'matrix' ? 'none' : 'matrix';
        startCanvasEffect(nextMode);
        localStorage.setItem('canvas-mode', nextMode);
        addTermLine(`Matrix Rain Canvas: ${nextMode === 'matrix' ? 'ENABLED' : 'DISABLED'}`, 'success');
        break;

      case 'nodes':
        const nextModeNodes = canvasMode === 'nodes' ? 'none' : 'nodes';
        startCanvasEffect(nextModeNodes);
        localStorage.setItem('canvas-mode', nextModeNodes);
        addTermLine(`Particle Nodes Canvas: ${nextModeNodes === 'nodes' ? 'ENABLED' : 'DISABLED'}`, 'success');
        break;

      case 'crt':
        toggleCRT();
        const crtActive = document.body.classList.contains('crt-active');
        addTermLine(`Retro CRT Monitor: ${crtActive ? 'ENABLED' : 'DISABLED'}`, 'success');
        break;

      case 'hack':
        if (args.length === 0) {
          addTermLine('Error: Specify a target IP or domain. E.g. hack 192.168.1.1', 'error');
        } else {
          const target = args[0];
          addTermLine(`[+] Launching security probe on target: ${target}...`, 'system');
          
          let steps = [
            `[*] Resolving ${target} routing path... OK`,
            `[*] Initiating stealth SYN scan on ports: 21, 22, 80, 443, 445, 8080...`,
            `[!] Alert: Port 445 (Microsoft-DS) detected vulnerable to MS17-010!`,
            `[*] Constructing exploit payload buffer...`,
            `[*] Sending Ring 0 kernel shellcode...`,
            `[+] EXPLOIT EXECUTED. Spawning NT AUTHORITY\\SYSTEM shell!`,
            `======================================================`,
            `ACCESS GRANTED TO TARGET CONTAINER [${target}]`,
            `======================================================`
          ];

          input.disabled = true;
          let stepIndex = 0;

          function runHackStep() {
            if (stepIndex < steps.length) {
              const isSuccess = steps[stepIndex].includes('GRANT') || steps[stepIndex].includes('EXPLOIT EXECUTED');
              const isAlert = steps[stepIndex].includes('detected vulnerable');
              addTermLine(steps[stepIndex], isSuccess ? 'success' : (isAlert ? 'error' : ''));
              stepIndex++;
              setTimeout(runHackStep, 700);
            } else {
              input.disabled = false;
              input.focus();
            }
          }
          
          setTimeout(runHackStep, 700);
        }
        break;

      default:
        addTermLine(`Command not found: '${command}'. Type 'help' for instructions.`, 'error');
        break;
    }
  }

  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const val = input.value;
      input.value = '';
      runCommand(val);
    }
  });

  document.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.key === '`') {
      e.preventDefault();
      if (term.classList.contains('minimized')) {
        term.classList.remove('minimized');
        trigger.classList.add('active');
        input.focus();
      } else {
        term.classList.add('minimized');
        trigger.classList.remove('active');
      }
    }
  });
});
