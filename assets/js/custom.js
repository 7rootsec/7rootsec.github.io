/**
 * 7rootsec Cybersecurity Blog Custom Script
 * Adds interactive retro terminal, Matrix rain, typewriter subtitle,
 * and dynamic cybersecurity widgets.
 */

document.addEventListener('DOMContentLoaded', () => {
  // ----------------------------------------------------
  // 1. DOM SELECTORS & INITIALIZATION
  // ----------------------------------------------------
  const sidebar = document.getElementById('sidebar');
  const siteTitle = document.querySelector('.site-title a') || document.querySelector('.site-title');
  const siteSubtitle = document.querySelector('.site-subtitle');

  // Apply CSS glitch class to site title
  if (siteTitle) {
    siteTitle.classList.add('glitch-hover');
  }

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

    // Create container for typing text and cursor
    siteSubtitle.innerHTML = '<span class="typewriter-text"></span><span class="typewriter-cursor"></span>';
    const textSpan = siteSubtitle.querySelector('.typewriter-text');

    function typeEffect() {
      const currentPhrase = phrases[phraseIndex];
      
      if (isDeleting) {
        textSpan.textContent = currentPhrase.substring(0, charIndex - 1);
        charIndex--;
        delay = 40; // delete faster
      } else {
        textSpan.textContent = currentPhrase.substring(0, charIndex + 1);
        charIndex++;
        delay = 80; // normal typing speed
      }

      if (!isDeleting && charIndex === currentPhrase.length) {
        isDeleting = true;
        delay = 2000; // pause at full text
      } else if (isDeleting && charIndex === 0) {
        isDeleting = false;
        phraseIndex = (phraseIndex + 1) % phrases.length;
        delay = 500; // pause before typing next
      }

      setTimeout(typeEffect, delay);
    }

    // Start typewriter
    setTimeout(typeEffect, 1000);
  }

  // ----------------------------------------------------
  // 3. SECURE CONNECTION SIDEBAR WIDGET
  // ----------------------------------------------------
  if (sidebar) {
    // Generate a random-looking IP address
    const randomIP = `10.24.${Math.floor(Math.random() * 254) + 1}.${Math.floor(Math.random() * 254) + 1}`;
    
    // Create widget elements
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
      <div class="widget-row" style="margin-top: 8px; border-top: 1px dashed rgba(0, 255, 102, 0.15); padding-top: 6px; justify-content: space-around;">
        <a href="#" id="widget-matrix-toggle" style="color: #00ff66; text-decoration: none; border-bottom: 1px dotted; font-size: 0.68rem;">Matrix: OFF</a>
        <a href="#" id="widget-crt-toggle" style="color: #00e5ff; text-decoration: none; border-bottom: 1px dotted; font-size: 0.68rem;">CRT: OFF</a>
      </div>
    `;

    // Insert into sidebar after the profile block
    const profileWrapper = sidebar.querySelector('.profile-wrapper') || sidebar.firstElementChild;
    if (profileWrapper) {
      profileWrapper.parentNode.insertBefore(widget, profileWrapper.nextSibling);
    } else {
      sidebar.appendChild(widget);
    }

    // Uptime session counter
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
  // 4. MATRIX RAIN EFFECT CANVAS
  // ----------------------------------------------------
  const canvas = document.createElement('canvas');
  canvas.id = 'matrix-canvas';
  document.body.appendChild(canvas);
  const ctx = canvas.getContext('2d');

  let columns = 0;
  let drops = [];
  const chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ01010101/*-+=%';
  const fontSize = 14;
  let matrixAnimationId = null;

  function resizeCanvas() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    columns = Math.floor(canvas.width / fontSize);
    drops = Array(columns).fill(1);
  }

  function drawMatrix() {
    ctx.fillStyle = 'rgba(13, 15, 18, 0.08)'; // trails
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    ctx.fillStyle = '#00ff66';
    ctx.font = `${fontSize}px 'Share Tech Mono', monospace`;

    for (let i = 0; i < drops.length; i++) {
      const text = chars.charAt(Math.floor(Math.random() * chars.length));
      ctx.fillText(text, i * fontSize, drops[i] * fontSize);

      if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
        drops[i] = 0;
      }
      drops[i]++;
    }
    matrixAnimationId = requestAnimationFrame(drawMatrix);
  }

  function startMatrix() {
    if (!matrixAnimationId) {
      resizeCanvas();
      drawMatrix();
      document.body.classList.add('matrix-active');
      updateMatrixToggleText(true);
    }
  }

  function stopMatrix() {
    if (matrixAnimationId) {
      cancelAnimationFrame(matrixAnimationId);
      matrixAnimationId = null;
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      document.body.classList.remove('matrix-active');
      updateMatrixToggleText(false);
    }
  }

  function toggleMatrix() {
    const isActive = document.body.classList.contains('matrix-active');
    if (isActive) {
      stopMatrix();
      localStorage.setItem('matrix-active', 'false');
    } else {
      startMatrix();
      localStorage.setItem('matrix-active', 'true');
    }
  }

  function updateMatrixToggleText(active) {
    const toggleLink = document.getElementById('widget-matrix-toggle');
    if (toggleLink) {
      toggleLink.textContent = active ? 'Matrix: ON' : 'Matrix: OFF';
      toggleLink.style.color = active ? '#00ff66' : 'rgba(0, 255, 102, 0.6)';
    }
  }

  window.addEventListener('resize', () => {
    if (matrixAnimationId) {
      resizeCanvas();
    }
  });

  // Load user matrix preference
  const localMatrixPref = localStorage.getItem('matrix-active');
  if (localMatrixPref === 'true') {
    startMatrix();
  }

  // Bind widget toggle click
  document.addEventListener('click', (e) => {
    if (e.target && e.target.id === 'widget-matrix-toggle') {
      e.preventDefault();
      toggleMatrix();
    }
  });

  // ----------------------------------------------------
  // 5. CRT RETRO SCANLINES
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

  // Load user CRT preference
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
  // 6. INTERACTIVE FLOATING TERMINAL OVERLAY
  // ----------------------------------------------------
  // Construct terminal elements dynamically
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
  
  // Open terminal
  trigger.addEventListener('click', () => {
    term.classList.remove('minimized');
    trigger.classList.add('active');
    input.focus();
  });

  // Close / Minimize terminal
  document.getElementById('term-close-btn').addEventListener('click', () => {
    term.classList.add('minimized');
    trigger.classList.remove('active');
  });

  document.getElementById('term-min-btn').addEventListener('click', () => {
    term.classList.add('minimized');
    trigger.classList.remove('active');
  });

  // Expand / Maximize size
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

  // Terminal drag functionality
  const header = document.getElementById('terminal-header');
  let isDragging = false;
  let offsetX = 0;
  let offsetY = 0;

  header.addEventListener('mousedown', (e) => {
    if (e.target.classList.contains('control-dot')) return; // ignore control button clicks
    isDragging = true;
    offsetX = e.clientX - term.offsetLeft;
    offsetY = e.clientY - term.offsetTop;
    header.style.cursor = 'grabbing';
  });

  document.addEventListener('mousemove', (e) => {
    if (!isDragging) return;
    
    let x = e.clientX - offsetX;
    let y = e.clientY - offsetY;

    // Viewport constraints
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

  // Handle touch events for mobile draggability
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
  // 7. SHELL COMMAND INTERPRETER LOGIC
  // ----------------------------------------------------
  function addTermLine(text, type = '') {
    const line = document.createElement('div');
    line.className = `terminal-line ${type}`;
    line.textContent = text;
    body.appendChild(line);
    body.scrollTop = body.scrollHeight;
  }

  // Preloaded posts fallback list
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

    // Print command entered
    addTermLine(`guest@7rootsec:~$ ${trimmed}`, 'command');

    const parts = trimmed.split(' ');
    const command = parts[0].toLowerCase();
    const args = parts.slice(1);

    switch (command) {
      case 'help':
        addTermLine('Available tools & actions:', 'success');
        addTermLine('  about       - Displays information about 7rootsec security experience');
        addTermLine('  posts       - Lists published blog writeups');
        addTermLine('  status      - Checks simulated firewall logs and system metrics');
        addTermLine('  matrix      - Toggle high-performance Matrix code rain waterfall');
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
        
        // Scan the active site DOM for posts if available, fallback otherwise
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
        toggleMatrix();
        const matrixActive = document.body.classList.contains('matrix-active');
        addTermLine(`Matrix Rain Canvas: ${matrixActive ? 'ENABLED' : 'DISABLED'}`, 'success');
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

          input.disabled = true; // disable input while hacking
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

  // Handle enter key inside input
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const val = input.value;
      input.value = '';
      runCommand(val);
    }
  });

  // Shortkey toggle (Ctrl + ` or Ctrl + ~)
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
