/**
 * ScamLens - Mobile-First Scam Link & QR Scanner Prototype
 * Full Pipeline & Local Heuristic Engine (9 Rules)
 * Pure Vanilla JavaScript (No backend, no frameworks)
 */

document.addEventListener('DOMContentLoaded', () => {
  // --- State ---
  let currentStep = 1;
  const totalSteps = 5;
  let scannedUrl = '';
  let scanTimer = null;
  let analysisResult = null;

  // --- Target Brands for Typosquatting (Levenshtein Distance Check) ---
  const TARGET_BRANDS = [
    'paypal', 'google', 'apple', 'amazon', 'netflix',
    'microsoft', 'chase', 'bankofamerica', 'facebook',
    'instagram', 'whatsapp', 'wellsfargo', 'ebay', 'twitter', 'binance', 'coinbase'
  ];

  // --- Suspicious TLDs (Abuse / Disposable) ---
  const SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
    '.work', '.click', '.loan', '.buzz', '.fit', '.date', '.kim', '.rest'
  ];

  // --- Known URL Shorteners ---
  const KNOWN_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'cutt.ly',
    'rb.gy', 'ow.ly', 'buff.ly', 'goo.gl', 'trib.al'
  ];

  // --- Scam Keywords (Urgency, Harvesting, Financial Lures) ---
  const SCAM_KEYWORDS = [
    'free', 'prize', 'login', 'verify', 'lottery', 'urgent',
    'otp', 'banking', 'claim', 'winner', 'bonus', 'suspended',
    're-activate', 'validate', 'security-update', 'giftcard'
  ];

  // --- DOM Elements ---
  const screens = {
    1: document.getElementById('screen-1'),
    2: document.getElementById('screen-2'),
    3: document.getElementById('screen-3'),
    4: document.getElementById('screen-4'),
    5: document.getElementById('screen-5')
  };

  const currentStepNum = document.getElementById('current-step-num');
  const progressFill = document.getElementById('progress-fill');
  const progressBar = document.getElementById('progress-bar');

  // Screen 1 Elements
  const btnStart = document.getElementById('btn-start');

  // Screen 2 Elements
  const linkInput = document.getElementById('link-input');
  const btnClear = document.getElementById('btn-clear');
  const inputError = document.getElementById('input-error');
  const btnUploadQr = document.getElementById('btn-upload-qr');
  const qrStatusHint = document.getElementById('qr-status-hint');
  const btnCheck = document.getElementById('btn-check');
  const sampleButtons = document.querySelectorAll('.tag-btn');

  // Screen 3 Elements
  const scanningUrlDisplay = document.getElementById('scanning-url-display');
  const pipelineCheckItems = [
    document.getElementById('chk-pipe-1'),
    document.getElementById('chk-pipe-2'),
    document.getElementById('chk-pipe-3'),
    document.getElementById('chk-pipe-4'),
    document.getElementById('chk-pipe-5'),
    document.getElementById('chk-pipe-6')
  ];

  // Screen 4 Elements
  const resultBadgeCard = document.getElementById('result-badge-card');
  const badgeEmoji = document.getElementById('badge-emoji');
  const resultHeading = document.getElementById('screen-4-title');
  const riskScoreBadge = document.getElementById('risk-score-badge');
  const resultReason = document.getElementById('result-reason');
  const resultUrlDisplay = document.getElementById('result-url-display');
  const redirectInfoCard = document.getElementById('redirect-info-card');
  const redirectDetail = document.getElementById('redirect-detail');
  const heuristicsList = document.getElementById('heuristics-list');
  const intelSafebrowsing = document.getElementById('intel-safebrowsing');
  const intelVirustotal = document.getElementById('intel-virustotal');
  const intelDomainAge = document.getElementById('intel-domain-age');
  const intelRegistrar = document.getElementById('intel-registrar');
  const previewScreenMock = document.getElementById('preview-screen-mock');
  const previewMockIcon = document.getElementById('preview-mock-icon');
  const previewMockTag = document.getElementById('preview-mock-tag');
  const previewTitle = document.getElementById('preview-title');
  const previewSnippet = document.getElementById('preview-snippet');
  const previewTargetUrl = document.getElementById('preview-target-url');
  const adviceIcon = document.getElementById('advice-icon');
  const adviceText = document.getElementById('advice-text');
  const btnToFinal = document.getElementById('btn-to-final');

  // Tabs on Screen 4
  const tabs = {
    heuristics: document.getElementById('tab-heuristics'),
    intel: document.getElementById('tab-intel'),
    preview: document.getElementById('tab-preview')
  };
  const panes = {
    heuristics: document.getElementById('pane-heuristics'),
    intel: document.getElementById('pane-intel'),
    preview: document.getElementById('pane-preview')
  };

  // Screen 5 Elements
  const btnRestart = document.getElementById('btn-restart');

  // --- Step Navigation Function ---
  function goToStep(step) {
    if (step < 1 || step > totalSteps) return;

    Object.values(screens).forEach(screen => {
      screen.classList.remove('active');
    });

    screens[step].classList.add('active');
    currentStep = step;

    // Update Progress
    currentStepNum.textContent = step;
    const progressPercent = (step / totalSteps) * 100;
    progressFill.style.width = `${progressPercent}%`;
    progressBar.setAttribute('aria-valuenow', progressPercent);

    window.scrollTo({ top: 0, behavior: 'smooth' });

    if (step === 2) {
      setTimeout(() => linkInput.focus(), 100);
    } else if (step === 3) {
      startScanningProcess();
    }
  }

  // --- Screen 1: Start Button ---
  btnStart.addEventListener('click', () => {
    goToStep(2);
  });

  // --- Screen 2: Input Handling ---
  function toggleClearButton() {
    if (linkInput.value.trim().length > 0) {
      btnClear.classList.remove('hidden');
    } else {
      btnClear.classList.add('hidden');
    }
  }

  function clearInput() {
    linkInput.value = '';
    btnClear.classList.add('hidden');
    clearInputError();
    linkInput.focus();
  }

  function showInputError(message) {
    linkInput.classList.add('input-has-error');
    inputError.textContent = message;
    inputError.classList.remove('hidden');
    linkInput.setAttribute('aria-invalid', 'true');
    linkInput.focus();
  }

  function clearInputError() {
    linkInput.classList.remove('input-has-error');
    inputError.classList.add('hidden');
    linkInput.removeAttribute('aria-invalid');
  }

  linkInput.addEventListener('input', () => {
    toggleClearButton();
    if (linkInput.value.trim().length > 0) {
      clearInputError();
    }
  });

  btnClear.addEventListener('click', clearInput);

  linkInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleCheckSubmission();
    }
  });

  // Sample Buttons Click
  sampleButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const sample = btn.getAttribute('data-sample');
      linkInput.value = sample;
      toggleClearButton();
      clearInputError();
      linkInput.focus();
    });
  });

  // Mock QR Upload
  btnUploadQr.addEventListener('click', () => {
    const mockQrSamples = [
      'https://paypa1-security.xyz/login',
      'http://192.241.168.45/account-update',
      'https://bit.ly/claim-gift-2026',
      'http://verify-free-prize-login.net'
    ];
    const picked = mockQrSamples[Math.floor(Math.random() * mockQrSamples.length)];
    linkInput.value = picked;
    toggleClearButton();
    clearInputError();

    qrStatusHint.textContent = `✨ Simulated QR Code read: "${picked}"`;
    qrStatusHint.style.color = '#15803D';
    qrStatusHint.style.fontWeight = '600';

    setTimeout(() => {
      qrStatusHint.textContent = 'Have a photo of a QR code? Tap above to simulate scanning.';
      qrStatusHint.style.color = '';
      qrStatusHint.style.fontWeight = '';
    }, 4000);
  });

  function handleCheckSubmission() {
    const rawVal = linkInput.value.trim();

    if (!rawVal) {
      showInputError('⚠️ Please enter or paste a web address first so we can check it.');
      return;
    }

    scannedUrl = rawVal;
    goToStep(3);
  }

  btnCheck.addEventListener('click', handleCheckSubmission);

  // --- Levenshtein Distance Algorithm (Self-Implemented, No Libraries) ---
  function computeLevenshteinDistance(a, b) {
    const dp = Array.from({ length: b.length + 1 }, () => new Array(a.length + 1).fill(0));

    for (let i = 0; i <= b.length; i++) dp[i][0] = i;
    for (let j = 0; j <= a.length; j++) dp[0][j] = j;

    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        if (b.charAt(i - 1) === a.charAt(j - 1)) {
          dp[i][j] = dp[i - 1][j - 1];
        } else {
          dp[i][j] = Math.min(
            dp[i - 1][j - 1] + 1, // substitution
            dp[i][j - 1] + 1,     // insertion
            dp[i - 1][j] + 1      // deletion
          );
        }
      }
    }
    return dp[b.length][a.length];
  }

  // --- Parsing URL Helper ---
  function parseUrlDetails(rawUrl) {
    let normalized = rawUrl.trim();
    if (!normalized.startsWith('http://') && !normalized.startsWith('https://')) {
      normalized = 'https://' + normalized;
    }

    let urlObj;
    try {
      urlObj = new URL(normalized);
    } catch {
      // Fallback manual parse for tricky/spoofed URLs
      const hostMatch = normalized.match(/^(?:https?:\/\/)?([^/?#]+)/i);
      const host = hostMatch ? hostMatch[1] : rawUrl;
      urlObj = {
        hostname: host,
        pathname: normalized.replace(/^(?:https?:\/\/)?[^/?#]+/i, ''),
        search: '',
        protocol: rawUrl.startsWith('http://') ? 'http:' : 'https:'
      };
    }

    return {
      raw: rawUrl,
      normalized,
      protocol: rawUrl.startsWith('http://') ? 'http:' : (rawUrl.startsWith('https://') ? 'https:' : 'unknown'),
      hostname: urlObj.hostname.toLowerCase(),
      pathname: urlObj.pathname.toLowerCase(),
      fullLower: rawUrl.toLowerCase()
    };
  }

  // --- Local Heuristic Engine: 9 Rules (Section 5.2 of Report) ---
  function runLocalHeuristicEngine(parsed) {
    const rules = [];
    let riskScore = 0;

    // Rule 1: Scam Keyword Matching
    const foundKeywords = SCAM_KEYWORDS.filter(kw => parsed.fullLower.includes(kw));
    if (foundKeywords.length > 0) {
      const pts = Math.min(45, foundKeywords.length * 25);
      riskScore += pts;
      rules.push({
        id: 'keywords',
        name: 'Scam & Urgency Keywords',
        flagged: true,
        points: pts,
        detail: `Found high-risk keywords: "${foundKeywords.slice(0, 3).join('", "')}"`
      });
    } else {
      rules.push({
        id: 'keywords',
        name: 'Scam & Urgency Keywords',
        flagged: false,
        points: 0,
        detail: 'No common scam or urgency lure words detected.'
      });
    }

    // Rule 2: Suspicious TLD Detection
    const matchedTld = SUSPICIOUS_TLDS.find(tld => parsed.hostname.endsWith(tld));
    if (matchedTld) {
      riskScore += 25;
      rules.push({
        id: 'tld',
        name: 'Suspicious Domain Extension (TLD)',
        flagged: true,
        points: 25,
        detail: `Uses "${matchedTld}" (frequently abused in disposable phishing).`
      });
    } else {
      rules.push({
        id: 'tld',
        name: 'Domain Extension (TLD)',
        flagged: false,
        points: 0,
        detail: 'Domain extension is standard and established.'
      });
    }

    // Rule 3: Raw IP Address Detection
    const isIpHost = /^(\d{1,3}\.){3}\d{1,3}(:\d+)?$/.test(parsed.hostname);
    if (isIpHost) {
      riskScore += 35;
      rules.push({
        id: 'raw_ip',
        name: 'Raw IP Address Hostname',
        flagged: true,
        points: 35,
        detail: `Direct IP (${parsed.hostname}) used instead of a verified domain name.`
      });
    } else {
      rules.push({
        id: 'raw_ip',
        name: 'Domain Name vs IP',
        flagged: false,
        points: 0,
        detail: 'Uses standard alphanumeric domain name.'
      });
    }

    // Rule 4: Missing HTTPS Encryption
    const isHttpOnly = parsed.fullLower.includes('http://') && !parsed.fullLower.includes('https://');
    if (isHttpOnly) {
      riskScore += 25;
      rules.push({
        id: 'https',
        name: 'Connection Encryption',
        flagged: true,
        points: 25,
        detail: 'Uses unshielded "http://" without modern HTTPS encryption.'
      });
    } else {
      rules.push({
        id: 'https',
        name: 'Connection Encryption',
        flagged: false,
        points: 0,
        detail: 'Protected with modern HTTPS lock.'
      });
    }

    // Rule 5: URL Spoofing via '@' Symbol
    if (parsed.raw.includes('@')) {
      riskScore += 40;
      rules.push({
        id: 'at_trick',
        name: 'URL "@" Spoofing Trick',
        flagged: true,
        points: 40,
        detail: 'Contains "@" symbol used to disguise the real destination.'
      });
    } else {
      rules.push({
        id: 'at_trick',
        name: 'URL Structure Authenticity',
        flagged: false,
        points: 0,
        detail: 'No "@" userinfo spoofing detected.'
      });
    }

    // Rule 6: Excessive Subdomain Nesting
    const hostParts = parsed.hostname.split('.');
    if (hostParts.length >= 4 && !isIpHost) {
      riskScore += 20;
      rules.push({
        id: 'subdomains',
        name: 'Excessive Subdomains',
        flagged: true,
        points: 20,
        detail: `Stacked ${hostParts.length - 2} subdomains to hide real domain on mobile.`
      });
    } else {
      rules.push({
        id: 'subdomains',
        name: 'Subdomain Structure',
        flagged: false,
        points: 0,
        detail: 'Subdomain structure is normal and readable.'
      });
    }

    // Rule 7: Brand Typosquatting via Levenshtein Distance
    let typosquatMatch = null;
    if (!isIpHost) {
      const domainLabels = parsed.hostname.split('.');
      for (const label of domainLabels) {
        if (label.length >= 4) {
          for (const brand of TARGET_BRANDS) {
            if (label !== brand) {
              const dist = computeLevenshteinDistance(label, brand);
              if (dist >= 1 && dist <= 2) {
                typosquatMatch = { label, brand, dist };
                break;
              }
            }
          }
        }
        if (typosquatMatch) break;
      }
    }

    if (typosquatMatch) {
      riskScore += 40;
      rules.push({
        id: 'typosquat',
        name: 'Brand Typosquatting',
        flagged: true,
        points: 40,
        detail: `Deceptive look-alike: "${typosquatMatch.label}" mimics official "${typosquatMatch.brand}".`
      });
    } else {
      rules.push({
        id: 'typosquat',
        name: 'Brand Impersonation',
        flagged: false,
        points: 0,
        detail: 'No brand name misspelling or look-alike found.'
      });
    }

    // Rule 8: Known URL Shortener Detection
    const isShortener = KNOWN_SHORTENERS.some(sh => parsed.hostname === sh || parsed.hostname.endsWith('.' + sh));
    if (isShortener) {
      riskScore += 15;
      rules.push({
        id: 'shortener',
        name: 'URL Shortener (Hides Target)',
        flagged: true,
        points: 15,
        detail: `Known shortener (${parsed.hostname}) concealing the destination.`
      });
    } else {
      rules.push({
        id: 'shortener',
        name: 'Direct Destination',
        flagged: false,
        points: 0,
        detail: 'Direct full URL provided, not hidden behind a shortener.'
      });
    }

    // Rule 9: Abnormal URL Length & Excessive Hyphens
    const hyphenCount = (parsed.hostname.match(/-/g) || []).length;
    const isTooLong = parsed.raw.length > 75;
    const hasManyHyphens = hyphenCount >= 3;

    if (isTooLong || hasManyHyphens) {
      const pts = (isTooLong ? 10 : 0) + (hasManyHyphens ? 15 : 0);
      riskScore += pts;
      rules.push({
        id: 'length_hyphens',
        name: 'Abnormal Length / Hyphens',
        flagged: true,
        points: pts,
        detail: `${isTooLong ? 'Unusually long URL (>75 chars). ' : ''}${hasManyHyphens ? `${hyphenCount} hyphens in domain name.` : ''}`
      });
    } else {
      rules.push({
        id: 'length_hyphens',
        name: 'URL Formatting & Length',
        flagged: false,
        points: 0,
        detail: 'URL length and hyphen count are within normal limits.'
      });
    }

    // Cap Risk Score at 100
    riskScore = Math.min(100, riskScore);

    return {
      riskScore,
      rules,
      isShortener,
      foundKeywords,
      typosquatMatch,
      isHttpOnly,
      isIpHost,
      matchedTld
    };
  }

  // --- Threat Pipeline Simulation (Steps 3 to 6 of Report) ---
  function simulateFullPipeline(url) {
    const parsed = parseUrlDetails(url);
    const heuristics = runLocalHeuristicEngine(parsed);

    // 1. Redirect Tracer simulation
    let redirectChain = null;
    let finalUrl = parsed.raw;

    if (heuristics.isShortener) {
      if (parsed.fullLower.includes('gift') || parsed.fullLower.includes('bonus')) {
        finalUrl = 'http://claim-free-prize-bonus.com/login';
      } else {
        finalUrl = 'https://portal-update-service.org/verify';
      }
      redirectChain = {
        hops: 2,
        initial: parsed.raw,
        resolved: finalUrl
      };
      // If final URL brings new keywords, re-evaluate slightly
      if (finalUrl.includes('login') || finalUrl.includes('prize')) {
        heuristics.riskScore = Math.min(100, heuristics.riskScore + 30);
      }
    }

    // Determine Verdict based on Risk Score & rules
    let verdict = 'SAFE';
    let themeClass = 'theme-safe';
    let emoji = '✅';
    let plainReason = '';
    let advice = '';

    // Enforce prompt base rules:
    // If contains "free", "prize", "login", "verify" -> SCAM
    const hasPromptKeywords = ['free', 'prize', 'login', 'verify'].some(w => parsed.fullLower.includes(w) || finalUrl.toLowerCase().includes(w));

    if (heuristics.riskScore >= 50 || hasPromptKeywords || heuristics.typosquatMatch || heuristics.isIpHost) {
      verdict = 'SCAM';
      themeClass = 'theme-scam';
      emoji = '🚨';

      if (heuristics.typosquatMatch) {
        plainReason = `This link is a deceptive look-alike of official "${heuristics.typosquatMatch.brand}" created to fool you into handing over your account login.`;
      } else if (heuristics.isIpHost) {
        plainReason = 'This address uses a raw number code (IP address) instead of a real company website name, a classic hallmark of cyber scams.';
      } else if (hasPromptKeywords) {
        const kw = ['free', 'prize', 'login', 'verify'].find(w => parsed.fullLower.includes(w) || finalUrl.toLowerCase().includes(w));
        plainReason = `This link contains the word "${kw}", which scammers frequently use in fake messages to steal your passwords or money.`;
      } else {
        plainReason = 'Multiple high-risk warning signs were detected indicating this website was set up to steal personal information.';
      }

      advice = '🛑 Do not tap this link, do not download files, and never enter passwords or card numbers.';
    } else if (heuristics.riskScore >= 20 || (parsed.protocol === 'http:' && !parsed.fullLower.includes('https://'))) {
      verdict = 'SUSPICIOUS';
      themeClass = 'theme-suspicious';
      emoji = '⚠️';

      if (parsed.protocol === 'http:') {
        plainReason = 'This website does not have modern security protection ("https"), meaning information you send might not be private or safe.';
      } else if (heuristics.isShortener) {
        plainReason = 'This link is shortened, hiding where it really goes until it is already clicked.';
      } else {
        plainReason = 'This web address has unusual characteristics that require extra caution before opening.';
      }

      advice = '⚠️ Proceed with extreme care. Avoid entering sensitive passwords, banking credentials, or personal numbers.';
    } else {
      verdict = 'SAFE';
      themeClass = 'theme-safe';
      emoji = '✅';
      plainReason = 'We didn\'t find any common red flags, urgent trick words, or missing security locks in this web address.';
      advice = '👍 This link looks clean and standard. As always, verify that the website address matches what you expect.';
    }

    // Threat Intelligence Simulation
    let intel = {};
    if (verdict === 'SCAM') {
      intel = {
        safebrowsing: '⚠️ Flagged: Deceptive Site (Phishing)',
        virustotal: '14 / 72 Security Vendors Flagged Malicious',
        domainAge: 'Registered 3 days ago (Extremely New)',
        registrar: 'NameCheap (Privacy Guard Enabled)'
      };
    } else if (verdict === 'SUSPICIOUS') {
      intel = {
        safebrowsing: 'Neutral: No active blacklist yet',
        virustotal: '1 / 72 Vendors Flagged (Unrated/Insecure)',
        domainAge: 'Registered 42 days ago',
        registrar: 'Public Domain Registry Inc.'
      };
    } else {
      intel = {
        safebrowsing: '✅ Verified Safe: No threats detected',
        virustotal: '0 / 74 Security Vendors Clean',
        domainAge: 'Registered 14+ years ago (High Trust)',
        registrar: 'MarkMonitor Inc. / Verified Corporate'
      };
    }

    // Destination Preview Simulation
    let preview = {};
    if (verdict === 'SCAM') {
      preview = {
        icon: '🚨',
        tag: 'Blocked Preview',
        title: heuristics.typosquatMatch ? `${heuristics.typosquatMatch.brand.toUpperCase()} - Account Verification` : 'Login / Prize Claim Portal',
        snippet: 'Urgent notice: Claim your rewards or confirm your account immediately to prevent suspension.',
        target: finalUrl
      };
    } else if (verdict === 'SUSPICIOUS') {
      preview = {
        icon: '⚠️',
        tag: 'Unencrypted Site',
        title: 'Information Portal',
        snippet: 'Standard web page hosted without SSL encryption certificate.',
        target: finalUrl
      };
    } else {
      preview = {
        icon: '🛡️',
        tag: 'Verified Domain',
        title: parsed.hostname.toUpperCase() + ' - Official Portal',
        snippet: 'Secure, established website providing authentic corporate services.',
        target: finalUrl
      };
    }

    return {
      parsed,
      heuristics,
      redirectChain,
      verdict,
      themeClass,
      emoji,
      plainReason,
      advice,
      intel,
      preview
    };
  }

  // --- Screen 3: Scanning Process (6-Stage Pipeline Animation) ---
  function startScanningProcess() {
    scanningUrlDisplay.textContent = scannedUrl;

    // Reset pipeline checklist items
    pipelineCheckItems.forEach(item => {
      item.className = 'check-item';
      item.querySelector('.chk-icon').textContent = '⏳';
    });

    if (scanTimer) clearTimeout(scanTimer);

    // Run simulation
    analysisResult = simulateFullPipeline(scannedUrl);

    // Step 1: Active
    pipelineCheckItems[0].className = 'check-item active';

    // Timeline over 2.0 seconds
    setTimeout(() => {
      pipelineCheckItems[0].className = 'check-item done';
      pipelineCheckItems[0].querySelector('.chk-icon').textContent = '✅';
      pipelineCheckItems[1].className = 'check-item active';
    }, 350);

    setTimeout(() => {
      pipelineCheckItems[1].className = 'check-item done';
      pipelineCheckItems[1].querySelector('.chk-icon').textContent = '✅';
      pipelineCheckItems[2].className = 'check-item active';
    }, 700);

    setTimeout(() => {
      pipelineCheckItems[2].className = 'check-item done';
      pipelineCheckItems[2].querySelector('.chk-icon').textContent = '✅';
      pipelineCheckItems[3].className = 'check-item active';
    }, 1100);

    setTimeout(() => {
      pipelineCheckItems[3].className = 'check-item done';
      pipelineCheckItems[3].querySelector('.chk-icon').textContent = '✅';
      pipelineCheckItems[4].className = 'check-item active';
    }, 1450);

    setTimeout(() => {
      pipelineCheckItems[4].className = 'check-item done';
      pipelineCheckItems[4].querySelector('.chk-icon').textContent = '✅';
      pipelineCheckItems[5].className = 'check-item active';
    }, 1750);

    scanTimer = setTimeout(() => {
      pipelineCheckItems[5].className = 'check-item done';
      pipelineCheckItems[5].querySelector('.chk-icon').textContent = '✅';
      renderReportCard(analysisResult);
      goToStep(4);
    }, 2050);
  }

  // --- Screen 4: Render Interactive Report Card ---
  function renderReportCard(data) {
    // 1. Top Verdict Banner
    resultBadgeCard.className = `report-header-card ${data.themeClass}`;
    badgeEmoji.textContent = data.emoji;
    resultHeading.textContent = data.verdict;
    riskScoreBadge.textContent = `Risk: ${data.heuristics.riskScore}/100`;

    // 2. Reason & Inspected Link
    resultReason.textContent = data.plainReason;
    resultUrlDisplay.textContent = data.parsed.raw;

    // 3. Redirect Tracer info
    if (data.redirectChain) {
      redirectInfoCard.classList.remove('hidden');
      redirectDetail.innerHTML = `<strong>${data.redirectChain.initial}</strong><br>↳ Expanded to: <strong>${data.redirectChain.resolved}</strong>`;
    } else {
      redirectInfoCard.classList.add('hidden');
    }

    // 4. Render 9 Heuristics in Tab 1
    heuristicsList.innerHTML = '';
    data.heuristics.rules.forEach(rule => {
      const row = document.createElement('div');
      row.className = 'heuristic-row';

      const info = document.createElement('div');
      info.className = 'heuristic-info';

      const name = document.createElement('span');
      name.className = 'heuristic-name';
      name.textContent = rule.name;

      const desc = document.createElement('span');
      desc.className = 'heuristic-desc';
      desc.textContent = rule.detail;

      info.appendChild(name);
      info.appendChild(desc);

      const badge = document.createElement('span');
      badge.className = `h-badge ${rule.flagged ? 'flagged' : 'passed'}`;
      badge.textContent = rule.flagged ? `+${rule.points} Risk` : 'Passed';

      row.appendChild(info);
      row.appendChild(badge);
      heuristicsList.appendChild(row);
    });

    // 5. Threat Intel & WHOIS in Tab 2
    intelSafebrowsing.textContent = data.intel.safebrowsing;
    intelVirustotal.textContent = data.intel.virustotal;
    intelDomainAge.textContent = data.intel.domainAge;
    intelRegistrar.textContent = data.intel.registrar;

    // 6. Destination Preview in Tab 3
    previewMockIcon.textContent = data.preview.icon;
    previewMockTag.textContent = data.preview.tag;
    previewTitle.textContent = data.preview.title;
    previewSnippet.textContent = data.preview.snippet;
    previewTargetUrl.textContent = data.preview.target;

    // 7. Action Advice
    adviceIcon.textContent = data.verdict === 'SCAM' ? '🛑' : (data.verdict === 'SUSPICIOUS' ? '⚠️' : '💡');
    adviceText.textContent = data.advice;

    // Reset Tab Selection to Tab 1
    switchTab('heuristics');
  }

  // --- Tab Switching Logic on Screen 4 ---
  function switchTab(tabKey) {
    Object.keys(tabs).forEach(k => {
      const isSelected = k === tabKey;
      tabs[k].classList.toggle('active', isSelected);
      tabs[k].setAttribute('aria-selected', isSelected ? 'true' : 'false');
      panes[k].classList.toggle('active', isSelected);
      panes[k].hidden = !isSelected;
    });
  }

  tabs.heuristics.addEventListener('click', () => switchTab('heuristics'));
  tabs.intel.addEventListener('click', () => switchTab('intel'));
  tabs.preview.addEventListener('click', () => switchTab('preview'));

  btnToFinal.addEventListener('click', () => {
    goToStep(5);
  });

  // --- Screen 5: Final Screen & Check Another Link ---
  btnRestart.addEventListener('click', () => {
    clearInput();
    goToStep(2);
  });

  // Initial State
  goToStep(1);
});
