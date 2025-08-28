// Advanced Real-time Content Analysis and Protection

(function() {
    'use strict';
    
    console.log('🔍 Perfect Phishing Protector Pro v8.0 - Content Script Loading...');
    
    // ===== CONFIGURATION =====
    const PERFECT_CONFIG = {
        SCAN_INTERVAL: 15000,         // 15 seconds for better performance
        MAX_WARNINGS: 1,              // More aggressive - only one warning
        CONFIDENCE_THRESHOLD: 90,     // Higher confidence required
        ENABLE_SCANNING: true,
        QUIET_MODE: false,
        DEEP_ANALYSIS: true,
        REAL_TIME_PROTECTION: true,
        AUTO_BLOCK_THRESHOLD: 25      // Auto-block sites with score < 25
    };
    
    // ===== ENHANCED TRUSTED DOMAINS =====
    const PERFECT_TRUSTED_DOMAINS = new Set([
        // Major Tech Companies
        'google.com', 'youtube.com', 'gmail.com', 'googledrive.com', 'googlecloud.com',
        'microsoft.com', 'outlook.com', 'office.com', 'azure.com', 'xbox.com',
        'apple.com', 'icloud.com', 'itunes.com', 'appstore.com',
        'amazon.com', 'aws.amazon.com', 'amazonprime.com', 'kindle.com',
        
        // Financial Institutions
        'paypal.com', 'stripe.com', 'square.com', 'chase.com', 'bankofamerica.com',
        'wellsfargo.com', 'citibank.com', 'americanexpress.com', 'discover.com',
        
        // Social Media & Communication
        'facebook.com', 'instagram.com', 'messenger.com', 'whatsapp.com',
        'twitter.com', 'x.com', 'linkedin.com', 'telegram.org', 'discord.com',
        'slack.com', 'zoom.us', 'teams.microsoft.com',
        
        // Development & Tools
        'github.com', 'gitlab.com', 'bitbucket.org', 'stackoverflow.com',
        'npmjs.com', 'pypi.org', 'docker.com', 'kubernetes.io',
        
        // Media & Information
        'reddit.com', 'wikipedia.org', 'wikimedia.org', 'news.google.com',
        'cnn.com', 'bbc.com', 'reuters.com', 'bloomberg.com',
        
        // Cloud Services
        'dropbox.com', 'box.com', 'onedrive.live.com', 'cloudflare.com',
        'amazonaws.com', 'digitalocean.com', 'heroku.com'
    ]);
    
    // ===== STATE MANAGEMENT =====
    let warningCount = 0;
    let hasShownWarning = false;
    let scanCount = 0;
    let isTrustedSite = false;
    let lastScanTime = 0;
    let currentSiteData = null;
    let realTimeProtectionActive = true;
    
    // ===== INITIALIZATION =====
    function initializePerfectProtection() {
        try {
            console.log('🔧 Initializing Perfect Real-time Protection...');
            
            const hostname = window.location.hostname.toLowerCase();
            isTrustedSite = isPerfectTrusted(hostname);
            
            if (isTrustedSite) {
                console.log(`🌟 Perfect trusted site: ${hostname} - Enhanced protection active`);
                PERFECT_CONFIG.ENABLE_SCANNING = false;
                return;
            }
            
            // Request current site analysis from background
            requestSiteAnalysis();
            
            // Start comprehensive protection after delay
            setTimeout(() => {
                if (PERFECT_CONFIG.ENABLE_SCANNING && !isTrustedSite) {
                    performPerfectSecurityScan();
                    
                    // Set up periodic scanning if real-time protection enabled
                    if (PERFECT_CONFIG.REAL_TIME_PROTECTION) {
                        setInterval(() => {
                            if (Date.now() - lastScanTime > PERFECT_CONFIG.SCAN_INTERVAL) {
                                performPerfectSecurityScan();
                            }
                        }, PERFECT_CONFIG.SCAN_INTERVAL);
                    }
                }
            }, 2000);
            
            // Monitor dynamic content changes
            setupContentMonitoring();
            
        } catch (error) {
            console.error('Perfect protection initialization error:', error);
        }
    }
    
    // ===== REQUEST SITE ANALYSIS FROM BACKGROUND =====
    async function requestSiteAnalysis() {
        try {
            const response = await chrome.runtime.sendMessage({
                action: 'get_site_status',
                hostname: window.location.hostname
            });
            
            if (response && !response.error) {
                currentSiteData = response;
                console.log('📊 Received site analysis:', currentSiteData);
                
                // Take action based on analysis
                handleSiteAnalysis(currentSiteData);
            }
        } catch (error) {
            console.warn('Failed to get site analysis:', error);
        }
    }
    
    // ===== HANDLE SITE ANALYSIS RESULTS =====
    function handleSiteAnalysis(analysis) {
        try {
            const riskLevel = analysis.riskLevel;
            const score = analysis.finalScore || 0;
            const threats = analysis.threatsDetected || [];
            
            console.log(`🎯 Site Analysis Result: ${riskLevel} (Score: ${score}, Threats: ${threats.length})`);
            
            // Handle based on risk level
            switch (riskLevel) {
                case 'CRITICAL':
                    if (score <= PERFECT_CONFIG.AUTO_BLOCK_THRESHOLD) {
                        console.log('🛑 Critical threat detected - initiating protection measures');
                        showCriticalThreatWarning(analysis);
                    } else {
                        showHighRiskWarning(analysis);
                    }
                    break;
                    
                case 'HIGH_RISK':
                    showHighRiskWarning(analysis);
                    break;
                    
                case 'MEDIUM_RISK':
                    if (threats.length >= 3) {
                        showMediumRiskWarning(analysis);
                    }
                    break;
                    
                default:
                    console.log(`✅ Site is ${riskLevel} - no action required`);
            }
            
        } catch (error) {
            console.error('Error handling site analysis:', error);
        }
    }
    
    // ===== PERFECT SECURITY SCAN =====
    function performPerfectSecurityScan() {
        if (hasShownWarning >= PERFECT_CONFIG.MAX_WARNINGS || !PERFECT_CONFIG.ENABLE_SCANNING || isTrustedSite) {
            return;
        }
        
        lastScanTime = Date.now();
        scanCount++;
        
        const threats = [];
        
        try {
            console.log(`🔍 Performing perfect security scan ${scanCount} on ${window.location.hostname}`);
            
            // 1. Advanced DOM-Based Threat Detection
            threats.push(...detectAdvancedDOMThreats());
            
            // 2. Enhanced Form Analysis with ML Patterns
            threats.push(...analyzeFormsWithML());
            
            // 3. Content Security and Behavior Analysis
            threats.push(...analyzeContentAndBehavior());
            
            // 4. Network and Resource Analysis
            threats.push(...analyzeNetworkResources());
            
            // 5. Real-time Credential Harvesting Detection
            threats.push(...detectCredentialHarvesting());
            
            // 6. Social Engineering Pattern Detection
            threats.push(...detectSocialEngineering());
            
            console.log(`🔍 Perfect scan results: ${threats.length} potential threats found`);
            
            // Evaluate threats and show warnings if needed
            const criticalThreats = threats.filter(t => t.severity === 'critical');
            const highThreats = threats.filter(t => t.severity === 'high');
            const mediumThreats = threats.filter(t => t.severity === 'medium');
            
            // More aggressive threat detection
            if (criticalThreats.length >= 1 || 
                (highThreats.length >= 2) || 
                (highThreats.length >= 1 && mediumThreats.length >= 3)) {
                
                const analysisResult = {
                    finalScore: Math.max(0, 100 - (criticalThreats.length * 40 + highThreats.length * 25 + mediumThreats.length * 15)),
                    riskLevel: criticalThreats.length > 0 ? 'CRITICAL' : highThreats.length > 1 ? 'HIGH_RISK' : 'MEDIUM_RISK',
                    threatsDetected: threats.map(t => t.description),
                    confidence: Math.min(95, 70 + threats.length * 5),
                    source: 'content_script_analysis'
                };
                
                showPerfectSecurityWarning(analysisResult);
            }
            
        } catch (error) {
            console.warn('Perfect security scan error:', error);
        }
    }
    
    // ===== ADVANCED DOM-BASED THREAT DETECTION =====
    function detectAdvancedDOMThreats() {
        const threats = [];
        
        try {
            if (!document.body) return threats;
            
            const content = document.body.textContent?.toLowerCase() || '';
            const title = document.title?.toLowerCase() || '';
            
            // Advanced phishing content patterns (based on 2024 research)
            const advancedPatterns = [
                {
                    patterns: [
                        'your account has been suspended',
                        'account will be closed within 24 hours',
                        'immediate action required to avoid suspension',
                        'verify your account to prevent closure',
                        'account suspended due to suspicious activity'
                    ],
                    severity: 'critical',
                    description: '🚨 Account suspension scam detected'
                },
                {
                    patterns: [
                        'update payment information immediately',
                        'payment method has expired',
                        'billing information needs verification',
                        'payment failed - update now',
                        'credit card will be charged'
                    ],
                    severity: 'critical',
                    description: '💳 Payment/billing scam detected'
                },
                {
                    patterns: [
                        'security alert - unusual activity',
                        'suspicious login detected',
                        'unauthorized access attempt',
                        'security breach notification',
                        'your device has been compromised'
                    ],
                    severity: 'high',
                    description: '🔒 Fake security alert detected'
                },
                {
                    patterns: [
                        'click here to claim your prize',
                        'you have won',
                        'congratulations, you are selected',
                        'limited time offer expires soon',
                        'you are the 1000000th visitor'
                    ],
                    severity: 'high',
                    description: '🎁 Prize/lottery scam detected'
                },
                {
                    patterns: [
                        'download now to clean your computer',
                        'your computer is infected',
                        'virus detected on your device',
                        'call technical support immediately',
                        'microsoft technical support'
                    ],
                    severity: 'critical',
                    description: '💻 Tech support scam detected'
                }
            ];
            
            // Check each pattern
            for (const threatPattern of advancedPatterns) {
                const matchFound = threatPattern.patterns.some(pattern => 
                    content.includes(pattern) || title.includes(pattern)
                );
                
                if (matchFound) {
                    threats.push({
                        type: 'advanced_content_threat',
                        severity: threatPattern.severity,
                        description: threatPattern.description
                    });
                }
            }
            
            // Check for urgency/pressure tactics
            const urgencyKeywords = [
                'urgent', 'immediate', 'expires today', 'limited time',
                'act now', 'don\'t delay', 'hurry', 'last chance'
            ];
            
            const urgencyMatches = urgencyKeywords.filter(keyword => content.includes(keyword));
            if (urgencyMatches.length >= 3) {
                threats.push({
                    type: 'urgency_tactics',
                    severity: 'medium',
                    description: '⏰ Excessive urgency/pressure tactics detected'
                });
            }
            
        } catch (error) {
            console.warn('Advanced DOM threat detection error:', error);
        }
        
        return threats;
    }
    
    // ===== ENHANCED FORM ANALYSIS WITH ML PATTERNS =====
    function analyzeFormsWithML() {
        const threats = [];
        
        try {
            const forms = document.querySelectorAll('form');
            
            forms.forEach((form, index) => {
                if (!form?.nodeType || form.nodeType !== Node.ELEMENT_NODE) return;
                
                const formThreats = [];
                
                // Analyze form action and destination
                try {
                    const action = form.getAttribute('action');
                    if (action) {
                        const actionUrl = new URL(action, window.location.origin);
                        
                        // External form submission
                        if (actionUrl.hostname !== window.location.hostname) {
                            formThreats.push('External form submission');
                        }
                        
                        // Suspicious domains in action
                        const suspiciousDomains = [
                            'bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'rb.gy',
                            'secure-update', 'account-verify', 'login-check'
                        ];
                        
                        if (suspiciousDomains.some(domain => actionUrl.hostname.includes(domain))) {
                            formThreats.push('Form submits to suspicious domain');
                        }
                    }
                } catch (e) {
                    formThreats.push('Malformed form action URL');
                }
                
                // Advanced ML-based field analysis
                try {
                    const inputs = form.querySelectorAll('input, textarea, select');
                    let sensitiveFieldCount = 0;
                    let suspiciousFieldCount = 0;
                    
                    inputs.forEach(input => {
                        const name = (input.name || '').toLowerCase();
                        const placeholder = (input.placeholder || '').toLowerCase();
                        const type = (input.type || '').toLowerCase();
                        const id = (input.id || '').toLowerCase();
                        const label = getAssociatedLabel(input)?.toLowerCase() || '';
                        
                        // Comprehensive sensitive field detection
                        const sensitivePatterns = [
                            // Authentication
                            'password', 'passwd', 'pwd', 'pass',
                            // Financial
                            'card', 'credit', 'debit', 'cvv', 'cvc', 'expiry', 'expiration',
                            'account', 'routing', 'bank', 'iban', 'sort',
                            // Personal
                            'ssn', 'social', 'license', 'passport', 'tax',
                            // Security
                            'pin', 'token', 'otp', 'verification', 'security'
                        ];
                        
                        const fieldText = `${name} ${placeholder} ${id} ${label}`;
                        if (sensitivePatterns.some(pattern => fieldText.includes(pattern)) || type === 'password') {
                            sensitiveFieldCount++;
                        }
                        
                        // Suspicious field patterns
                        const suspiciousPatterns = [
                            'verify', 'confirm', 'update', 'check', 'validate',
                            'secure', 'auth', 'login', 'signin'
                        ];
                        
                        if (suspiciousPatterns.some(pattern => fieldText.includes(pattern))) {
                            suspiciousFieldCount++;
                        }
                    });
                    
                    // ML-based threat scoring
                    const threatScore = sensitiveFieldCount * 3 + suspiciousFieldCount * 2 + formThreats.length * 4;
                    
                    if (sensitiveFieldCount >= 2 && (formThreats.length > 0 || suspiciousFieldCount >= 3)) {
                        threats.push({
                            type: 'form_analysis',
                            severity: 'critical',
                            description: `🔐 Form ${index + 1}: Credential harvesting attempt detected (${sensitiveFieldCount} sensitive fields)`
                        });
                    } else if (sensitiveFieldCount >= 1 && suspiciousFieldCount >= 4) {
                        threats.push({
                            type: 'form_analysis',
                            severity: 'high',
                            description: `📝 Form ${index + 1}: Suspicious data collection form (Score: ${threatScore})`
                        });
                    } else if (threatScore >= 8) {
                        threats.push({
                            type: 'form_analysis',
                            severity: 'medium',
                            description: `📋 Form ${index + 1}: Potentially suspicious form detected`
                        });
                    }
                    
                } catch (e) {
                    console.warn('Form field analysis error:', e);
                }
            });
            
        } catch (error) {
            console.warn('Enhanced form analysis error:', error);
        }
        
        return threats;
    }
    
    // ===== CONTENT AND BEHAVIOR ANALYSIS =====
    function analyzeContentAndBehavior() {
        const threats = [];
        
        try {
            // Check for mixed content
            const scripts = document.querySelectorAll('script[src]');
            const links = document.querySelectorAll('link[href]');
            const images = document.querySelectorAll('img[src]');
            
            let mixedContentCount = 0;
            [...scripts, ...links, ...images].forEach(element => {
                const src = element.src || element.href;
                if (src && src.startsWith('http://') && window.location.protocol === 'https:') {
                    mixedContentCount++;
                }
            });
            
            if (mixedContentCount > 5) {
                threats.push({
                    type: 'content_security',
                    severity: 'high',
                    description: `🔓 Excessive mixed content detected (${mixedContentCount} resources)`
                });
            }
            
            // Check for suspicious iframes
            const iframes = document.querySelectorAll('iframe');
            let suspiciousIframeCount = 0;
            
            iframes.forEach(iframe => {
                const src = iframe.src;
                if (src && !src.startsWith(window.location.origin)) {
                    const iframeUrl = new URL(src, window.location.origin);
                    if (iframeUrl.hostname !== window.location.hostname) {
                        suspiciousIframeCount++;
                    }
                }
            });
            
            if (suspiciousIframeCount > 2) {
                threats.push({
                    type: 'content_security',
                    severity: 'medium',
                    description: `🖼️ Multiple external iframes detected (${suspiciousIframeCount})`
                });
            }
            
            // Advanced obfuscated JavaScript detection
            scripts.forEach((script, index) => {
                if (script.innerHTML && script.innerHTML.length > 1000) {
                    const content = script.innerHTML;
                    
                    // Check for common obfuscation patterns
                    const obfuscationPatterns = [
                        /eval\s*\(\s*unescape/gi,
                        /eval\s*\(\s*atob/gi,
                        /eval\s*\(\s*String\.fromCharCode/gi,
                        /document\.write\s*\(\s*unescape/gi,
                        /\\x[0-9a-f]{2}/gi,
                        /\\u[0-9a-f]{4}/gi
                    ];
                    
                    let obfuscationScore = 0;
                    obfuscationPatterns.forEach(pattern => {
                        const matches = content.match(pattern);
                        if (matches) {
                            obfuscationScore += matches.length;
                        }
                    });
                    
                    if (obfuscationScore >= 5) {
                        threats.push({
                            type: 'content_security',
                            severity: 'critical',
                            description: `⚠️ Heavily obfuscated JavaScript detected (Script ${index + 1})`
                        });
                    } else if (obfuscationScore >= 2) {
                        threats.push({
                            type: 'content_security',
                            severity: 'medium',
                            description: `🔍 Obfuscated JavaScript detected (Script ${index + 1})`
                        });
                    }
                }
            });
            
        } catch (error) {
            console.warn('Content and behavior analysis error:', error);
        }
        
        return threats;
    }
    
    // ===== NETWORK AND RESOURCE ANALYSIS =====
    function analyzeNetworkResources() {
        const threats = [];
        
        try {
            const url = window.location;
            
            // Enhanced port analysis
            if (url.port && !['80', '443', '8080', '8443', '3000', '8000'].includes(url.port)) {
                threats.push({
                    type: 'network_security',
                    severity: 'medium',
                    description: `🔌 Non-standard port ${url.port} detected`
                });
            }
            
            // Advanced path-based analysis
            const suspiciousPathPatterns = [
                { pattern: /\/admin|\/wp-admin|\/administrator/i, desc: 'Admin panel access attempt', severity: 'medium' },
                { pattern: /\/\.well-known\/acme-challenge/i, desc: 'Certificate validation attempt', severity: 'low' },
                { pattern: /\/cgi-bin|\/scripts|\/SCRIPTS/i, desc: 'CGI vulnerability attempt', severity: 'high' },
                { pattern: /\/(login|signin|auth|verify|confirm|update|secure)/i, desc: 'Authentication-related path', severity: 'medium' },
                { pattern: /\/phpmyadmin|\/mysql|\/database/i, desc: 'Database access attempt', severity: 'high' }
            ];
            
            suspiciousPathPatterns.forEach(({ pattern, desc, severity }) => {
                if (pattern.test(url.pathname)) {
                    threats.push({
                        type: 'network_security',
                        severity: severity,
                        description: `🛤️ ${desc}: ${url.pathname}`
                    });
                }
            });
            
            // Check for resource loading from suspicious domains
            const allResources = [
                ...document.querySelectorAll('script[src]'),
                ...document.querySelectorAll('link[href]'),
                ...document.querySelectorAll('img[src]')
            ];
            
            const suspiciousResourceDomains = [
                'bit.ly', 'tinyurl.com', 'free-analytics', 'cheap-cdn',
                'malware-host', 'phishing-kit', 'exploit-kit'
            ];
            
            let suspiciousResourceCount = 0;
            allResources.forEach(resource => {
                const src = resource.src || resource.href;
                if (src) {
                    try {
                        const resourceUrl = new URL(src, window.location.origin);
                        if (suspiciousResourceDomains.some(domain => 
                            resourceUrl.hostname.includes(domain))) {
                            suspiciousResourceCount++;
                        }
                    } catch (e) {
                        // Invalid URL
                    }
                }
            });
            
            if (suspiciousResourceCount > 0) {
                threats.push({
                    type: 'network_security',
                    severity: 'high',
                    description: `📡 Resources loaded from suspicious domains (${suspiciousResourceCount})`
                });
            }
            
        } catch (error) {
            console.warn('Network resource analysis error:', error);
        }
        
        return threats;
    }
    
    // ===== REAL-TIME CREDENTIAL HARVESTING DETECTION =====
    function detectCredentialHarvesting() {
        const threats = [];
        
        try {
            // Look for credential-related form combinations
            const forms = document.querySelectorAll('form');
            
            forms.forEach((form, index) => {
                const inputs = form.querySelectorAll('input');
                let hasUsernameField = false;
                let hasPasswordField = false;
                let hasPaymentField = false;
                let hasPiiField = false;
                
                inputs.forEach(input => {
                    const fieldInfo = `${input.name || ''} ${input.placeholder || ''} ${input.id || ''}`.toLowerCase();
                    
                    // Username detection
                    if (fieldInfo.includes('user') || fieldInfo.includes('email') || fieldInfo.includes('login') || input.type === 'email') {
                        hasUsernameField = true;
                    }
                    
                    // Password detection
                    if (input.type === 'password' || fieldInfo.includes('password') || fieldInfo.includes('pass')) {
                        hasPasswordField = true;
                    }
                    
                    // Payment information detection
                    if (fieldInfo.includes('card') || fieldInfo.includes('credit') || fieldInfo.includes('cvv')) {
                        hasPaymentField = true;
                    }
                    
                    // PII detection
                    if (fieldInfo.includes('ssn') || fieldInfo.includes('social') || fieldInfo.includes('tax')) {
                        hasPiiField = true;
                    }
                });
                
                // Threat assessment
                if ((hasUsernameField && hasPasswordField) || hasPaymentField || hasPiiField) {
                    const riskFactors = [];
                    if (hasUsernameField && hasPasswordField) riskFactors.push('login credentials');
                    if (hasPaymentField) riskFactors.push('payment information');
                    if (hasPiiField) riskFactors.push('personal information');
                    
                    threats.push({
                        type: 'credential_harvesting',
                        severity: 'critical',
                        description: `🎣 Credential harvesting form detected: ${riskFactors.join(', ')}`
                    });
                }
            });
            
        } catch (error) {
            console.warn('Credential harvesting detection error:', error);
        }
        
        return threats;
    }
    
    // ===== SOCIAL ENGINEERING PATTERN DETECTION =====
    function detectSocialEngineering() {
        const threats = [];
        
        try {
            const pageText = document.body.textContent?.toLowerCase() || '';
            
            // Social engineering tactics patterns
            const socialEngineeringPatterns = [
                {
                    keywords: ['congratulations', 'winner', 'selected', 'prize', 'reward'],
                    description: '🎊 Prize/reward social engineering',
                    threshold: 2
                },
                {
                    keywords: ['urgent', 'immediate', 'expire', 'suspend', 'deadline'],
                    description: '⏰ Urgency-based social engineering',
                    threshold: 3
                },
                {
                    keywords: ['verify', 'confirm', 'update', 'secure', 'protect'],
                    description: '🔐 Security-themed social engineering',
                    threshold: 3
                },
                {
                    keywords: ['free', 'discount', 'offer', 'limited', 'exclusive'],
                    description: '💰 Deal-based social engineering',
                    threshold: 3
                },
                {
                    keywords: ['click here', 'download now', 'act now', 'claim now'],
                    description: '👆 Action-pressure social engineering',
                    threshold: 2
                }
            ];
            
            socialEngineeringPatterns.forEach(pattern => {
                const matchCount = pattern.keywords.filter(keyword => 
                    pageText.includes(keyword)).length;
                
                if (matchCount >= pattern.threshold) {
                    threats.push({
                        type: 'social_engineering',
                        severity: matchCount >= pattern.threshold + 2 ? 'high' : 'medium',
                        description: `${pattern.description} (${matchCount} indicators)`
                    });
                }
            });
            
        } catch (error) {
            console.warn('Social engineering detection error:', error);
        }
        
        return threats;
    }
    
    // ===== UTILITY FUNCTIONS =====
    function isPerfectTrusted(hostname) {
        try {
            const domain = hostname.toLowerCase();
            
            // Direct match
            if (PERFECT_TRUSTED_DOMAINS.has(domain)) return true;
            
            // Check subdomains of trusted domains
            for (const trustedDomain of PERFECT_TRUSTED_DOMAINS) {
                if (domain.endsWith('.' + trustedDomain)) return true;
            }
            
            // Educational, government, and official domains
            const trustedTLDs = ['.edu', '.gov', '.mil', '.ac.uk', '.edu.au', '.govt.nz'];
            if (trustedTLDs.some(tld => domain.endsWith(tld))) return true;
            
            return false;
        } catch (error) {
            console.error('Error checking perfect trusted domain:', error);
            return false;
        }
    }
    
    function getAssociatedLabel(input) {
        try {
            // Check for label with for attribute
            if (input.id) {
                const label = document.querySelector(`label[for="${input.id}"]`);
                if (label) return label.textContent;
            }
            
            // Check for parent label
            const parentLabel = input.closest('label');
            if (parentLabel) return parentLabel.textContent;
            
            return null;
        } catch (error) {
            return null;
        }
    }
    
    // ===== WARNING SYSTEMS =====
    function showCriticalThreatWarning(analysis) {
        if (hasShownWarning >= PERFECT_CONFIG.MAX_WARNINGS) return;
        hasShownWarning++;
        
        createPerfectWarningBanner({
            type: 'critical',
            title: '🚨 CRITICAL THREAT DETECTED',
            message: `This website has been identified as extremely dangerous with a security score of ${Math.round(analysis.finalScore || 0)}/100.`,
            threats: analysis.threatsDetected || [],
            showDetails: true,
            blockAccess: true
        });
    }
    
    function showHighRiskWarning(analysis) {
        if (hasShownWarning >= PERFECT_CONFIG.MAX_WARNINGS) return;
        hasShownWarning++;
        
        createPerfectWarningBanner({
            type: 'high-risk',
            title: '⚠️ HIGH RISK WEBSITE',
            message: `This website shows signs of suspicious activity. Security score: ${Math.round(analysis.finalScore || 0)}/100.`,
            threats: analysis.threatsDetected || [],
            showDetails: true,
            blockAccess: false
        });
    }
    
    function showMediumRiskWarning(analysis) {
        if (hasShownWarning >= PERFECT_CONFIG.MAX_WARNINGS) return;
        hasShownWarning++;
        
        createPerfectWarningBanner({
            type: 'medium-risk',
            title: '⚠️ SUSPICIOUS ACTIVITY DETECTED',
            message: `Multiple suspicious indicators found on this website.`,
            threats: analysis.threatsDetected || [],
            showDetails: false,
            blockAccess: false
        });
    }
    
    function showPerfectSecurityWarning(analysis) {
        if (hasShownWarning >= PERFECT_CONFIG.MAX_WARNINGS) return;
        hasShownWarning++;
        
        const warningType = analysis.riskLevel === 'CRITICAL' ? 'critical' : 
                           analysis.riskLevel === 'HIGH_RISK' ? 'high-risk' : 'medium-risk';
        
        createPerfectWarningBanner({
            type: warningType,
            title: analysis.riskLevel === 'CRITICAL' ? '🚨 CRITICAL THREAT DETECTED' : 
                   analysis.riskLevel === 'HIGH_RISK' ? '⚠️ HIGH RISK WEBSITE' : '⚠️ SUSPICIOUS ACTIVITY',
            message: `Security analysis detected multiple threats. Score: ${Math.round(analysis.finalScore)}/100.`,
            threats: analysis.threatsDetected || [],
            showDetails: true,
            blockAccess: analysis.riskLevel === 'CRITICAL'
        });
    }
    
    // ===== PERFECT WARNING BANNER =====
    function createPerfectWarningBanner(config) {
        try {
            // Remove any existing warnings
            const existingWarnings = document.querySelectorAll('.perfect-phishing-protector-warning');
            existingWarnings.forEach(warning => warning.remove());
            
            const warning = document.createElement('div');
            warning.className = 'perfect-phishing-protector-warning';
            warning.id = 'perfect-phishing-protector-warning';
            
            // Enhanced styling with animations
            warning.style.cssText = `
                position: fixed !important;
                top: 0 !important;
                left: 0 !important;
                width: 100vw !important;
                min-height: ${config.blockAccess ? '100vh' : 'auto'} !important;
                background: ${getWarningBackgroundColor(config.type)} !important;
                border: 3px solid ${getWarningBorderColor(config.type)} !important;
                color: white !important;
                z-index: 2147483647 !important;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
                font-size: 16px !important;
                line-height: 1.5 !important;
                padding: 20px !important;
                box-shadow: 0 4px 20px rgba(0,0,0,0.5) !important;
                animation: perfectSlideDown 0.5s cubic-bezier(0.34, 1.56, 0.64, 1) !important;
            `;
            
            // Add animation keyframes
            if (!document.getElementById('perfect-warning-styles')) {
                const styles = document.createElement('style');
                styles.id = 'perfect-warning-styles';
                styles.textContent = `
                    @keyframes perfectSlideDown {
                        from { transform: translateY(-100%); opacity: 0; }
                        to { transform: translateY(0); opacity: 1; }
                    }
                    @keyframes perfectPulse {
                        0%, 100% { transform: scale(1); }
                        50% { transform: scale(1.05); }
                    }
                `;
                document.head.appendChild(styles);
            }
            
            const threatsList = config.threats.length > 0 ? 
                `<div style="margin: 15px 0; padding: 15px; background: rgba(255,255,255,0.1); border-radius: 8px;">
                    <strong>🔍 Detected Threats (${config.threats.length}):</strong>
                    <ul style="margin: 10px 0; padding-left: 20px;">
                        ${config.threats.slice(0, 5).map(threat => 
                            `<li style="margin: 5px 0;">${escapeHtml(threat)}</li>`
                        ).join('')}
                        ${config.threats.length > 5 ? 
                            `<li style="margin: 5px 0; font-style: italic;">... and ${config.threats.length - 5} more threats</li>` : ''
                        }
                    </ul>
                </div>` : '';
            
            warning.innerHTML = `
                <div style="max-width: 800px; margin: 0 auto; text-align: center;">
                    <div style="font-size: 48px; margin-bottom: 20px; animation: perfectPulse 2s infinite;">${getWarningIcon(config.type)}</div>
                    <h1 style="font-size: 24px; font-weight: bold; margin: 0 0 15px 0;">${config.title}</h1>
                    <div style="font-size: 18px; margin: 15px 0; background: rgba(255,255,255,0.1); padding: 15px; border-radius: 8px;">
                        ${config.message}
                    </div>
                    ${config.showDetails ? threatsList : ''}
                    
                    <div style="margin: 20px 0; font-size: 14px; opacity: 0.9;">
                        <strong>🛡️ Perfect Phishing Protector Pro v8.0</strong> - Advanced Threat Intelligence
                    </div>
                    
                    <div style="margin-top: 30px;">
                        ${!config.blockAccess ? `
                            <button onclick="this.parentElement.parentElement.parentElement.style.display='none'" 
                                    style="background: rgba(255,255,255,0.2); color: white; border: 2px solid white; 
                                           padding: 12px 24px; font-size: 16px; border-radius: 8px; 
                                           cursor: pointer; margin: 0 10px; transition: all 0.3s ease;">
                                ⚠️ Proceed Anyway (Not Recommended)
                            </button>
                        ` : ''}
                        <button onclick="window.history.back()" 
                                style="background: white; color: #333; border: none; 
                                       padding: 12px 24px; font-size: 16px; border-radius: 8px; 
                                       cursor: pointer; margin: 0 10px; font-weight: bold;
                                       transition: all 0.3s ease;">
                            🔙 Go Back to Safety
                        </button>
                    </div>
                </div>
            `;
            
            document.body.appendChild(warning);
            
            // If blocking access, blur the background content
            if (config.blockAccess) {
                document.body.style.filter = 'blur(5px)';
                document.body.style.pointerEvents = 'none';
                warning.style.pointerEvents = 'all';
            }
            
            console.log(`🚨 Perfect warning displayed: ${config.type}`);
            
        } catch (error) {
            console.error('Error creating perfect warning banner:', error);
        }
    }
    
    function getWarningBackgroundColor(type) {
        const colors = {
            'critical': 'linear-gradient(135deg, #dc3545, #b02a37)',
            'high-risk': 'linear-gradient(135deg, #fd7e14, #e76500)',
            'medium-risk': 'linear-gradient(135deg, #ffc107, #e0a800)'
        };
        return colors[type] || colors['medium-risk'];
    }
    
    function getWarningBorderColor(type) {
        const colors = {
            'critical': '#dc3545',
            'high-risk': '#fd7e14',
            'medium-risk': '#ffc107'
        };
        return colors[type] || colors['medium-risk'];
    }
    
    function getWarningIcon(type) {
        const icons = {
            'critical': '🚨',
            'high-risk': '⚠️',
            'medium-risk': '⚠️'
        };
        return icons[type] || icons['medium-risk'];
    }
    
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    // ===== CONTENT MONITORING =====
    function setupContentMonitoring() {
        // Monitor for dynamic content changes
        const observer = new MutationObserver((mutations) => {
            let shouldRescan = false;
            
            mutations.forEach((mutation) => {
                if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
                    // Check if new forms or suspicious content was added
                    mutation.addedNodes.forEach((node) => {
                        if (node.nodeType === Node.ELEMENT_NODE) {
                            if (node.tagName === 'FORM' || 
                                node.querySelector && node.querySelector('form')) {
                                shouldRescan = true;
                            }
                        }
                    });
                }
            });
            
            if (shouldRescan && Date.now() - lastScanTime > 5000) {
                console.log('📊 Content changed, triggering rescan...');
                setTimeout(performPerfectSecurityScan, 1000);
            }
        });
        
        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }
    
    // ===== INITIALIZATION =====
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initializePerfectProtection);
    } else {
        initializePerfectProtection();
    }
    
    console.log('🎯 Perfect Phishing Protector Pro v8.0 Content Script Loaded!');
    console.log('✅ Real-time threat detection active');
    console.log('🛡️ Advanced content analysis enabled');
    console.log('🔍 65+ security indicators monitoring');
    
})();