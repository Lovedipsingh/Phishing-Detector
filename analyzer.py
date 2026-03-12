import re
import hashlib
from datetime import datetime
from urllib.parse import urlparse

class PhishingAnalyzer:
    def __init__(self, email_content):
        self.content = email_content
        self.flags = []
        self.score = 0

    # ── HEADER ANALYSIS ───────────────────────────────────────────────────────
    def extract_headers(self):
        headers = {}
        lines = self.content.split('\n')
        for line in lines:
            if ':' in line and not line.startswith(' ') and not line.startswith('\t'):
                key, _, value = line.partition(':')
                headers[key.strip().lower()] = value.strip()
            if line.strip() == '':
                break  # end of headers
        return headers

    def check_spoofed_sender(self, headers):
        from_addr = headers.get('from', '')
        reply_to = headers.get('reply-to', '')
        return_path = headers.get('return-path', '')

        if reply_to and from_addr:
            from_domain = re.findall(r'@([\w.-]+)', from_addr)
            reply_domain = re.findall(r'@([\w.-]+)', reply_to)
            if from_domain and reply_domain and from_domain[0] != reply_domain[0]:
                self.flags.append({
                    'category': 'Header Spoofing',
                    'severity': 'HIGH',
                    'detail': f'Reply-To domain ({reply_domain[0]}) differs from From domain ({from_domain[0]}) — classic spoofing indicator'
                })
                self.score += 25

        if return_path and from_addr:
            from_domain = re.findall(r'@([\w.-]+)', from_addr)
            rp_domain = re.findall(r'@([\w.-]+)', return_path)
            if from_domain and rp_domain and from_domain[0] != rp_domain[0]:
                self.flags.append({
                    'category': 'Return-Path Mismatch',
                    'severity': 'HIGH',
                    'detail': f'Return-Path domain ({rp_domain[0]}) does not match From domain ({from_domain[0]})'
                })
                self.score += 20

    def check_auth_headers(self, headers):
        auth_results = headers.get('authentication-results', '')
        received_spf = headers.get('received-spf', '')

        if 'fail' in auth_results.lower() or 'fail' in received_spf.lower():
            self.flags.append({
                'category': 'SPF/DKIM Failure',
                'severity': 'HIGH',
                'detail': 'Email failed SPF or DKIM authentication — sender may be forged'
            })
            self.score += 30

        if not auth_results and not received_spf:
            self.flags.append({
                'category': 'Missing Authentication',
                'severity': 'MEDIUM',
                'detail': 'No SPF or DKIM authentication headers found — legitimate emails typically include these'
            })
            self.score += 10

    # ── URL ANALYSIS ──────────────────────────────────────────────────────────
    def extract_urls(self):
        return re.findall(r'https?://[^\s<>"\']+', self.content)

    def check_suspicious_urls(self, urls):
        suspicious_tlds = ['.xyz', '.tk', '.pw', '.cc', '.top', '.gq', '.ml', '.ga', '.cf']
        url_shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly']
        suspicious_keywords = ['login', 'verify', 'secure', 'account', 'update', 'confirm', 'banking', 'paypal', 'amazon', 'apple', 'microsoft', 'google']

        for url in urls:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            # Check suspicious TLDs
            for tld in suspicious_tlds:
                if domain.endswith(tld):
                    self.flags.append({
                        'category': 'Suspicious Domain',
                        'severity': 'HIGH',
                        'detail': f'URL uses suspicious TLD: {url}'
                    })
                    self.score += 20
                    break

            # Check URL shorteners
            for shortener in url_shorteners:
                if shortener in domain:
                    self.flags.append({
                        'category': 'URL Shortener',
                        'severity': 'MEDIUM',
                        'detail': f'URL shortener detected — hides true destination: {url}'
                    })
                    self.score += 15
                    break

            # Check IP address URLs
            if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
                self.flags.append({
                    'category': 'IP Address URL',
                    'severity': 'HIGH',
                    'detail': f'URL uses raw IP address instead of domain name: {url}'
                })
                self.score += 25

            # Check suspicious keywords in URL
            for keyword in suspicious_keywords:
                if keyword in url.lower() and keyword not in domain:
                    self.flags.append({
                        'category': 'Suspicious URL Keyword',
                        'severity': 'MEDIUM',
                        'detail': f'Suspicious keyword "{keyword}" found in URL path: {url}'
                    })
                    self.score += 10
                    break

            # Check for @ in URL (obfuscation)
            if '@' in url:
                self.flags.append({
                    'category': 'URL Obfuscation',
                    'severity': 'HIGH',
                    'detail': f'@ symbol in URL — used to obfuscate true destination: {url}'
                })
                self.score += 25

            # Mismatched display text vs URL
            display_urls = re.findall(r'href=["\']([^"\']+)["\']', self.content)
            for display in display_urls:
                if display != url:
                    d_parsed = urlparse(display)
                    u_parsed = urlparse(url)
                    if d_parsed.netloc and u_parsed.netloc and d_parsed.netloc != u_parsed.netloc:
                        self.flags.append({
                            'category': 'Mismatched URL',
                            'severity': 'HIGH',
                            'detail': f'Display URL does not match actual href destination — classic phishing technique'
                        })
                        self.score += 25
                        break

    # ── CONTENT ANALYSIS ──────────────────────────────────────────────────────
    def check_urgency_language(self):
        urgency_patterns = [
            r'urgent', r'immediately', r'account.*suspend', r'verify.*now',
            r'click.*here', r'limited time', r'act now', r'expires',
            r'your account.*compromised', r'unusual.*activity', r'confirm.*identity',
            r'update.*payment', r'suspended', r'locked', r'unauthorized',
            r'24 hours', r'48 hours', r'action required', r'important notice',
            r'security alert', r'final notice', r'last chance'
        ]
        found = []
        for pattern in urgency_patterns:
            if re.search(pattern, self.content, re.IGNORECASE):
                found.append(pattern.replace(r'.*', ' ').replace(r'\b', '').replace('r\'', ''))

        if len(found) >= 3:
            self.flags.append({
                'category': 'High Urgency Language',
                'severity': 'HIGH',
                'detail': f'Multiple urgency triggers detected: {", ".join(found[:5])}'
            })
            self.score += 25
        elif len(found) >= 1:
            self.flags.append({
                'category': 'Urgency Language',
                'severity': 'MEDIUM',
                'detail': f'Urgency language detected: {", ".join(found[:3])}'
            })
            self.score += 10

    def check_sensitive_requests(self):
        sensitive_patterns = [
            r'social security', r'ssn', r'credit card', r'bank account',
            r'password', r'username', r'login credentials', r'date of birth',
            r'pin number', r'cvv', r'routing number', r'wire transfer',
            r'gift card', r'bitcoin', r'crypto', r'send money'
        ]
        found = []
        for pattern in sensitive_patterns:
            if re.search(pattern, self.content, re.IGNORECASE):
                found.append(pattern)

        if found:
            self.flags.append({
                'category': 'Sensitive Information Request',
                'severity': 'CRITICAL',
                'detail': f'Email requests sensitive information: {", ".join(found[:5])}'
            })
            self.score += 35

    def check_brand_impersonation(self):
        brands = ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
                  'netflix', 'bank of america', 'chase', 'wells fargo', 'irs',
                  'social security', 'fedex', 'ups', 'usps', 'dhl']
        headers = self.extract_headers()
        from_addr = headers.get('from', '').lower()

        for brand in brands:
            if brand in self.content.lower():
                if brand not in from_addr:
                    self.flags.append({
                        'category': 'Brand Impersonation',
                        'severity': 'HIGH',
                        'detail': f'Email mentions "{brand}" but sender domain does not match — possible impersonation'
                    })
                    self.score += 20
                    break

    def check_attachment_indicators(self):
        attachment_patterns = [
            r'\.exe', r'\.zip', r'\.rar', r'\.js', r'\.vbs', r'\.bat',
            r'\.cmd', r'\.ps1', r'\.docm', r'\.xlsm', r'invoice.*attached',
            r'open.*attachment', r'see.*attached'
        ]
        for pattern in attachment_patterns:
            if re.search(pattern, self.content, re.IGNORECASE):
                self.flags.append({
                    'category': 'Suspicious Attachment',
                    'severity': 'HIGH',
                    'detail': f'Suspicious attachment type or language detected: {pattern}'
                })
                self.score += 20
                break

    def check_grammar(self):
        poor_grammar = [
            r'dear (customer|user|account holder|valued member)',
            r'kindly (click|verify|update|confirm)',
            r'do the needful',
            r'revert back',
            r'please to ',
        ]
        found = []
        for pattern in poor_grammar:
            if re.search(pattern, self.content, re.IGNORECASE):
                found.append(pattern)

        if found:
            self.flags.append({
                'category': 'Poor Grammar / Generic Greeting',
                'severity': 'MEDIUM',
                'detail': f'Generic or poorly written language detected — common in phishing emails'
            })
            self.score += 10

    # ── MAIN ANALYSIS ─────────────────────────────────────────────────────────
    def analyze(self):
        headers = self.extract_headers()
        urls = self.extract_urls()

        self.check_spoofed_sender(headers)
        self.check_auth_headers(headers)
        self.check_suspicious_urls(urls)
        self.check_urgency_language()
        self.check_sensitive_requests()
        self.check_brand_impersonation()
        self.check_attachment_indicators()
        self.check_grammar()

        # Cap score at 100
        self.score = min(self.score, 100)

        # Determine verdict
        if self.score >= 70:
            verdict = 'PHISHING'
            verdict_color = '#ff4444'
        elif self.score >= 40:
            verdict = 'SUSPICIOUS'
            verdict_color = '#ffaa00'
        else:
            verdict = 'LIKELY SAFE'
            verdict_color = '#00cc66'

        # Count by severity
        critical = len([f for f in self.flags if f['severity'] == 'CRITICAL'])
        high = len([f for f in self.flags if f['severity'] == 'HIGH'])
        medium = len([f for f in self.flags if f['severity'] == 'MEDIUM'])

        return {
            'score': self.score,
            'verdict': verdict,
            'verdict_color': verdict_color,
            'flags': self.flags,
            'total_flags': len(self.flags),
            'critical_flags': critical,
            'high_flags': high,
            'medium_flags': medium,
            'urls_found': urls,
            'headers': dict(list(headers.items())[:10]),
            'analyzed_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
