#!/usr/bin/env python3
"""
phish_analyzer.py
Usage: python3 phish_analyzer.py suspect.eml
Outputs:
 - phish_report.json
 - phish_report.txt
 - extracted_urls.txt
 - extracted_domains.txt
"""
import sys, email, json, re
from email import policy
from bs4 import BeautifulSoup
import tldextract
import dns.resolver
from urllib.parse import urlparse

EML = sys.argv[1] if len(sys.argv)>1 else 'suspect.eml'

# Helpers
url_re = re.compile(r'https?://[^\s\'"<>]+', flags=re.IGNORECASE)

def extract_urls_from_html(html):
    soup = BeautifulSoup(html, 'html.parser')
    urls = []
    for a in soup.find_all('a', href=True):
        urls.append(a['href'])
    # also fallback to regex for other links
    urls += url_re.findall(html)
    return list(dict.fromkeys(urls))  # dedupe preserving order

def dns_txt_records(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT', lifetime=5)
        return [r.to_text().strip('"') for r in answers]
    except Exception:
        return []

def check_spf(domain):
    txts = dns_txt_records(domain)
    return [t for t in txts if t.lower().startswith('v=spf1')]

def check_dmarc(domain):
    # DMARC is at _dmarc.domain TXT
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT', lifetime=5)
        return [r.to_text().strip('"') for r in answers]
    except Exception:
        return []

def simplify_domain(u):
    try:
        p = urlparse(u)
        host = p.hostname or u
    except Exception:
        host = u
    ext = tldextract.extract(host)
    if ext.domain:
        return f"{ext.domain}.{ext.suffix}"
    return host

# Parse email
with open(EML, 'rb') as f:
    msg = email.message_from_binary_file(f, policy=policy.default)

headers = dict(msg.items())

# Gather key headers
hdr_from = headers.get('From','').strip()
hdr_to = headers.get('To','').strip()
hdr_subject = headers.get('Subject','').strip()
hdr_return = headers.get('Return-Path','').strip()
dkim_present = 'DKIM-Signature' in headers

# Attempt to find envelope-from domain: prefer Return-Path then From
env_domain = ''
if hdr_return:
    m = re.search(r'@([^\s>]+)', hdr_return)
    if m: env_domain = m.group(1)
if not env_domain and hdr_from:
    m = re.search(r'@([^\s>]+)', hdr_from)
    if m: env_domain = m.group(1)

# Extract body (text + html)
body_text = ''
body_html = ''
if msg.is_multipart():
    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype == 'text/plain' and not body_text:
            try:
                body_text += part.get_content()
            except:
                pass
        if ctype == 'text/html' and not body_html:
            try:
                body_html += part.get_content()
            except:
                pass
else:
    ctype = msg.get_content_type()
    if ctype == 'text/html':
        body_html = msg.get_content()
    else:
        body_text = msg.get_content()

# Extract URLs
urls = []
if body_html:
    urls += extract_urls_from_html(body_html)
if body_text:
    urls += url_re.findall(body_text)
# normalize and dedupe
seen = set()
clean_urls = []
for u in urls:
    u = u.strip()
    if not u: continue
    if u not in seen:
        clean_urls.append(u)
        seen.add(u)

# Extract domains from URLs + headers
domains = set()
for u in clean_urls:
    dom = simplify_domain(u)
    if dom:
        domains.add(dom)
# also include From/Return-Path domain
if env_domain:
    domains.add(env_domain)
if hdr_from:
    m = re.search(r'@([^\s>]+)', hdr_from)
    if m:
        domains.add(m.group(1))

# Check SPF/DKIM/DMARC for those domains (best-effort)
spf_results = {}
dmarc_results = {}
for d in sorted(domains):
    try:
        spf_results[d] = check_spf(d)
    except Exception as e:
        spf_results[d] = []
    try:
        dmarc_results[d] = check_dmarc(d)
    except Exception:
        dmarc_results[d] = []

# Simple heuristic scoring
score = 0
reasons = []

# No DKIM header -> +1
if not dkim_present:
    score += 1
    reasons.append('DKIM header not present')

# For each domain: no SPF -> +1 per domain; no DMARC -> +0.5
for d in spf_results:
    if not spf_results[d]:
        score += 1
        reasons.append(f'No SPF for {d}')
    if not dmarc_results.get(d):
        score += 0.5
        reasons.append(f'No DMARC for {d}')

# look for IP URLs or suspicious patterns
for u in clean_urls:
    p = urlparse(u)
    host = p.hostname or ''
    # URL with numeric IP as host
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
        score += 2
        reasons.append(f'URL uses IP address: {u}')
    # long or punycode/odd unicode (basic)
    if 'xn--' in host or any(ord(ch) > 127 for ch in host):
        score += 1.5
        reasons.append(f'Possible IDN/obfuscated domain: {host}')

# Build report
report = {
    'file': EML,
    'subject': hdr_subject,
    'from': hdr_from,
    'to': hdr_to,
    'return_path': hdr_return,
    'envelope_domain': env_domain,
    'dkim_present': dkim_present,
    'urls': clean_urls,
    'domains': sorted(domains),
    'spf': spf_results,
    'dmarc': dmarc_results,
    'score': round(score,2),
    'reasons': reasons,
}

# Write outputs
with open('phish_report.json','w') as f:
    json.dump(report, f, indent=2)

with open('extracted_urls.txt','w') as f:
    for u in clean_urls:
        f.write(u + '\n')

with open('extracted_domains.txt','w') as f:
    for d in sorted(domains):
        f.write(d + '\n')

# Human readable summary
with open('phish_report.txt','w') as f:
    f.write(f"Subject: {hdr_subject}\nFrom: {hdr_from}\nTo: {hdr_to}\nReturn-Path: {hdr_return}\n")
    f.write(f"DKIM header present: {dkim_present}\nEnvelope-from domain: {env_domain}\n\n")
    f.write("Extracted URLs:\n")
    for u in clean_urls:
        f.write("  " + u + "\n")
    f.write("\nExtracted domains:\n")
    for d in sorted(domains):
        f.write("  " + d + "\n")
    f.write("\nSPF records (if any):\n")
    for d, val in spf_results.items():
        f.write(f"{d}: {val}\n")
    f.write("\nDMARC records (if any):\n")
    for d, val in dmarc_results.items():
        f.write(f"{d}: {val}\n")
    f.write("\nScore: " + str(report['score']) + "\n")
    f.write("Reasons:\n")
    for r in report['reasons']:
        f.write(" - " + r + "\n")

print("Wrote phish_report.json, phish_report.txt, extracted_urls.txt, extracted_domains.txt")
