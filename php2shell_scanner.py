#!/usr/bin/env python3
"""PHP2Shell HTTP banner auditor. Python 3.10+, no third-party dependencies.

Use only on systems you own or have explicit permission to assess.
No exploitation. Declared banners do NOT confirm exploitability or backports.
Static rules reviewed on 2026-10-22; no automatic rule updates.
Sources:
https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote
https://github.com/NCSC-NL/php2shell

Examples:
  python3 php2shell_scanner.py app.example.com -o results.csv
  python3 php2shell_scanner.py -f targets.txt --timeout 5
  python3 php2shell_scanner.py https://app.example.com/login.php --protocol https

Checks HTTP/80 and HTTPS/443 by default, preserving the supplied path.
One HEAD request attempt per protocol; --method GET selects GET instead.
--protocol http/https selects one protocol. No retries or automatic fallback.
Live colored console; --format table selects the table layout.
--color never disables colors; --color auto respects NO_COLOR.
No redirects, response-body reads, phpinfo discovery, environment proxies,
or persistent cookies. The Redirect column records the Location header.
If / does not execute PHP, supply a known read-only PHP route. A missing banner
does not prove that PHP is absent. php -v may describe CLI rather than the web
runtime; verify the actual web runtime and vendor package revision internally.
"""
import argparse
import csv
import ipaddress
import math
import os
import time
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

FIXED = {(8, 2): (8, 2, 35), (8, 3): (8, 3, 36),
         (8, 4): (8, 4, 27), (8, 5): (8, 5, 12)}
MIGRATE = 'Migrate to PHP 8.5.12 or a later stable 8.5 release; validate compatibility'
VERSION = re.compile(r'\bPHP/(\d+)\.(\d+)\.(\d+)([^\s;,()]*)', re.I)
COLUMNS = ['Server', 'URL', 'Protocol', 'Port', 'HTTP', 'Method', 'PHP Version',
           'Vulnerable', 'Upgrade To', 'Evidence', 'Redirect', 'TLS',
           'Details', 'Timestamp UTC']


def clean(value):
    # Remove terminal controls and newlines from remote values.
    return ''.join(c if c.isprintable() else ' ' for c in str(value))[:2048]


def normalize(target):
    target = target.strip()
    if not target or any(c.isspace() or ord(c) < 32 for c in target):
        raise ValueError('Target is empty or contains whitespace/control characters')
    # Accept bare IPv6 addresses when no scheme or path is supplied.
    try:
        ipaddress.IPv6Address(target)
        target = '[' + target + ']'
    except ValueError:
        pass
    parts = urllib.parse.urlsplit(target if '://' in target else 'http://' + target)
    if parts.scheme not in ('http', 'https') or not parts.hostname:
        raise ValueError('A domain, IP address, or HTTP(S) URL is required')
    if parts.username is not None or parts.password is not None:
        raise ValueError('Embedded URL credentials are not accepted')
    if parts.port not in (None, 80, 443):
        raise ValueError('Only ports 80 and 443 are supported')
    host = parts.hostname.encode('idna').decode('ascii')
    if '%' in host or '\\' in host:
        raise ValueError('Unsupported hostname')
    authority = '[' + host + ']' if ':' in host else host
    path = urllib.parse.quote(parts.path or '/', safe="/%:@!$&'()*+,;=-._~")
    query = urllib.parse.quote(parts.query, safe="%=&?/:@!$'()*+,;~-._")
    return host, authority, path + ('?' + query if query else '')


def evaluate(evidence):
    matches = VERSION.findall(evidence)
    values = {(int(a), int(b), int(c), suffix) for a, b, c, suffix in matches}
    if not values:
        return ('Not disclosed', 'Unknown', 'Verify the web runtime and installed package',
                'No complete PHP version; this does not mean unaffected')
    versions = ', '.join('.'.join(map(str, v[:3])) + v[3] for v in sorted(values))
    if len(values) != 1:
        return versions, 'Unknown', 'Verify backend versions', 'Conflicting version banners'
    major, minor, patch, suffix = next(iter(values))
    version = (major, minor, patch)
    if suffix:
        return versions, 'Unknown', 'Check the vendor advisory and package revision', 'Suffixed version; possible backport or prerelease'
    branch = (major, minor)
    if branch in FIXED:
        minimum = '.'.join(map(str, FIXED[branch]))
        if version < FIXED[branch]:
            return versions, 'Yes (by version)', 'PHP ' + minimum + ' or a later stable release in the same branch', 'Verify vendor backports before closing the finding'
        return versions, 'No (by version)', 'No change for these CVEs; keep the branch supported', 'Declared banner, not proof of effective patching or overall security'
    if (5, 4) <= branch < (8, 2) and (major in (5, 7, 8)):
        return versions, 'Yes (by version)', MIGRATE, 'Upstream EOL branch; verify vendor patches'
    return versions, 'Unknown', MIGRATE, 'Version outside verified rules; review manually'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def opener(insecure=False):
    context = ssl.create_default_context()
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                      urllib.request.HTTPSHandler(context=context))


def fetch(client, url, method, timeout):
    request = urllib.request.Request(url, method=method, headers={
        'User-Agent': 'PHP2Shell-Version-Audit/1.0', 'Accept': '*/*',
        'Connection': 'close'})
    try:
        response = client.open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        response = error  # Include 3xx/4xx/5xx without following redirects.
    try:
        headers = response.headers
        evidence = '; '.join(name + ': ' + value
                             for name in ('Server', 'X-Powered-By')
                             for value in headers.get_all(name, []))
        return response.code, evidence, headers.get('Location', '')
    finally:
        response.close()  # Do not read the response body.


def scan(job, timeout, insecure, method='HEAD'):
    host, authority, path, scheme, port = job
    url = f'{scheme}://{authority}:{port}{path}'
    row = dict.fromkeys(COLUMNS, '')
    row.update({'Server': host, 'URL': url, 'Protocol': scheme.upper(),
                'Port': str(port), 'Method': method, 'Vulnerable': 'Unknown',
                'PHP Version': 'Not disclosed', 'Upgrade To': 'Verify the web runtime and installed package',
                'TLS': ('NOT verified' if insecure else 'Verification enabled') if scheme == 'https' else 'N/A',
                'Timestamp UTC': datetime.now(timezone.utc).isoformat(timespec='seconds')})
    client = opener(insecure)
    raw = ''
    errors = []
    try:
        code, raw, location = fetch(client, url, method, timeout)
        row['HTTP'] = str(code)
        row['Redirect'] = clean(location)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        errors.append(method + ': ' + clean(exc))
    version, vulnerable, remediation, detail = evaluate(raw)
    row.update({'PHP Version': version, 'Vulnerable': vulnerable,
                'Upgrade To': remediation, 'Evidence': clean(raw),
                'Details': detail + ('; ' + '; '.join(errors) if errors else '')})
    if not row['HTTP']:
        row['HTTP'] = 'No HTTP response'
    return row


def csv_safe(value):
    text = clean(value)
    return "'" + text if text.lstrip().startswith(('=', '+', '-', '@')) else text


def print_table(rows):
    fields = ['Server', 'Protocol', 'Port', 'HTTP', 'Method', 'PHP Version', 'Vulnerable', 'Upgrade To']
    widths = {f: max(len(f), *(len(clean(r[f])) for r in rows)) for f in fields}
    print(' | '.join(f.ljust(widths[f]) for f in fields))
    print('-+-'.join('-' * widths[f] for f in fields))
    for row in rows:
        print(' | '.join(clean(row[f]).ljust(widths[f]) for f in fields))



def colors_enabled(mode):
    if mode != 'auto':
        return mode == 'always'
    return (sys.stdout.isatty() and 'NO_COLOR' not in os.environ
            and (os.name != 'nt' or any(os.environ.get(k) for k in ('WT_SESSION', 'ANSICON', 'TERM'))))


def paint(text, code, enabled):
    return '\033[' + code + 'm' + text + '\033[0m' if enabled else text


def status_key(row):
    return {'Yes (by version)': 'vulnerable', 'No (by version)': 'not_affected'}.get(row['Vulnerable'], 'unknown')


def is_eol(row):
    # Label from the 2026-10-22 support snapshot, not a live lookup.
    match = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)', row['PHP Version'])
    return bool(match and (5, 4) <= tuple(map(int, match.groups()[:2])) < (8, 2))


def print_console_header(jobs, args, enabled):
    print(paint('php2shell - Passive PHP version banner scanner', '1', enabled))
    print(paint(f'CVE-2026-109618 / CVE-2026-109619 | {len(jobs)} planned check(s)'
                f' | {args.workers} worker(s) | timeout {args.timeout:.1f}s | {args.method}', '90', enabled))
    print('Owned systems or explicit permission only. One request per protocol; no retries.')
    print('* Banner-based status, NOT confirmed exploitation. Rules: 2026-10-22. Verify backports.\n')


def console_line(row, enabled=False, host_width=28):
    labels = {'vulnerable': ('VULNERABLE*', '91'),
              'not_affected': ('NOT AFFECTED*', '92'), 'unknown': ('UNKNOWN', '93')}
    label, color = labels[status_key(row)]
    status = paint(label.ljust(14), color, enabled)
    host = clean(row['Server']).ljust(host_width)
    service = (row['Protocol'].lower() + ':' + row['Port']).ljust(9)
    version = ('PHP ' + clean(row['PHP Version']) if row['PHP Version'] != 'Not disclosed' else 'PHP not disclosed').ljust(19)
    eol = paint('[EOL]', '93', enabled) if is_eol(row) else '     '
    http = row['HTTP'] if row['HTTP'].isdigit() else 'ERR'
    remediation = clean(row['Upgrade To'])
    if status_key(row) == 'vulnerable' and not is_eol(row):
        remediation = remediation.replace('PHP ', '', 1).replace(' or a later stable release in the same branch', ' + (same branch)')
    if status_key(row) == 'not_affected':
        remediation = 'Fixed minimum declared; verify runtime and package'
    return f'{status} {host} {service} {version} {eol} {paint("->", "90", enabled)} {remediation}  [HTTP {http}]'


def print_summary(rows, elapsed, enabled):
    vulnerable = sum(status_key(r) == 'vulnerable' for r in rows)
    not_affected = sum(status_key(r) == 'not_affected' for r in rows)
    unknown = len(rows) - vulnerable - not_affected
    print(f'\nCompleted: {len(rows)} checks | {elapsed:.1f}s')
    print(paint(f'VULNERABLE*: {vulnerable}', '91', enabled) + ' | '
          + paint(f'NOT AFFECTED*: {not_affected}', '92', enabled) + ' | '
          + paint(f'UNKNOWN: {unknown}', '93', enabled))
    print('* Declared-version assessment; not proof of exploitability or effective remediation.')

def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('targets', nargs='*', help='Domains, IP addresses, or URLs')
    parser.add_argument('-f', '--file', type=Path, help='One target per line; # starts a comment')
    parser.add_argument('-o', '--output', type=Path, default=Path('php2shell_results.csv'))
    parser.add_argument('--timeout', type=float, default=5, help='Seconds per socket operation')
    parser.add_argument('--workers', type=int, default=1, help='Concurrency, 1 to 16; default 1')
    parser.add_argument('--insecure', action='store_true', help='Skip TLS verification (recorded in CSV)')
    parser.add_argument('--method', choices=['HEAD', 'GET'], default='HEAD', help='One method only; no automatic fallback')
    parser.add_argument('--protocol', choices=['both', 'http', 'https'], default='both', help='Default: both protocols')
    parser.add_argument('--format', choices=['console', 'table'], default='console', help='Live output or classic table')
    parser.add_argument('--color', choices=['auto', 'always', 'never'], default='auto', help='ANSI colors; auto respects NO_COLOR')
    args = parser.parse_args()
    if not math.isfinite(args.timeout) or args.timeout <= 0 or not 1 <= args.workers <= 16:
        parser.error('Timeout must be positive and finite; workers must be between 1 and 16')
    targets = list(args.targets)
    if args.file:
        try:
            targets += [line.strip() for line in args.file.read_text(encoding='utf-8-sig').splitlines()
                        if line.strip() and not line.lstrip().startswith('#')]
        except OSError as exc:
            parser.error(str(exc))
    if not targets:
        parser.error('Specify at least one target or --file')
    try:
        normalized = list(dict.fromkeys(normalize(t) for t in targets))
    except ValueError as exc:
        parser.error(str(exc))
    jobs = [(host, authority, path, scheme, port)
            for host, authority, path in normalized
            for scheme, port in [('http', 80), ('https', 443)]
            if args.protocol in ('both', scheme)]
    enabled = colors_enabled(args.color)
    print_console_header(jobs, args, enabled)
    started = time.monotonic()
    rows = [None] * len(jobs)
    host_width = max(28, max(len(job[0]) for job in jobs))
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        pending = {pool.submit(scan, job, args.timeout, args.insecure, args.method): i
                   for i, job in enumerate(jobs)}
        for future in as_completed(pending):
            row = future.result()
            rows[pending[future]] = row
            if args.format == 'console':
                print(console_line(row, enabled, host_width), flush=True)
    if args.format == 'table':
        print_table(rows)
    print_summary(rows, time.monotonic() - started, enabled)
    try:
        with args.output.open('w', newline='', encoding='utf-8-sig') as stream:
            writer = csv.DictWriter(stream, fieldnames=COLUMNS)
            writer.writeheader()
            writer.writerows({key: csv_safe(value) for key, value in row.items()} for row in rows)
    except OSError as exc:
        parser.exit(2, 'Could not save CSV: ' + str(exc) + '\n')
    print('\nCSV: ' + str(args.output))


if __name__ == '__main__':
    main()
