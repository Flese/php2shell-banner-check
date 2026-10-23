PHP2Shell Banner Check
Low-impact PHP version banner checks for PHP2Shell (CVE-2026-109618 and CVE-2026-109619). Written in Python, with no third-party dependencies.

Authorized use only
This tool is only for authorized security assessments: systems you own or have explicit permission to assess. Permission must cover the targets, routes, protocols, and assessment window. Do not use it against third-party systems without authorization.

This is a passive assessment of banner contents, not an exploitation test. It generates traffic: at most one HTTP request attempt per selected protocol, using HEAD or GET. It is not passive network capture and does not guarantee zero impact. Even ordinary requests can generate logs, alerts, or application processing.

Terminal preview
Illustrative output generated with simulated responses. These are not findings from real servers, and the elapsed time is illustrative.

php2shell - Passive PHP version banner scanner
CVE-2026-109618 / CVE-2026-109619 | 4 planned check(s) | 1 worker(s) | timeout 5.0s | HEAD
Owned systems or explicit permission only. One request per protocol; no retries.
* Banner-based status, NOT confirmed exploitation. Rules: 2026-10-22. Verify backports.

VULNERABLE*    app.example.com              https:443 PHP 8.3.35                -> 8.3.36 + (same branch)  [HTTP 200]
VULNERABLE*    legacy.example.com           http:80   PHP 7.4.33          [EOL] -> Migrate to PHP 8.5.12 or a later stable 8.5 release; validate compatibility  [HTTP 200]
NOT AFFECTED*  fixed.example.com            https:443 PHP 8.5.12                -> Fixed minimum declared; verify runtime and package  [HTTP 200]
UNKNOWN        hidden.example.com           https:443 PHP not disclosed         -> Verify the web runtime and installed package  [HTTP 200]

Completed: 4 checks | 0.0s
VULNERABLE*: 2 | NOT AFFECTED*: 1 | UNKNOWN: 1
* Declared-version assessment; not proof of exploitability or effective remediation.
Red VULNERABLE*: the declared version falls within the affected rules.
Green NOT AFFECTED*: the declared version meets the fixed minimum for its branch, not proof that the server is generally safe.
Yellow UNKNOWN: evidence is missing, ambiguous, or outside the verified rules.
Yellow [EOL]: older branch outside upstream support according to the rules snapshot, not a live support lookup.
Results appear as checks complete; CSV rows retain input order. Colors are enabled automatically on compatible terminals and respect NO_COLOR. Use --color never for plain text or --color always to force ANSI codes. Colors never appear in the CSV. On older Windows terminals without ANSI support, use --color never. Long lines may wrap in narrow terminals.

What it does
Checks HTTP/80 and HTTPS/443 independently by default.
Makes one request attempt per unique target path and selected protocol. HEAD is the default; GET must be selected explicitly.
Inspects only Server and X-Powered-By headers for PHP version information.
Reports the protocol, port, HTTP status, declared version, banner-based assessment, and recommended upgrade.
Exports evidence, method, TLS verification setting, redirect destination, details, and UTC timestamp to CSV.
By default, the budget is at most two application requests per target: one HTTP and one HTTPS. Use --protocol https or --protocol http for at most one. DNS, connection, or TLS failures may prevent a request from being sent. Distinct paths on the same host count as distinct targets.

What it does not do
No exploitation, remote code execution, memory exhaustion, denial-of-service tests, or memory disclosure attempts.
No brute force, route discovery, network enumeration, or authentication.
No automatic HEAD-to-GET fallback or retries, including after HTTP 405 responses.
No redirects: Location is recorded but never followed.
No automatic phpinfo() requests, persistent cookies, or environment-configured proxies.
No response-body reads or analysis. A GET response may still be generated and transmitted by the server before the connection closes.
No confirmation of exploitability, effective backports, internal runtime state, or overall server security.
Requirements
Python 3.10 or later, preferably a currently supported release.
Windows, macOS, or Linux with Python's SSL module available.
DNS resolution when using hostnames, and connectivity to the selected ports.
A trusted certificate store for normal HTTPS verification.
Explicit authorization to assess every target.
No pip install, requirements.txt, administrator privileges, or local PHP installation is required. Git is optional unless you want to clone or contribute. For a virtual host, use its authorized DNS name rather than an IP that may serve a different default site.

Quick start
Download and extract the repository ZIP, or clone the repository using its GitHub Code menu. Open a terminal in the project directory:

python3 --version
python3 php2shell_scanner.py --help
python3 php2shell_scanner.py app.example.com -o results.csv
Replace example hosts with your authorized targets. Example domains are not suggested scan targets. On Windows, replace python3 with py -3, or with python if it selects Python 3.10 or later.

One request, HTTPS only
python3 php2shell_scanner.py app.example.com --protocol https
Select GET explicitly
If HEAD is unsupported, the checker records that response without retrying. You may perform a separate authorized GET check:

python3 php2shell_scanner.py app.example.com --protocol https --method GET
This is a new execution and an additional request. Choose a known read-only route.

Check a known application route
python3 php2shell_scanner.py https://app.example.com/login.php --protocol https
No routes are discovered automatically. A static root page or reverse proxy may not expose PHP. An https:// input URL does not select HTTPS by itself: use --protocol https. Otherwise both protocols are checked, preserving the supplied path and query. Only ports 80 and 443 are accepted. Embedded URL credentials are rejected.

Check a target file
Create targets.txt with one authorized target per line. You can copy targets.example.txt and replace its commented examples:

# Owned systems or explicit permission only
app.example.com
https://portal.example.com/known-route.php
python3 php2shell_scanner.py -f targets.txt -o results.csv --workers 1
Internal certificates
TLS verification is enabled by default. A certificate failure does not mean the server is unaffected. Fix the trust chain or, only when allowed by your assessment process, explicitly bypass verification:

python3 php2shell_scanner.py app.example.com --protocol https --insecure
The CSV records NOT verified. This weakens confidence in the server's identity and reported banners. Do not use it as your normal setting.

Classic table or plain output
python3 php2shell_scanner.py app.example.com --format table --color never
Options
Option	Meaning	Default
targets	One or more authorized domains, IP addresses, or URLs	None
-f, --file	Target file, one entry per line	None
-o, --output	Output CSV file	php2shell_results.csv
--protocol	both, http, or https	both
--method	HEAD or GET, without fallback	HEAD
--timeout	Seconds per socket operation, not a total scan or DNS deadline	5
--workers	Concurrency, from 1 to 16	1
--insecure	Skip TLS certificate verification	Disabled
--format	console for live lines or table for a table	console
--color	auto, always, or never	auto
Existing output files are overwritten. Choose another filename when retaining previous results.

CSV columns
Server, URL, Protocol, Port, HTTP, Method, PHP Version, Vulnerable, Upgrade To, Evidence, Redirect, TLS, Details, Timestamp UTC.

This English-only release changes the earlier Spanish CSV column names and values. Update any downstream spreadsheet imports or scripts accordingly.

Interpreting results
Console label	CSV Vulnerable value	Meaning
VULNERABLE*	Yes (by version)	Declared version falls within affected rules; verify vendor backports and actual web runtime
NOT AFFECTED*	No (by version)	Declared version meets the fixed minimum for its branch; corroborate the installed package and runtime
UNKNOWN	Unknown	Missing/incomplete version, suffixes, conflicting banners, connection failure, or version outside the known rules
Banners may be hidden, forged, stale, or supplied by a proxy. A load balancer may expose only one backend. Distribution packages may contain backports without changing the base version. Hiding X-Powered-By does not remediate PHP2Shell. php -v may describe CLI PHP rather than the PHP-FPM or web module serving the application.

Do not equate an unknown result with a safe server, a vulnerable banner with confirmed exploitation, or a fixed-looking banner with completed remediation.

Remediation rules
Static rules reviewed on October 22, 2026, using the sources below. No rule updates are downloaded at runtime.

Branch	Minimum fixed release for these CVEs
PHP 8.2	8.2.35
PHP 8.3	8.3.36
PHP 8.4	8.4.27
PHP 8.5	8.5.12
These are CVE-specific minimums, not necessarily the latest releases or a guarantee of future support. Check current PHP and distribution advisories before applying changes.

For covered branches from 5.4 through 8.1, the checker recommends migrating to PHP 8.5.12 or a later stable 8.5 release, subject to compatibility. Some older branches may have vendor packages or source backports requiring separate verification. Versions outside known rules remain unknown.

Test application and extension compatibility, follow the vendor's runtime restart/reload procedure, and verify all backends. Do not close remediation solely because a header disappeared or changed.

Tests
python3 -m unittest -v test_php2shell_scanner.py
python3 -m py_compile php2shell_scanner.py
Tests use simulated responses, not external scans. They cover version boundaries, ambiguous versions, request count, explicit GET, no fallback, redirects, HTTP/TLS failures, input handling, CSV output, no response-body reads, colors, and console formatting.

The included GitHub Actions workflow is configured for Python 3.10 through 3.14. Its results are only confirmed after it runs in your repository. Local testing does not establish compatibility on every OS or Python release.

Publishing and safe sharing
See the step-by-step GitHub publishing guide.

Do not upload real findings, inventories, internal hostnames, URL tokens, or client information.
.gitignore excludes CSV files and targets.txt, but every file still needs review before publication. It does not remove files already committed to Git.
Do not expand testing of someone else's exposure without permission. Contact the owner through their security channel.
Report tool bugs using synthetic examples with sensitive information removed.
Keep contributions focused on banner inspection. Do not add exploitation payloads or disruptive tests.
Sources
Tenable: PHP2Shell FAQ and affected/fixed versions
NCSC-NL: operational information about PHP2Shell
PHP: supported versions
PHP: downloads and available releases
