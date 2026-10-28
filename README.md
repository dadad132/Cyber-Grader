# Cyber Hygiene Grader

A website where businesses check how well their domain is protected. In about ten seconds it grades a domain's
email spoofing protection, HTTPS, browser security headers and DNS from A+ to F, with a plain-English fix list.
Customers sign up, buy credits or a 30-day plan through **Yoco**, and get an invoice for every payment.
You run it all from a **super-admin portal**.

The checks are passive: DNS records, one page load, a few TLS handshakes and two well-known files.
It never port-scans, brute-forces or logs in to anything.

## Install on AlmaLinux (production)

1. Get a server with AlmaLinux 8, 9 or 10. Rocky Linux and RHEL work too; 1 vCPU and 1 GB RAM is plenty to start.
2. Point your domain at it: an **A record** for e.g. `grader.yourdomain.co.za` pointing to the server's public IP.
3. Download the code onto the server from GitHub, then run the installer from inside it:

```
ssh root@your-server
dnf install -y git
git clone https://github.com/dadad132/Cyber-Grader.git /root/grader
cd /root/grader
sudo bash install.sh grader.yourdomain.co.za you@yourdomain.co.za
```

(Or copy the project folder over yourself, e.g. `scp -r Safety root@your-server:/root/grader`.)

The installer asks you to choose the super-admin password, then sets up:
- Python, the app in `/opt/cybergrader` and a systemd service;
- nginx and a free Let's Encrypt certificate (renewed automatically);
- the firewall and SELinux;
- a private DNS resolver (unbound, on 127.0.0.1 only) for blacklist lookups;
- a daily job that issues monthly account bills, emails bill and plan reminders, and keeps 14 days of database backups.

When it finishes, open `https://grader.yourdomain.co.za/admin/` and work through the **go-live checklist**
on the dashboard:

| Settings page | What to enter |
|---|---|
| Website & scanning | Business name, contact email and phone |
| Invoices & tax | Registered name, address, company reg. no., VAT registration and VAT number |
| Payments & pricing | Your **Yoco secret key**, then click **Register webhook with Yoco**. Also set credit-pack and plan prices, renewal reminder days, free sign-up credits and (optionally) the monthly account's fee, price per check, limit and days to pay. |
| Email | Your SMTP server, which sends invoices, password resets and plan reminders. Send a test email. |
| Legal pages | Review the starter terms and privacy policy, ideally with your legal adviser |

To **update** later, run `cd /root/grader && git pull` (or copy the new code over) and run the same `install.sh` command again. Your data
(`/var/lib/cybergrader`) and certificate are kept.

```
sudo cybergrader-manage status             # go-live checklist from the command line
sudo cybergrader-manage add-credits someone@example.com 10 --reason "Promo"
sudo cybergrader-manage set-admin-password
sudo cybergrader-manage backup /var/lib/cybergrader/manual-backup.db
sudo journalctl -u cybergrader -f          # live log
```

**Back up `/var/lib/cybergrader` somewhere else regularly.** It holds the database, including the
invoices you're legally required to keep, plus `settings.json`, which has your keys and passwords.

If the domain is proxied through Cloudflare (orange cloud), every visitor appears to come from a Cloudflare IP, so per-visitor
rate limits would treat them as one visitor. Switch the record to *DNS only*, or configure nginx's `real_ip` module for Cloudflare.

## Payments with Yoco

- **Keys:** get them in the Yoco app or portal under *Sales › Payment gateway*.
  - Test keys (`sk_test_…`) work immediately. Test payments produce invoices numbered `TEST-…`, so they never mix with real ones.
  - Live keys (`sk_live_…`) unlock once you verify your domain in the Yoco app.
  - Each time you switch between test and live keys, click **Register webhook with Yoco** again.
- **How a payment works:** the customer picks a pack or plan, pays on Yoco's hosted checkout page and returns to the site.
  The order is only marked paid when Yoco's signed webhook arrives. We verify its HMAC signature and timestamp, and check the amount matches.
- **Delivery:** credits or the plan are then added, and an invoice is issued and emailed. Webhook retries can't double-credit an order.
- **Plans (up to 6):** Yoco has no recurring billing, so a plan is bought for the number of days you set (30 for monthly,
  90 for quarterly, 365 for yearly). Customers get renewal emails on the days you choose (7, 3 and 1 days before by default)
  and one after it has ended, each with a link straight to renewing that plan. Renewing early adds the days and checks on top.
- **Monthly accounts (pay after use):** switch them on under *Payments & pricing*. The customer pays your monthly fee up front
  to open the account, then checks and downloads reports during the month; checks they run with no credits or plan checks
  left go on the account at your price per check. On the same day each month they get one itemised bill: that month's
  checks plus next month's fee. Bills are due within the days you set (3 by default), with a reminder the day before. An
  unpaid bill puts the account **on hold**, so checks on it stop until it's paid; paying (by card, or *Mark paid* for an EFT)
  takes it off hold straight away. A monthly check limit caps what anyone can run up before paying. Customers can close the
  account under *Account*; it closes on its next billing day with a final bill for the checks used and no new fee. In the
  admin portal, each customer's page shows their account and has **Open without payment**, **Bill now** and **Close**.
- **Bills and reminders are sent by the daily job** at 07:00 (`cybergrader-manage daily`, set up by the installer). To run
  it by hand: `cybergrader-manage bill-accounts` or `cybergrader-manage send-reminders`.
- **Missed webhooks:** if a payment shows in the Yoco app but is still pending here, use **Payments › Mark paid**.
  That delivers what was bought and issues the invoice. The same button works for EFTs you receive directly.

## Invoices

- **Numbering:** every paid order gets an invoice numbered `INV-00001`, `INV-00002`, … with no gaps. The prefix is configurable.
- **What's on it:** your registered details and the customer's company, VAT number and address, which they enter under *Account*.
- **Tax invoices:** if you tick *VAT registered*, invoices become **tax invoices** showing your VAT number and the VAT included in each price. Prices you set include VAT.
- **Records:** each invoice keeps a frozen copy of those details, so later changes never rewrite old invoices.
- **Access:** customers find them under *Invoices* and can print them or save them as a PDF.

## Customers' accounts

- **Sign-up:** name, email, password and an optional company. New accounts get free credits; you set how many, and 0 means none.
- **Credits, plans and monthly accounts:** one credit = one check of one domain, and credits never expire. Plan checks are
  used first, then credits, then the monthly account (if they have one).
  If a check can't run (the domain doesn't exist, DNS fails) the customer isn't charged. Re-opening a saved report is free,
  and checking the same domain again within 10 minutes shows the earlier report instead of charging twice.
- **Reports:** kept in the account and can be downloaded as a standalone HTML file or printed to PDF.
- **Account page:** invoice details, password change (which signs out other devices), credit history, and a personal
  **API key** for `GET /api/grade?domain=…` with the `X-API-Key` header. Each API check uses a credit too.
- **Password reset:** by email, with a one-hour, single-use link.

## IT providers managing clients

An IT firm (e.g. managing@itfirm.co.za) can look after many client domains from one account:

1. **Add the client** under *Clients*: company name, domain (a.co.za) and a contact **at that domain** (compony@a.co.za).
2. **The client approves.** We email the contact a link. Approving needs a click, so email security scanners that open links
   don't approve by accident. Because the email reaches a mailbox at the client's own domain, the approval proves the client
   controls it. The same link lets the client withdraw access later, and the firm is emailed either way.
3. **Check and fix.** The firm runs checks with its own credits or plan; you invoice the firm as usual. Reports for client
   domains show who authorised them, and your "have us fix it" offer is hidden so you never compete with your own customer.
4. **Send the report and a quote.** For approved clients only, the firm emails the PDF report, its own message and an optional quote.
   The email shows "IT Firm via EasyMikroTik", and replies go to the firm. The client pays the firm directly.

The firm sets the name, email, phone and website that appear on its reports under *Account › Your business on client reports*.
Those PDFs say "Powered by EasyMikroTik" in small print. Sending is rate-limited (5 emails per client per day) so it can't be used for spam.

## Free checks, owner unlocks and leads

- **Free summary:** anyone can check a domain from the home page or a tool page. They see the grade, the score per area, and how
  many problems there are by severity. They don't see which checks failed or how to fix them, so the site can't be used to scout
  other companies' weak spots.
- **Unlocking the full report:**
  - **With a credit:** for a signed-in customer. Unlocking reuses the free check, with no second scan.
  - **Free for the verified owner:** a 6-digit code goes to a mailbox at that domain, e.g. info@theirdomain. Codes expire after 15 minutes and allow 5 attempts, and sending is rate-limited. The owner is emailed the PDF, and becomes a lead.
  - **Super admin:** always sees everything.
- **"Have us fix it":** every report, free or paid, offers a quote request with a typical "from" price based on how much work the report needs.
  Requests land in **Super admin › Leads** (new → contacted → won/lost) and are emailed to you.
- **Settings:** prices, the free-check limit and the owner unlock are under **Settings › Free checks, leads & SEO**.

## Search engines (SEO)

- **Pages:** the home page targets *domain health check*. Seven tool pages target what people actually search for:
  `/email-security-check`, `/dmarc-check`, `/spf-check`, `/dkim-check`, `/ssl-check`, `/security-headers-check` and `/dns-security-check`.
  Each has its own title, description, explanation, FAQ and a free-check box.
- **Behind the scenes:**
  - pages carry canonical URLs, social-sharing tags and structured data (organisation, web app, FAQ, breadcrumbs);
  - `/robots.txt` and `/sitemap.xml` are generated;
  - accounts, reports and other people's results are marked `noindex`.
- **After going live:**
  1. Add the site to [Google Search Console](https://search.google.com/search-console) with the *HTML tag* method, and paste the code under **Settings › Free checks, leads & SEO**.
  2. Submit `/sitemap.xml` there.
  3. Link to the checker from easymikrotik.com, for example a menu item and footer link reading "Free domain health check".
  4. Create a Google Business Profile.

  No wording can guarantee the top result. Ranking also depends on links, age and competition; the pages give Google everything it needs to rank them.

## Building network audits

For on-site visits, the agent checks the building network from the **inside**:
- the router's management ports (Telnet, FTP, Winbox, the RouterOS API, web admin, SNMP, SSH);
- UPnP;
- devices exposing file shares, RDP, cameras or printers to the network;
- Wi-Fi encryption and signal;
- latency.

It also triggers one **outside** check: the grader server (on the internet) looks back at the public IP the upload came
from and reports whether router-management ports are open to the whole internet (the key MikroTik check). For safety the
server only ever checks **the public IP the request came from** — the network the technician is on — never a target named
in the request, so it can't be used to scan anyone else. This check needs the grader on a real internet server and the
upload to come from the office; a local test (uploading from the same PC) skips it and lists it as "not checked".

Anything it can't measure is listed as "not checked" and left out of the score. Results upload to the customer's account with their API key.

```
python tools/lan_agent.py --server https://check.easymikrotik.com --api-key cg_... --site "Client office"
python tools/lan_agent.py --output audit.json      # save locally instead
```

The agent needs only Python 3.8+. There's also an **Android app** (`mobile_app/`, built to `tools/building-network-audit.apk`).
Both are downloadable from the website, and **`/network-audit`** is the step-by-step guide for customers: getting an API key,
installing the app, running an audit, reading the results and troubleshooting. It's linked from the Dashboard and Account pages.
`mobile_app/README.md` explains how to rebuild the APK. Only audit networks you own or are authorised to test.

**Testing the app against this PC:** the phone can't reach `127.0.0.1`, so start the site on your network with
`python -m cybergrader.webapp --host 0.0.0.0` (allow Python through Windows Firewall when asked). In the app, use
`http://<this PC's IP>:8000` as the grader address.

## Try it on Windows

Double-click **`Start Grader.bat`**. It installs anything missing, starts the site at http://127.0.0.1:8000/
and opens the super-admin portal, which asks you to create a password on the first visit. Everything works locally
except confirming Yoco payments, because Yoco can't reach a webhook on your PC. Use *Mark paid* to test the flow.

## What it checks (25 checks, 124 points)

| Category | Checks |
|---|---|
| **Email Security** (39) | SPF (full include/redirect walk, 10-lookup limit, `+all`, duplicates) · DMARC (proper tag parsing, `sp=`, `pct=`, `rua=`, inherited from the parent domain) · DKIM (35 common selectors) · MTA-STS (record and policy file) · TLS-RPT · STARTTLS on the mail servers (port 25, with certificate check) |
| **Blacklists & Reputation** (20) | Own mail server IPs on 9 spam blacklists (Spamhaus ZEN, Barracuda, SpamCop, UCEPROTECT 1, PSBL, Mailspike, blocklist.de, 0spam, GBUdb) · the domain on Spamhaus DBL, SURBL and URIBL (spam, phishing, malware, hacked site) · reverse DNS (PTR) of the mail servers, forward-confirmed |
| **HTTPS & TLS** (25) | Trusted certificate (explains expired, wrong host, self-signed or incomplete chain) · renewal runway (scaled to the certificate's lifetime) · TLS 1.3 · TLS 1.0/1.1 refused · HTTP→HTTPS redirect |
| **Web Security Headers** (30) | HSTS (max-age) · CSP (flags `unsafe-inline` and wildcards) · clickjacking (XFO or `frame-ancestors`) · nosniff · Referrer-Policy · Permissions-Policy · version banners · cookie flags |
| **Domain & DNS** (10) | CAA (walks up the DNS tree per RFC 8659) · DNSSEC · security.txt |

**Which mail servers are checked for blacklists.** The domain's own ones: its MX hosts, plus the servers its SPF record
names directly (single `ip4:` addresses, `a`, `mx`). Big providers (Google, Microsoft, Zoho, Mimecast, ...) and SPF
`include:`s are left out, because their reputation is the provider's job and nothing the customer can change.

**Scoring.** Each check earns full, partial or zero points, and the score is the percentage of the points that could
be measured. Bands: A ≥ 90, B ≥ 80, C ≥ 65, D ≥ 50, else F.
An A+ needs 97+ with no medium-or-worse findings.

**Caps.** A critical issue caps the grade at C, and a high-severity issue caps it at B.
This means a domain anyone can spoof can't get an A just for having good headers. A domain on a phishing or malware
blocklist is critical; a mail server on Spamhaus, Barracuda or SpamCop is high.

**Unscored results:**
- Checks that don't apply aren't scored, for example DKIM or MTA-STS when the domain has no mail servers, or every web check when it has no website.
- Lookups that time out show as "couldn't determine" rather than as failures.
- If under 80% of the checks complete, the grade is marked provisional.

## How accurate is it?

- **Facts are exact.** Everything is read live from the internet at the moment of the check: DNS records,
  certificates, TLS versions, redirects and response headers. A "missing DMARC record" or "certificate expires in
  5 days" is exactly what the rest of the world sees. The parsers follow the RFCs, for example SPF lookup limits and
  includes, DMARC tag parsing and inheritance, and CAA tree climbing. They are covered by automated tests and were
  checked against known-good and deliberately broken test sites (badssl.com).
- **Known blind spots:**
  - **DKIM:** keys can only be found under 35 common selector names. If none match, it's shown as a note, not a failure.
  - **Homepage only:** only the homepage's headers and cookies are checked, not every page.
  - **Blocked scanner:** some sites block automated visitors. The report notes when the homepage answered 403.
  - **One vantage point:** results reflect your server's view of the domain, which almost always matches everyone else's.
  - **Port 25:** many networks (home connections, some clouds) block outgoing port 25. The STARTTLS check then says
    "not tested" instead of failing; on a normal server it works.
- **Blacklists never give false alarms from refusals.** Spamhaus, SURBL and URIBL answer lookups they refuse (e.g.
  through Google or Cloudflare DNS) with codes that look like listings, and lists that shut down sometimes "list"
  everything. Every answer is checked against each list's documented codes, and each list must first answer its
  RFC 5782 test entries correctly; a list that doesn't is shown as "couldn't check", never as a listing. The admin
  dashboard's system check shows which lists answer from your server. On the server, the installer sets up a
  private resolver (unbound, 127.0.0.1) so Spamhaus answers. For commercial volumes Spamhaus requires a free or paid
  **Data Query Service key** (spamhaus.com): enter it under *Website & scanning › Blacklist checks*.
- **The grade is a judgement.** The letter grade reflects how the issues are weighted, and the caps stop a spoofable
  domain getting an A. It's a strong indicator of security hygiene, not a penetration test: it can't see
  vulnerable software, weak passwords or anything behind a login.

## Command line

```
python -m cybergrader example.com                     # coloured terminal report
python -m cybergrader example.com -v                  # include the evidence (records, headers)
python -m cybergrader example.com --json              # machine-readable output
python -m cybergrader example.com --html report.html --brand "EasyMikroTik" --brand-url https://easymikrotik.com
python -m cybergrader -f clients.txt --html reports/  # batch: one HTML file per domain
python -m cybergrader -f clients.txt --fail-under B   # exit code 2 if any domain is below B (monitoring/CI)
```

URLs work too (`https://example.com/contact` is graded as `example.com`). The HTML report is a
single self-contained file that works offline, adapts to light and dark mode, and prints cleanly to PDF.
Business details, timeout, DNS servers and user agent default to what's set in the super-admin portal.
The command line is free and unlimited for you; credits only apply to customers on the website.

## Python API

```python
from cybergrader import grade_domain

report = grade_domain("example.com")
print(report.grade, report.score)
for finding in report.findings:          # sorted most severe first
    print(finding.severity.value, finding.title, finding.fix)
data = report.to_dict()                  # includes the v1 keys: passed_checks, vulnerabilities_and_fixes
```

The original `CyberHygieneGrader("example.com").run_full_grade()` still works.

## Layout

```
install.sh                                    AlmaLinux installer/updater (nginx, certbot, systemd, firewall, SELinux)
Start Grader.bat                              run it on Windows
cybergrader/
  checks/mail.py, smtp.py, reputation.py,
         tls.py, web.py, domain.py            the 25 checks, registered with @check(id, category, title, points)
  dnsbl.py                                    blacklist lookups with answer-code and RFC 5782 test-entry validation
  grader.py, report.py, pdf.py                scoring and grade caps; terminal, HTML and PDF reports
  site.py, accounts.py                        customer website: sign-up, credits, plans, paid checks, API keys
  preview.py, leads.py, seo.py                free checks and owner unlocks; fix-it leads; search pages, robots, sitemap
  lan.py                                      building network audit grading
  billing.py, mailer.py                       Yoco checkout + signed webhooks, orders, invoices; SMTP email
  postpaid.py                                 monthly accounts: bills, on hold when unpaid, bill emails
  admin.py, settings.py, selfcheck.py         super-admin portal, settings, environment checks
  db.py, manage.py, service.py                SQLite storage; server maintenance commands; scan limits
  templates/                                  website, super-admin, invoice and email templates
  cli.py, webapp.py                           command line; web app factory
tools/lan_agent.py                            on-site building network agent (standard library only)
mobile_app/                                   the same audit as a Flutter app
tests/                                        offline tests (fake DNS, fake scanner, signed test webhooks): python -m pytest
```

To add a check, write a function in the relevant `checks/` module that takes the scan context and
returns `Outcome.ok(...)`, `Outcome.warn(...)` or `Outcome.fail(...)`, then decorate it with
`@check("my_id", CATEGORY, "Title", points)`. It is picked up automatically.
