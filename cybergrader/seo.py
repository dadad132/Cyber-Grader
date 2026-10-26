"""Search-engine pages: one landing page per search intent (DMARC check, SPF check, SSL check, ...),
plus robots.txt and sitemap.xml. Each page runs the same free domain health check."""
from __future__ import annotations

import json

from flask import Blueprint, Response, render_template, request, url_for
from markupsafe import Markup

from .service import GraderService
from .settings import Settings

# slug -> page content. Titles stay under ~60 characters and descriptions under ~155 for search results.
TOOLS = {
    "email-security-check": {
        "phrase": "email security check",
        "nav": "Email security check",
        "title": "Email Security Check: Can Your Domain Be Spoofed?",
        "h1": "Email security check",
        "description": "Free email security test: find out if criminals can send email as your business. Checks SPF, DMARC, DKIM, MTA-STS and TLS reporting in seconds.",
        "lede": "Business email compromise and fake invoices start with one weakness: a domain that anyone can send email from. This free check shows whether yours is protected.",
        "sections": [
            ("What the email security check looks at",
             "We read your domain's public email records the same way every mail server on the internet does: the SPF record that lists who may send for you, the DMARC policy that tells receivers what to do with fakes, DKIM signing keys, MTA-STS (which forces encrypted delivery to you) and TLS reporting. Each one gets a pass or a fix, written in plain English."),
            ("Why it matters",
             "Without an enforced DMARC policy, a scammer can send an email that shows your exact address in the From line, asking your customers to pay into a new bank account. It is one of the most common and expensive frauds against South African businesses, and it is preventable with a few DNS records."),
            ("How to fix the usual problems",
             "Most domains need three things: one SPF record that lists every service that sends email for you, DKIM switched on in your email provider (Microsoft 365, Google Workspace and others), and a DMARC record that starts at p=none for monitoring and moves to p=quarantine or p=reject once the reports look clean. The full report gives you the exact records to publish."),
        ],
        "faqs": [
            ("Is the email security check free?", "Yes. You see your grade and how many problems there are for free. The detailed fixes unlock with a credit, or free if you verify that you own the domain."),
            ("Will the check send email from my domain?", "No. It only reads public DNS records. Nothing is sent and nothing on your systems changes."),
            ("Which email providers does it work with?", "All of them: Microsoft 365, Google Workspace, Zoho, cPanel and any other host, because the records it checks are standard."),
        ],
    },
    "dmarc-check": {
        "phrase": "DMARC check",
        "nav": "DMARC check",
        "title": "DMARC Check: Free DMARC Record Checker",
        "h1": "DMARC checker",
        "description": "Check your DMARC record for free: policy (none, quarantine, reject), subdomain policy, reporting addresses and percentage, with plain-English fixes.",
        "lede": "DMARC is the record that tells the world's mail servers to reject email that pretends to come from you. This checker finds your DMARC record and explains whether it actually protects you.",
        "sections": [
            ("What the DMARC check verifies",
             "We look up _dmarc.yourdomain, including policies inherited from a parent domain, and parse every tag properly: the policy (p=), the subdomain policy (sp=), the percentage (pct=) and whether reports (rua=) are going anywhere. A record that exists but says p=none is reported as monitoring only, because it doesn't stop a single fake email."),
            ("Common DMARC mistakes",
             "Publishing two DMARC records (receivers then ignore both), leaving the policy on p=none forever, setting a strong p=reject but a weak sp=none so attackers simply use a made-up subdomain, and having no reporting address so you never see who is sending as you."),
            ("Moving to p=reject safely",
             "Start with p=none and a reporting address, check the reports for a few weeks to confirm your real senders pass SPF or DKIM, then move to p=quarantine and finally p=reject. The report includes a ready-to-paste record for your domain."),
        ],
        "faqs": [
            ("What is a good DMARC policy?", "p=reject gives full protection. p=quarantine sends fakes to spam. p=none only monitors and doesn't stop spoofing."),
            ("Does DMARC need SPF and DKIM?", "Yes. DMARC passes when SPF or DKIM passes and matches your domain, so both should be set up properly."),
            ("How long does a DMARC change take?", "Usually minutes to a few hours, depending on your DNS provider's TTL."),
        ],
    },
    "spf-check": {
        "phrase": "SPF record check",
        "nav": "SPF check",
        "title": "SPF Record Check: Free SPF Validator & Lookup Counter",
        "h1": "SPF record checker",
        "description": "Validate your SPF record free: syntax, the 10-DNS-lookup limit, duplicate records, includes that no longer exist, and whether it ends in -all or ~all.",
        "lede": "SPF lists the servers that may send email for your domain. A missing or broken SPF record lets anyone send as you, and a record over the 10-lookup limit silently breaks your own email.",
        "sections": [
            ("What the SPF check verifies",
             "We fetch your SPF record and follow every include and redirect exactly as a receiving mail server would. That catches the problems simple lookups miss: more than 10 DNS lookups (which makes receivers reject your SPF outright), includes that point to domains with no SPF record, duplicate SPF records, and dangerous endings like +all."),
            ("-all or ~all?",
             "Both are fine when DMARC is enforcing. -all tells receivers to fail unlisted servers outright; ~all marks them as suspicious and lets DMARC decide. Records that end in ?all or have no 'all' at all give no protection."),
            ("Fixing an SPF record over the lookup limit",
             "Remove includes for services you no longer use, and replace large includes with the IP ranges they cover. Keep exactly one record that starts with v=spf1."),
        ],
        "faqs": [
            ("Can I have two SPF records?", "No. Two records count as an error and SPF fails for all your mail. Merge them into one."),
            ("What is the SPF 10-lookup limit?", "SPF may trigger at most 10 DNS lookups (include, a, mx, ptr, exists and redirect). Above that, receivers treat your SPF as broken."),
            ("Does SPF stop spoofing on its own?", "Not completely. SPF checks a hidden envelope address, so you also need DMARC to protect the From address people see."),
        ],
    },
    "dkim-check": {
        "phrase": "DKIM check",
        "nav": "DKIM check",
        "title": "DKIM Check: Find and Test Your DKIM Keys",
        "h1": "DKIM checker",
        "description": "Free DKIM check: we look for your DKIM public keys under the selectors used by Microsoft 365, Google Workspace, Zoho, Mailchimp and other senders.",
        "lede": "DKIM adds a tamper-proof signature to every email you send. Together with DMARC, it's the most reliable way to prove your mail is genuine.",
        "sections": [
            ("How the DKIM check works",
             "DKIM keys live under a 'selector' name that each email service chooses. We look under 35 common selectors, including selector1 and selector2 (Microsoft 365), google (Google Workspace), k1 (Mailchimp), s1 and s2 (SendGrid) and default, and report any keys we find, including revoked ones."),
            ("If no key is found",
             "Your provider may use a custom selector. Open an email you sent, view the original message and find the s= value in the DKIM-Signature header; that's your selector. If there's no DKIM-Signature at all, DKIM is switched off and you should enable it in your email admin console."),
        ],
        "faqs": [
            ("How do I turn on DKIM in Microsoft 365?", "In the Microsoft Defender portal under Email authentication settings, publish the two CNAME records it gives you, then enable signing."),
            ("How do I turn on DKIM in Google Workspace?", "In the Admin console under Apps > Gmail > Authenticate email, generate a key, publish the TXT record and click Start authentication."),
            ("Is DKIM required for DMARC?", "DMARC needs SPF or DKIM to pass. DKIM is more reliable because it survives email forwarding."),
        ],
    },
    "ssl-check": {
        "phrase": "SSL certificate check",
        "nav": "SSL certificate check",
        "title": "SSL Certificate Checker: Expiry, Trust & TLS Test",
        "h1": "SSL certificate checker",
        "description": "Free SSL check: certificate trust and expiry, hostname match, incomplete chains, TLS 1.3 support, old TLS 1.0/1.1 and HTTP-to-HTTPS redirects.",
        "lede": "An expired or misconfigured certificate shows visitors a full-page security warning and breaks apps that talk to your site. This check catches it before your customers do.",
        "sections": [
            ("What the SSL check verifies",
             "We connect to your website like a modern browser and verify the certificate against the trusted CA list: is it trusted, does it match the hostname, is the full chain installed, and how long until it expires? We also test whether the server still accepts the obsolete TLS 1.0 and 1.1 protocols, whether TLS 1.3 is available, and whether plain HTTP redirects to HTTPS."),
            ("Common certificate problems",
             "An incomplete chain is the sneakiest: desktop browsers often cope, but phones, payment gateways and API clients refuse to connect. Expired certificates usually mean automatic renewal broke silently. Hostname mismatches happen when www and the bare domain aren't both covered."),
            ("Fixing them",
             "Free Let's Encrypt certificates renew automatically with certbot or your host's control panel. Install the full chain file (fullchain.pem), cover both yourdomain and www.yourdomain, and set the minimum TLS version to 1.2 on your server or CDN."),
        ],
        "faqs": [
            ("How often should I check my SSL certificate?", "Let's Encrypt certificates last 90 days and renew at 30, so a monthly check catches failed renewals in time."),
            ("Why is TLS 1.0 a problem?", "TLS 1.0 and 1.1 were deprecated in 2021 (RFC 8996), have known weaknesses and fail PCI DSS card-security requirements."),
            ("Does this check work for any website?", "Yes, for any public website on port 443."),
        ],
    },
    "security-headers-check": {
        "phrase": "security headers check",
        "nav": "Security headers check",
        "title": "Security Headers Check: HSTS, CSP & More",
        "h1": "Security headers checker",
        "description": "Test your website's security headers free: HSTS, Content-Security-Policy, clickjacking protection, nosniff, Referrer-Policy, Permissions-Policy and cookies.",
        "lede": "Security headers are instructions your website gives to visitors' browsers. A handful of them block whole classes of attacks, such as script injection, clickjacking and cookie theft, at almost no cost.",
        "sections": [
            ("What the headers check looks at",
             "We load your homepage once and grade HSTS (and its max-age), Content-Security-Policy (including risky 'unsafe-inline' and wildcard sources), clickjacking protection, X-Content-Type-Options, Referrer-Policy and Permissions-Policy. We also look for server version banners and cookies missing the Secure, HttpOnly or SameSite flags."),
            ("Where to add headers",
             "In nginx use add_header, in Apache Header always set, in IIS the HTTP Response Headers feature, and on Cloudflare Transform Rules. WordPress sites can also use a security plugin. The full report lists exactly which headers to add."),
        ],
        "faqs": [
            ("Which security header matters most?", "HSTS and a Content-Security-Policy give the biggest protection. Clickjacking and nosniff headers are quick wins."),
            ("Can security headers break my site?", "A strict Content-Security-Policy can block scripts you use. Trial it with Content-Security-Policy-Report-Only first."),
            ("Why does the report say my site blocked the check?", "Some bot protection returns an error page to automated visitors; the report notes when that happens so you can read the results accordingly."),
        ],
    },
    "dns-security-check": {
        "phrase": "DNSSEC and CAA check",
        "nav": "DNSSEC & CAA check",
        "title": "DNS Security Check: DNSSEC, CAA & security.txt",
        "h1": "DNS security check",
        "description": "Free DNS security test: DNSSEC signing, CAA records that control who can issue your certificates, and a security.txt contact for researchers.",
        "lede": "Your domain's DNS decides where your email and website traffic go. These protections stop attackers forging DNS answers or getting a certificate issued for your domain.",
        "sections": [
            ("What the DNS check verifies",
             "DNSSEC: whether your zone is signed and its parent publishes a DS record, so resolvers can detect forged answers. CAA: whether you've limited which certificate authorities may issue certificates for your domain (checked up the DNS tree as RFC 8659 requires). security.txt: whether you publish a contact for people who find vulnerabilities."),
            ("Turning them on",
             "Many DNS hosts, Cloudflare among them, offer DNSSEC as a simple switch; you then add the DS record they give you at your registrar. CAA is one DNS record per certificate authority you use. security.txt is a small text file at /.well-known/security.txt."),
        ],
        "faqs": [
            ("Does every domain support DNSSEC?", "Most domain endings do. Your DNS host signs the zone and you add the DS record at your registrar; ask them if you're unsure."),
            ("Will a CAA record break my certificate renewals?", "Not if it lists every CA you use. The report suggests a record based on your current certificate's issuer."),
            ("Is security.txt required?", "No, but it's a simple, recommended way to receive vulnerability reports instead of having them ignored or made public."),
        ],
    },
}


def landing_faqs(settings: Settings) -> list[tuple[str, str]]:
    """The home page FAQ, shared by the visible page and its structured data."""
    days = settings.plans[0]["days"] if settings.plans else 30
    invoice = "a VAT tax invoice" if settings.vat_registered else "an invoice"
    return [
        ("What is a domain health check?",
         "A domain health check tests the public settings that protect your business domain: email authentication "
         "(SPF, DMARC, DKIM, MTA-STS), the website's SSL certificate and TLS versions, browser security headers, and DNS "
         "protections like DNSSEC and CAA. It shows whether criminals could send email as you or intercept your traffic."),
        ("Is it safe and legal to check a domain?",
         "Yes. The checks are passive: we read public DNS records, load the home page once and open a few normal secure "
         "connections, exactly what a browser or mail server does. We never scan ports, guess passwords or try to break in."),
        ("Is the domain health check free?",
         "Yes. Anyone can check a domain and see its grade, score and how many problems it has. The detailed fixes unlock "
         "with a credit, or free if you verify that you own the domain with a code sent to an email address at that domain."),
        ("How accurate is it?",
         "The facts are read live from the internet at the moment of the check, so a missing DMARC record or a certificate "
         "about to expire is exactly what the rest of the world sees. DKIM can only be found under common selector names, only "
         "the home page's headers are checked, and some sites block automated visitors; the report says when that happens. "
         "The grade is a strong indicator of security hygiene, not a full penetration test."),
        ("What does a credit buy?",
         "One complete check of one domain with the full report, PDF and fix list saved in your account. Credits never expire, "
         "and if a check can't run you aren't charged."),
        ("How does the monthly plan work?",
         f"You pay once through Yoco and get the plan's checks for the next {days} days. Nothing is debited automatically: "
         "we email you before it ends and you can renew with one click."),
        ("How do I pay, and do I get an invoice?",
         f"Payments are processed by Yoco by card or Instant EFT; we never see your card details. You get {invoice} for every payment."),
        ("Can you fix the problems for us?",
         "Yes. Every report has a 'have us fix it' button. Tell us what you need and we'll quote and do the work: DNS records, "
         "email authentication, certificates, server headers and network security."),
    ]


def faq_schema(faqs: list[tuple[str, str]]) -> dict:
    return {"@type": "FAQPage", "mainEntity": [
        {"@type": "Question", "name": q, "acceptedAnswer": {"@type": "Answer", "text": a}} for q, a in faqs]}


def jsonld(*items: dict) -> Markup:
    """A JSON-LD block. '</' is escaped so text can never close the script element early."""
    data = {"@context": "https://schema.org", "@graph": list(items)}
    text = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    return Markup(f'<script type="application/ld+json">{text}</script>')


def create_seo_blueprint(service: GraderService) -> Blueprint:
    bp = Blueprint("seo", __name__)
    store = service.store

    def base_url() -> str:
        return store.current.site_url.rstrip("/") or request.host_url.rstrip("/")

    def tool_view(slug: str):
        def view():
            return render_template("site/tool.html", slug=slug, page=TOOLS[slug], tools=TOOLS, active="tools")
        view.__name__ = f"tool_{slug.replace('-', '_')}"
        return view

    for slug in TOOLS:
        bp.add_url_rule(f"/{slug}", endpoint=f"tool_{slug.replace('-', '_')}", view_func=tool_view(slug))

    @bp.get("/robots.txt")
    def robots():
        lines = ["User-agent: *", "Disallow: /app", "Disallow: /admin", "Disallow: /api/", "Disallow: /reset/",
                 "Disallow: /billing/", "", f"Sitemap: {base_url()}/sitemap.xml", ""]
        return Response("\n".join(lines), mimetype="text/plain")

    @bp.get("/sitemap.xml")
    def sitemap():
        pages = [(url_for("site.landing"), "1.0"), (url_for("site.pricing"), "0.8")]
        pages += [(url_for(f"seo.tool_{slug.replace('-', '_')}"), "0.9") for slug in TOOLS]
        pages += [(url_for("site.signup"), "0.5"), (url_for("site.terms"), "0.2"), (url_for("site.privacy"), "0.2")]
        entries = "".join(f"<url><loc>{base_url()}{path}</loc><priority>{priority}</priority></url>" for path, priority in pages)
        xml = f'<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{entries}</urlset>\n'
        return Response(xml, mimetype="application/xml")

    @bp.app_context_processor
    def seo_helpers():
        return {"tool_pages": [(f"seo.tool_{slug.replace('-', '_')}", page["nav"]) for slug, page in TOOLS.items()],
                "landing_faqs": landing_faqs, "faq_schema": faq_schema, "jsonld": jsonld, "seo_base": base_url(),
                "landing_schema": landing_schema}

    return bp


def landing_schema(settings: Settings, base: str) -> list[dict]:
    """Organisation, website, the free web app and the FAQ, for the home page's structured data."""
    organisation = {"@type": "Organization", "name": settings.business_name, "url": settings.brand_url or f"{base}/"}
    if settings.contact_email:
        organisation["email"] = settings.contact_email
    if settings.contact_phone:
        organisation["telephone"] = settings.contact_phone
    app_name = f"{settings.business_name} Domain Health Check"
    return [
        organisation,
        {"@type": "WebSite", "name": app_name, "url": f"{base}/"},
        {"@type": "WebApplication", "name": app_name, "url": f"{base}/", "applicationCategory": "SecurityApplication",
         "operatingSystem": "Any (web browser)",
         "description": "Free domain health check: email security (SPF, DMARC, DKIM), SSL certificate, security headers and DNS.",
         "offers": {"@type": "Offer", "price": "0", "priceCurrency": "ZAR"}},
        faq_schema(landing_faqs(settings)),
    ]
