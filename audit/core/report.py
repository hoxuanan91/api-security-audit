import json
from datetime import datetime
from audit.core.models import AuditResult, Status, Severity
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.text import Text

console = Console()

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

STATUS_ICONS = {
    Status.FAIL: "[red]FAIL[/red]",
    Status.PASS: "[green]PASS[/green]",
    Status.WARN: "[yellow]WARN[/yellow]",
    Status.SKIP: "[dim]SKIP[/dim]",
}

# Human-readable name shown in the table instead of "API1:2023"
FRIENDLY_CHECK_NAMES = {
    "API1:2023": "Unauthorized Data Access",
    "API2:2023": "Missing Authentication",
    "API3:2023": "Sensitive Data Leaked",
    "API4:2023": "No Rate Limiting",
    "API5:2023": "Admin Endpoints Exposed",
    "API7:2023": "Request Forgery (SSRF)",
    "API8:2023": "Security Misconfiguration",
}

# Plain-English explanation + concrete real-world example per check
PLAIN_ENGLISH = {
    "API1:2023": {
        "what": (
            "Any authenticated user can access data that belongs to someone else "
            "simply by changing an ID number in the URL. The API does not verify "
            "that the requester actually owns that resource."
        ),
        "example": (
            "You are customer #42 on an e-commerce site. Your order history is at "
            "/api/orders/42. By typing /api/orders/43 in the browser you can see "
            "another customer's full order history — their address, items, and payment method."
        ),
        "impact": "Full exposure of other users' private data.",
    },
    "API2:2023": {
        "what": (
            "The API does not properly check who is making the request. "
            "Private endpoints can be reached without a login, or with a completely "
            "fake/expired token."
        ),
        "example": (
            "A banking app exposes /api/accounts/transactions. "
            "An attacker opens that URL in a browser with no login at all "
            "and receives a full list of recent transactions."
        ),
        "impact": "Anyone on the internet can read or modify protected data.",
    },
    "API3:2023": (
        {
            "what": (
                "The API response contains sensitive information that was never "
                "meant to be visible to the end user — passwords, tokens, "
                "internal file paths, credit card numbers, or stack traces."
            ),
            "example": (
                "A mobile app calls /api/user/profile to display a name and avatar. "
                "The JSON response also includes the user's hashed password, "
                "their internal database ID, and a private API key — "
                "none of which the app actually needs."
            ),
            "impact": "Credential theft, identity theft, or full account takeover.",
        }
    ),
    "API4:2023": {
        "what": (
            "The API lets a single client send unlimited requests with no slowdown "
            "or block. There is no mechanism to detect or stop abusive traffic."
        ),
        "example": (
            "An attacker writes a script that tries 10,000 different passwords "
            "per minute on /api/login. Without rate limiting, the server "
            "processes every single request, making brute-force attacks trivial."
        ),
        "impact": "Account takeover via brute force, denial of service, sky-high hosting bills.",
    },
    "API5:2023": {
        "what": (
            "Sensitive administrative or internal pages are reachable by regular users "
            "or without any authentication. Only privileged roles should access these."
        ),
        "example": (
            "The /admin/users endpoint lists all registered users with their emails "
            "and roles. It returns data to anyone who knows the URL, "
            "even without an admin account."
        ),
        "impact": "Full access to admin features, user management, or system internals.",
    },
    "API7:2023": {
        "what": (
            "The API accepts a URL as input and then fetches it from the server side. "
            "An attacker can supply an internal address to make the server read "
            "files or services that should never be publicly accessible."
        ),
        "example": (
            "A feature lets users import a profile picture from a URL. "
            "An attacker submits http://169.254.169.254/latest/meta-data/ "
            "(AWS cloud metadata). The server fetches it internally and returns "
            "the cloud credentials back to the attacker."
        ),
        "impact": "Exposure of cloud credentials, internal network access, full server compromise.",
    },
    "API8:2023": {
        "what": (
            "The server is missing standard security settings that modern browsers "
            "and clients rely on. This includes missing HTTP headers that prevent "
            "common attacks, or an overly permissive cross-origin policy."
        ),
        "example": (
            "Without a Content-Security-Policy header, an attacker who finds an XSS "
            "vulnerability can inject malicious scripts that steal session cookies. "
            "Without HSTS, a coffee-shop attacker can intercept traffic even if the "
            "site uses HTTPS."
        ),
        "impact": "Enables XSS attacks, clickjacking, cookie theft, and man-in-the-middle attacks.",
    },
}


def _score_label(score: int) -> str:
    if score >= 80:
        return f"[bold green]{score}/100 — Good[/bold green]"
    if score >= 50:
        return f"[bold yellow]{score}/100 — Needs improvement[/bold yellow]"
    return f"[bold red]{score}/100 — Critical issues found[/bold red]"


def print_report(result: AuditResult) -> None:
    console.print()
    console.rule(f"[bold]API Security Audit — {result.target}[/bold]")
    console.print(f"[dim]Scanned at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]\n")

    # ── Main findings table ──────────────────────────────────────────────────
    table = Table(box=box.ROUNDED, show_lines=True, expand=False)
    table.add_column("", width=4, justify="center")
    table.add_column("Severity", width=10)
    table.add_column("Category", width=28)
    table.add_column("What was detected", min_width=30)

    for finding in result.findings:
        if finding.status == Status.PASS:
            continue
        friendly = FRIENDLY_CHECK_NAMES.get(finding.check_id, finding.check_id)
        table.add_row(
            STATUS_ICONS[finding.status],
            Text(finding.severity.value, style=SEVERITY_COLORS[finding.severity]),
            friendly,
            finding.title,
        )

    console.print(table)

    # ── Score summary ────────────────────────────────────────────────────────
    failed = result.failed
    critical = sum(1 for f in failed if f.severity == Severity.CRITICAL)
    high = sum(1 for f in failed if f.severity == Severity.HIGH)
    medium = sum(1 for f in failed if f.severity == Severity.MEDIUM)

    console.print()
    console.print(
        f"[bold]Security score:[/bold] {_score_label(result.score)}  │  "
        f"[bold red]{critical} critical[/bold red]  "
        f"[red]{high} high[/red]  "
        f"[yellow]{medium} medium[/yellow]  "
        f"[green]{len(result.passed)} passed[/green]"
    )

    # ── Plain-English explanations for each failing check ───────────────────
    failing_check_ids = list(dict.fromkeys(          # unique, order preserved
        f.check_id for f in failed
    ))

    if failing_check_ids:
        console.print("\n[bold]Understanding your findings[/bold]\n")
        for check_id in failing_check_ids:
            info = PLAIN_ENGLISH.get(check_id)
            if not info:
                continue
            friendly = FRIENDLY_CHECK_NAMES.get(check_id, check_id)
            severity_color = SEVERITY_COLORS[
                max((f.severity for f in failed if f.check_id == check_id),
                    key=lambda s: list(Severity).index(s))
            ]

            content = (
                f"[bold]What is it?[/bold]\n{info['what']}\n\n"
                f"[bold]Real-world example[/bold]\n[dim]{info['example']}[/dim]\n\n"
                f"[bold]Potential impact[/bold]  {info['impact']}\n\n"
                f"[bold]How to fix[/bold]\n"
                + "\n".join(
                    f"  • {rec}"
                    for rec in dict.fromkeys(          # deduplicate, preserve order
                        f.recommendation
                        for f in failed
                        if f.check_id == check_id and f.recommendation
                    )
                )[:400]
            )

            console.print(Panel(
                content,
                title=f"[{severity_color}]{friendly}[/{severity_color}]  [dim]({check_id})[/dim]",
                border_style=severity_color,
                padding=(1, 2),
            ))


def export_json(result: AuditResult, path: str) -> None:
    data = {
        "target": result.target,
        "scanned_at": datetime.now().isoformat(),
        "score": result.score,
        "findings": [
            {
                "check_id": f.check_id,
                "category": FRIENDLY_CHECK_NAMES.get(f.check_id, f.check_id),
                "title": f.title,
                "severity": f.severity.value,
                "status": f.status.value,
                "detail": f.detail,
                "recommendation": f.recommendation,
                "evidence": f.evidence,
                "plain_english": PLAIN_ENGLISH.get(f.check_id, {}).get("what"),
                "real_world_example": PLAIN_ENGLISH.get(f.check_id, {}).get("example"),
            }
            for f in result.findings
        ],
    }
    with open(path, "w") as fp:
        json.dump(data, fp, indent=2)
    console.print(f"\n[green]Report saved to {path}[/green]")
