# Page Pulse

A small web tool that audits any URL: it fetches the page, parses it, and
returns HTTP status, response time, page title, meta description, H1 count,
image alt-text coverage, and an approximate word count — with SSRF-safe
fetching and every attempt (success or failure) persisted to PostgreSQL.

Built for the Digital Heroes SDE internship task, "Task A – Build Page
Pulse" and "Task B – Prove it and explain it."

**Live URL:** http://3.25.97.249/

**Repo:** https://github.com/saga1206/pagepulse

---

## Screenshots

### Home Page

![Home Page](screenshots/home-page.png)

### Audit Result

![Audit Result](screenshots/audit-result.png)

### Audit Failure

![Audit Failure](screenshots/audit-failure.png)

### Recent Audits

![Recent Audits](screenshots/recent-audits.png)

---


## Features

- `POST /api/audit/` — audits a submitted URL and returns a structured report
- `GET /api/audits/` — the 50 most recent audits, newest first
- SSRF-safe fetching: private/loopback/link-local/multicast/reserved
  addresses are rejected, including on redirect targets, not just the
  original URL
- Handles invalid URLs, DNS failures, timeouts, non-HTML responses,
  redirect loops, and unexpected exceptions without ever crashing or
  leaking a stack trace
- Every audit attempt — successful or failed — is persisted to Postgres
- A minimal single-page frontend that calls the API and renders the report

---

## Architecture

```
pagepulse_project/
├── pagepulse_project/       # Django project (settings, urls, wsgi)
├── audit/                   # Django application
│   ├── models.py            # AuditReport + AuditReportManager
│   ├── serializers.py       # request validation + response shaping
│   ├── utils.py             # fetching / parsing / SSRF logic (no Django request/response coupling)
│   ├── views.py             # thin — validate, call utils, persist, respond
│   ├── urls.py
│   ├── tests.py
│   └── templates/audit/index.html
├── requirements.txt
└── .env                     # not committed — see .env example below
```

The core rule: **`utils.py` never touches Django's request/response cycle**,
and **`views.py` never contains fetching or parsing logic.** See Design
Decision #1 below for why.

---


## Deployment

The application is deployed on AWS EC2 using:

- Ubuntu 26.04 LTS
- Nginx
- Gunicorn
- PostgreSQL
- Django
- WhiteNoise



## Setup

### Prerequisites
- Python 3.11+
- PostgreSQL running locally (or a `DATABASE_URL` pointing at one)

### 1. Clone and install

```bash
git clone https://github.com/saga1206/pagepulse.git
cd pagepulse
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure environment

Create a `.env` file in the project root:

```env
DJANGO_SECRET_KEY=replace-with-a-real-random-secret
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1
CSRF_TRUSTED_ORIGINS=http://localhost:8000

DATABASE_URL=postgres://pagepulseuser:your-password@localhost:5432/pagepulse

PAGEPULSE_FETCH_TIMEOUT_SECONDS=8
PAGEPULSE_MAX_CONTENT_BYTES=5242880
PAGEPULSE_MAX_REDIRECTS=5
DJANGO_LOG_LEVEL=INFO
```

### 3. Create the database

```bash
psql -U postgres -c "CREATE DATABASE pagepulse;"
psql -U postgres -c "CREATE USER pagepulse WITH PASSWORD 'pagepulse';"
psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE pagepulse TO pagepulse;"
```

### 4. Migrate and run

```bash
python manage.py migrate
python manage.py runserver
```

Visit http://127.0.0.1:8000/ to access the application locally.

---

## API Contract

### `POST /api/audit/`

**Request**
```json
{ "url": "https://example.com" }
```

**Success — `200 OK`**
```json
{
  "id": 14,
  "url": "https://example.com/",
  "requested_at": "2026-07-25T10:12:03.441Z",
  "succeeded": true,
  "http_status": 200,
  "response_time_ms": 421.3,
  "title": "Example Domain",
  "meta_description": null,
  "h1_count": 1,
  "images_total": 0,
  "images_missing_alt": 0,
  "word_count": 28,
  "error_code": null,
  "error_message": null
}
```

**Failure** — status code depends on the error:
```json
{ "error": "blocked_address", "detail": "This URL resolves to a private or internal address, which cannot be audited.", "report_id": 15 }
```

| `error` code | HTTP status | Meaning |
|---|---|---|
| `invalid_url` | 400 | Missing/malformed URL or disallowed scheme |
| `blocked_address` | 400 | URL (or a redirect target) resolves to a private/internal address |
| `too_many_redirects` | 400 | Exceeded the configured redirect limit |
| `timeout` | 504 | Connect/read timeout, or body-read deadline exceeded |
| `non_html_response` | 422 | Final response's Content-Type isn't HTML |
| `unreachable` | 502 | DNS failure, connection refused, or connection dropped mid-read |
| `internal_error` | 500 | Unexpected server error (never exposes the underlying exception) |

Every attempt, success or failure, is persisted; failure responses include
`report_id` so a specific failed attempt can be traced later.

### `GET /api/audits/`

Returns the 50 most recent `AuditReport` records, newest first, using the
same shape as the success response above.

---

## Running the tests

```bash
python manage.py test
```

Coverage includes (`audit/tests.py`):
- **`IsSafeIpTests`** — the SSRF address-safety check directly, including
  public/private IPv4, loopback, the AWS metadata address, and the
  IPv4-mapped / NAT64-embedded IPv6 unwrap logic (see Decision #2)
- **`AuditUrlParsingTests`** — the happy path (title, meta description, H1
  count, alt-text counting, word count) plus failure cases: invalid URL,
  timeout, non-HTML response, blocked private address, unresolvable host,
  a followed-and-revalidated redirect, and a redirect loop
- **`AuditAPITests`** — HTTP status codes and that both successful and
  failed attempts are persisted correctly

DNS resolution and outbound HTTP calls are mocked throughout, so the suite
never touches the real network and isn't affected by connectivity in
whatever environment it runs in.

---

## Design decisions

### 1. Service-layer logic (`utils.py`) has zero Django request/response coupling

`audit_url()` takes a string and returns a dict or raises a typed
exception — nothing about it knows it's being called from a view. Views
only validate the incoming request, call `audit_url()`, persist the
result, and shape the response.

**Why:** it means the entire fetching/parsing/SSRF pipeline — the part
this task is actually testing — can be unit tested directly and quickly,
without spinning up Django's test client for every case. It also keeps
`views.py` short enough to review in one pass, which is exactly what the
"code quality and structure" criterion is checking for.

### 2. SSRF protection resolves and re-validates on every redirect hop, and unwraps embedded IPv4 addresses before classifying them

The naive approach — validate the original URL once, then let `requests`
follow redirects automatically — has a real bypass: a public-looking URL
can redirect straight to an internal address, and the check never runs
again. `audit_url()` disables automatic redirects and re-runs
`_assert_resolves_to_public_address()` on every hop instead.

Separately, while testing against real sites, `github.com` and
`openai.com` were incorrectly blocked as "private." The cause: Python's
`ipaddress` module classifies IPv4-mapped IPv6 addresses
(`::ffff:a.b.c.d`) and NAT64-synthesized addresses (`64:ff9b::a.b.c.d`,
RFC 6052) as private/reserved *regardless of the real IPv4 address
embedded inside them* — and some DNS resolvers return exactly these forms
for hosts with no native AAAA record. `_embedded_ipv4()` now unwraps both
forms and classifies the real underlying address, so a genuinely public
host is no longer misclassified, while a private address wrapped either
way is still correctly blocked.

**Why this is worth calling out specifically:** it's the kind of bug that
passes every manual test against "obviously safe" sites like
`google.com` and only shows up against a site whose DNS resolver behavior
differs — which is exactly the kind of gap a reviewer will probe for.

### 3. Every audit attempt is persisted through a model manager, not inline in the view

`AuditReportManager.log_success()` / `log_failure()` own the mapping from
a result dict (or an error) to `AuditReport` fields. `views.py` never
touches a model field name directly.

**Why:** the task only requires returning JSON, but persisting every
attempt — including failures — makes it possible to answer "why did this
audit fail three hours ago" after the fact, which a stateless JSON
response can't do. Keeping the field-mapping logic in the manager (rather
than duplicated across `views.py`) means there's exactly one place that
needs to change if the model's shape ever does.

---

## Given more time, I would...


- Add a small allowlist/denylist override for edge-case hosts, rather
  than relying solely on IP-range classification — the NAT64 bug shows
  IP-based classification alone has sharp edges
- Move the synchronous `audit_url()` call off the request/response cycle
  (e.g. into a background task) so a slow target site doesn't hold a web
  worker for the full timeout window
- Add basic per-domain rate limiting on top of the existing
  `AnonRateThrottle`, so one client can't use the audit endpoint to
  hammer a single third-party site

---

## AI Usage Disclosure

I used ChatGPT and Claude as development assistants throughout this project. I used them to discuss the overall architecture, clarify Django and DRF implementation details, troubleshoot deployment and configuration issues, review the code structure, and improve the project documentation. After each suggestion, I implemented the changes myself, tested the application, and refined the code where needed. I configured and deployed the application on AWS EC2 using PostgreSQL, Gunicorn, and Nginx, configured PostgreSQL, Gunicorn, and Nginx, verified the API through manual testing and the test suite, and updated the documentation to reflect the final implementation.

---

## Requirements

See `requirements.txt`:
```
Django==5.0.7
djangorestframework==3.15.2
psycopg[binary]==3.2.13
django-environ==0.11.2
requests==2.32.3
beautifulsoup4==4.12.3
whitenoise==6.7.0
gunicorn==22.0.0
```
## Author

**Sagar Kumar Singh**

- GitHub: https://github.com/saga1206
- Project: Page Pulse

---

Built for Digital Heroes Training Task &middot; digitalheroesco.com