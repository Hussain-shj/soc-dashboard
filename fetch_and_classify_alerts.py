#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fetch_and_classify_alerts.py
=============================
The "ingestion + triage" agentic step for the SOC dashboard.

What it does, every time it runs:
  1. Fetches the latest items from a fixed list of cybersecurity RSS feeds.
  2. Skips anything already seen in a previous run (tracked in seen_ids.json).
  3. Sends each genuinely NEW item to Claude, which decides whether it's
     relevant enough for a municipal SOC dashboard and, if so, classifies it
     (severity / category / audience) and drafts the Arabic + English title,
     summary, and mitigation bullets — in the exact schema the dashboard
     already expects.
  4. Appends the results to alerts.json, sitting next to SOC-Dashboard.html.
     The dashboard automatically picks this file up on next page load
     (see loadAlerts() in the dashboard's own script) — no manual editing.

This script does NOT send anything to employees/IT — that stays manual from
inside the dashboard, by design. It CAN optionally send a short email digest
to a single internal address (e.g. yourself or the security team) whenever
new alerts are added, purely as an "FYI, new alerts are in" notification —
see EMAIL SETUP below. That's a notification about the dashboard, not a
message to staff.

--------------------------------------------------------------------------
SETUP
--------------------------------------------------------------------------
1. pip install requests anthropic
2. Get an API key from https://console.anthropic.com and set it:
       export ANTHROPIC_API_KEY="sk-ant-..."      (Linux/Mac)
       setx ANTHROPIC_API_KEY "sk-ant-..."         (Windows)
3. Put this script in the SAME folder as SOC-Dashboard.html.
4. Run it once by hand to make sure it works:
       python3 fetch_and_classify_alerts.py
5. Schedule it to run automatically, e.g. every 2 hours:
   - Linux/Mac (cron):  crontab -e   then add:
         0 */2 * * * cd /path/to/dashboard && /usr/bin/python3 fetch_and_classify_alerts.py >> ingest.log 2>&1
   - Windows: Task Scheduler -> create a Basic Task -> Trigger "every 2 hours"
     -> Action "Start a program" -> point it at python.exe with this script
     as the argument, and set "Start in" to the dashboard's folder.
   - No-code option: an n8n or Power Automate flow with a Schedule trigger
     and an "Execute Command" / "Run script" step that runs this file.

--------------------------------------------------------------------------
EMAIL SETUP (optional — leave RESEND_API_KEY unset to skip email entirely)
--------------------------------------------------------------------------
Sends via Resend's HTTPS API (https://resend.com) rather than SMTP — most
hosting platforms, including Railway on its Hobby plan, block outbound SMTP
ports (25/465/587) entirely to prevent spam abuse, which breaks Gmail SMTP
regardless of how correct the App Password is. Resend sends over plain
HTTPS, which isn't blocked.

Set these as environment variables (on Railway: Variables tab — never put
real secrets in this file):

  RESEND_API_KEY   from https://resend.com (free tier is plenty for this) —
                    sign up, then Dashboard -> API Keys -> Create API Key
  EMAIL_RECIPIENT  the single address to notify, e.g. you@yourorg.gov.ae
  EMAIL_SENDER     optional — defaults to onboarding@resend.dev, which
                    works out of the box but ONLY delivers to the email
                    address you signed up to Resend with. To send to any
                    other address, verify your own domain in Resend's
                    dashboard and set this to an address on that domain.

Add or remove sources by editing the FEEDS list below.
--------------------------------------------------------------------------
"""

import json
import os
import re
import sys
import hashlib
from datetime import datetime, timezone
from xml.etree import ElementTree as ET

import requests

try:
    from anthropic import Anthropic
except ImportError:
    print("Missing dependency. Run: pip install anthropic", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Configuration — edit this section to fit your needs
# ---------------------------------------------------------------------------

FEEDS = [
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml"},
    # BleepingComputer (https://www.bleepingcomputer.com/feed/) is deliberately
    # NOT included: it returns HTTP 403 to requests from cloud/datacenter IPs
    # (Railway, AWS, etc.) regardless of headers — this is the publisher
    # blocking hosting-provider IP ranges, not a bug in this script. It works
    # fine from a home/office connection if you ever run this script locally.
    #
    # Add more RSS-capable sources here, e.g.:
    # {"name": "CISA Advisories", "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml"},
    # {"name": "Huntress", "url": "https://www.huntress.com/blog/rss.xml"},
]

SEEN_FILE = "seen_ids.json"        # tracks which feed items we've already triaged
ALERTS_FILE = "alerts.json"        # consumed directly by SOC-Dashboard.html
LOG_FILE = "ingest_log.jsonl"      # one line per run, for auditing what the agent decided

MAX_ITEMS_PER_FEED = 8    # how far back into each feed to look every run
MAX_NEW_PER_RUN = 6       # safety cap: classify at most this many new items per run
MODEL = "claude-sonnet-5"

CATEGORIES = [
    "تصيد احتيالي", "ثغرات وتحديثات", "برمجيات خبيثة",
    "تهديدات متقدمة", "تحديثات الأجهزة الشخصية والذكية",
]

client = Anthropic()  # reads ANTHROPIC_API_KEY from the environment


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_json(path, default):
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return default


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def log_line(entry):
    entry["ts"] = datetime.now(timezone.utc).isoformat()
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def strip_html(text):
    return re.sub(r"<[^>]+>", "", text or "").strip()


def fetch_feed_items(feed):
    resp = requests.get(feed["url"], timeout=20, headers={"User-Agent": "Mozilla/5.0"})
    resp.raise_for_status()
    root = ET.fromstring(resp.content)
    items = []
    for item in root.iter("item"):
        title = strip_html(item.findtext("title"))
        link = (item.findtext("link") or "").strip()
        guid = (item.findtext("guid") or link).strip()
        desc = strip_html(item.findtext("description"))[:800]
        pub_date = (item.findtext("pubDate") or "").strip()
        if not title or not guid:
            continue
        items.append({
            "seen_key": hashlib.sha1(guid.encode("utf-8")).hexdigest()[:16],
            "source": feed["name"],
            "title_en": title,
            "summary_en": desc,
            "link": link,
            "pub_date": pub_date,
        })
        if len(items) >= MAX_ITEMS_PER_FEED:
            break
    return items


CLASSIFY_PROMPT = """You are the triage step of a municipal cybersecurity SOC dashboard \
(Sharjah City Municipality). You will be given ONE raw news/advisory item in English. \
Decide whether it is relevant and specific enough to alert municipal employees and/or \
the IT department about. Skip generic tech news, opinion pieces, product marketing, \
research-methodology pieces with no concrete threat, or anything not a real, specific \
vulnerability, attack campaign, malware family, or breach.

If NOT relevant, respond with EXACTLY this JSON and nothing else:
{{"relevant": false}}

If relevant, respond with ONLY a JSON object (no markdown fences, no commentary before \
or after it) with this exact shape:

{{
  "relevant": true,
  "severity": "critical" | "high" | "medium",
  "category": one of {categories},
  "audience": "employees" | "it" | "both",
  "reason": "one Arabic sentence explaining why this audience was chosen",
  "title": "Arabic translation/summary of the headline, natural phrasing not a literal word-for-word translation",
  "titleEn": "tightened English headline",
  "desc": "2-3 sentence Arabic summary of what happened and why it matters",
  "descEn": "2-3 sentence English summary of what happened and why it matters",
  "mitig": ["Arabic mitigation bullet 1", "Arabic mitigation bullet 2", "Arabic mitigation bullet 3"],
  "mitigEn": ["English mitigation bullet 1", "English mitigation bullet 2", "English mitigation bullet 3"]
}}

Severity guide:
- "critical": actively exploited zero-day, or a confirmed breach/campaign with major impact.
- "high": serious flaw or campaign, not yet mass-exploited, or affects widely used software.
- "medium": worth general awareness but lower urgency.

Audience guide:
- "employees": the needed action is something an ordinary staff member does themselves
  (update a personal device, recognize a phishing pattern, avoid a risky download).
- "it": the needed action is server/infrastructure work only IT can perform.
- "both": needs a general staff warning AND a separate IT-side technical fix.

Source item:
Title: {title}
Summary: {summary}
Published: {pub_date}
Source: {source}
"""


def send_email_digest(new_alerts):
    """Send a short 'FYI, new alerts were added' email via the Resend HTTPS
    API. Silently does nothing if the required env vars aren't set, so
    email stays fully optional and never blocks the ingestion pipeline.

    Why Resend instead of Gmail SMTP: Railway (like most hosting platforms)
    blocks outbound SMTP ports (25/465/587) entirely on the Hobby plan to
    prevent spam abuse — that's a network-level block, not a credentials
    problem, so no Gmail App Password can work around it there. Resend
    sends over plain HTTPS instead, which isn't blocked."""
    api_key = os.environ.get("RESEND_API_KEY")
    sender = os.environ.get("EMAIL_SENDER", "onboarding@resend.dev")
    recipient = os.environ.get("EMAIL_RECIPIENT")

    if not (api_key and recipient):
        return  # email not configured — this is fine, it's optional

    if not new_alerts:
        return

    sev_ar = {"critical": "حرج", "high": "عالي", "medium": "متوسط"}
    lines = [f"تمت إضافة {len(new_alerts)} تنبيه(ات) أمنية جديدة إلى لوحة الـ SOC:\n"]
    for a in new_alerts:
        lines.append(f"[{sev_ar.get(a['severity'], a['severity'])}] {a['title']}")
        lines.append(f"  المصدر: {a['source']} | التاريخ: {a['date']}")
        lines.append(f"  {a['desc']}")
        lines.append("")
    lines.append("افتح لوحة الـ SOC لمراجعة التفاصيل الكاملة والإجراءات الموصى بها.")
    body = "\n".join(lines)

    try:
        resp = requests.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "from": sender,
                "to": [recipient],
                "subject": f"SOC — {len(new_alerts)} تنبيه(ات) أمنية جديدة",
                "text": body,
            },
            timeout=20,
        )
        resp.raise_for_status()
        print(f"  ✉ sent email digest for {len(new_alerts)} new alert(s) to {recipient}")
        log_line({"event": "email_sent", "count": len(new_alerts), "recipient": recipient})
    except Exception as e:
        # A failed email must never break the ingestion run itself.
        detail = getattr(e, "response", None)
        detail_text = detail.text[:300] if detail is not None else str(e)
        print(f"  ! failed to send email digest: {detail_text}", file=sys.stderr)
        log_line({"event": "email_failed", "error": detail_text})


def classify(item):
    """Returns (result_dict_or_None, error_message_or_None)."""
    prompt = CLASSIFY_PROMPT.format(
        categories=CATEGORIES,
        title=item["title_en"],
        summary=item["summary_en"],
        pub_date=item["pub_date"],
        source=item["source"],
    )
    try:
        resp = client.messages.create(
            model=MODEL,
            max_tokens=1200,
            messages=[{"role": "user", "content": prompt}],
        )
    except Exception as e:
        # Bad/missing API key, rate limit, network hiccup, etc. Log the real
        # reason and skip just this item instead of crashing the whole run.
        print(f"  ! Claude API call failed for '{item['title_en'][:60]}': {e}", file=sys.stderr)
        log_line({"event": "api_call_failed", "title": item["title_en"], "error": str(e)})
        return None, str(e)

    text_blocks = [b.text for b in resp.content if getattr(b, "type", None) == "text"]
    if not text_blocks:
        err = "No text block in Claude's response (only non-text content, e.g. a thinking block)"
        print(f"  ! {err} for: {item['title_en'][:60]}", file=sys.stderr)
        log_line({"event": "no_text_block", "title": item["title_en"]})
        return None, err
    text = text_blocks[0].strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip())
    try:
        return json.loads(text), None
    except json.JSONDecodeError:
        print(f"  ! could not parse Claude's response for: {item['title_en'][:60]}", file=sys.stderr)
        log_line({"event": "parse_failed", "title": item["title_en"], "raw_response": text[:500]})
        return None, f"Could not parse Claude's response as JSON: {text[:200]!r}"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    seen = load_json(SEEN_FILE, {})
    alerts = load_json(ALERTS_FILE, [])
    next_id = max([a.get("id", 0) for a in alerts], default=0) + 1
    new_count = 0
    checked_count = 0
    api_failures = 0
    fetch_failures = 0
    first_api_error = None
    feed_results = []  # per-feed diagnostic detail, returned to the caller
    newly_added = []  # full alert objects added this run, for the email digest

    for feed in FEEDS:
        print(f"Checking {feed['name']}...")
        try:
            items = fetch_feed_items(feed)
        except Exception as e:
            print(f"  ! failed to fetch {feed['name']}: {e}", file=sys.stderr)
            log_line({"event": "fetch_failed", "feed": feed["name"], "error": str(e)})
            fetch_failures += 1
            feed_results.append({"feed": feed["name"], "ok": False, "error": str(e), "items_found": 0, "new_items": 0})
            continue

        feed_new_before = new_count
        feed_checked_before = checked_count

        for item in items:
            if item["seen_key"] in seen:
                continue

            if new_count >= MAX_NEW_PER_RUN:
                # Don't mark this item seen — leave it for the next run
                # instead of silently discarding it once the cap is hit.
                continue

            checked_count += 1

            result, err = classify(item)
            if not result:
                # Do NOT mark as seen: a bad API key, rate limit, or outage
                # is a transient/persistent problem with US, not with this
                # item — it must be retried once the real issue is fixed,
                # or every failed run permanently burns through the queue.
                log_line({"event": "classify_failed", "title": item["title_en"], "source": item["source"], "error": err})
                api_failures += 1
                if first_api_error is None:
                    first_api_error = err
                continue

            # From here on the item was successfully classified one way or
            # another — safe to mark seen so it's never reconsidered again.
            seen[item["seen_key"]] = True

            if not result.get("relevant"):
                log_line({"event": "skipped_not_relevant", "title": item["title_en"], "source": item["source"]})
                continue

            try:
                alert = {
                    "id": next_id,
                    "severity": result["severity"],
                    "category": result["category"],
                    "audience": result["audience"],
                    "reason": result["reason"],
                    "title": result["title"],
                    "titleEn": result["titleEn"],
                    "date": datetime.now(timezone.utc).strftime("%d %B %Y"),
                    "source": item["source"],
                    "desc": result["desc"],
                    "descEn": result["descEn"],
                    "mitig": result["mitig"],
                    "mitigEn": result["mitigEn"],
                    "_sourceLink": item["link"],
                }
            except KeyError as e:
                print(f"  ! classification missing field {e} for: {item['title_en'][:60]}", file=sys.stderr)
                log_line({"event": "malformed_classification", "title": item["title_en"], "missing_field": str(e), "raw": result})
                continue
            alerts.append(alert)
            newly_added.append(alert)
            log_line({"event": "alert_added", "id": next_id, "title": alert["titleEn"], "severity": alert["severity"]})
            next_id += 1
            new_count += 1
            print(f"  + added [{alert['severity']}] {alert['titleEn'][:70]}")

        feed_results.append({
            "feed": feed["name"], "ok": True, "error": None,
            "items_found": len(items),
            "new_items": checked_count - feed_checked_before,
            "added": new_count - feed_new_before,
        })

    save_json(SEEN_FILE, seen)
    save_json(ALERTS_FILE, alerts)
    print(f"\nDone. Checked {checked_count} new feed item(s), added {new_count} alert(s). "
          f"{len(alerts)} total now in {ALERTS_FILE}.")
    if new_count >= MAX_NEW_PER_RUN and checked_count > new_count:
        print(f"Note: MAX_NEW_PER_RUN cap reached — some items were left for the next run.")

    if newly_added:
        send_email_digest(newly_added)

    # Surface a TOTAL outage loudly (every feed unreachable) — partial
    # failures are still visible via feed_results below without aborting.
    if fetch_failures == len(FEEDS):
        raise RuntimeError(
            f"Could not fetch ANY of the {len(FEEDS)} feed(s) this run — "
            f"see feed_results in the last run summary for the exact error per feed. "
            f"This is often outbound network restrictions on the hosting platform, "
            f"or the feed URL itself changed."
        )
    if checked_count > 0 and api_failures == checked_count:
        raise RuntimeError(
            f"All {api_failures} item(s) failed classification this run. "
            f"First error: {first_api_error}"
        )

    return {
        "checked": checked_count,
        "added": new_count,
        "api_failures": api_failures,
        "fetch_failures": fetch_failures,
        "feed_results": feed_results,
    }


if __name__ == "__main__":
    main()
