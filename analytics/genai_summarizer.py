"""
uses an LLM to generate natural-language summaries of security alerts.
falls back to template-based summaries if the LLM is unavailable.

designed to work with openai's API or a local ollama instance.
set GENAI_PROVIDER env var to "openai" or "ollama" (default: template).
"""

import os
import json


GENAI_PROVIDER = os.environ.get("GENAI_PROVIDER", "template")


def summarize_alert(alert_context: dict) -> str:
    """
    generate a human-readable summary for a correlated alert.
    
    alert_context should have keys like:
        source_ip, dest_ip, ioc_threat_type, event_count,
        duration_hours, risk_score, ioc_confidence
    """
    provider = GENAI_PROVIDER.lower()

    if provider == "openai":
        return _summarize_openai(alert_context)
    elif provider == "ollama":
        return _summarize_ollama(alert_context)
    else:
        return _summarize_template(alert_context)


def _summarize_template(ctx):
    """
    fallback template-based summary. no LLM needed, just
    string formatting with the structured data we already have.
    good enough for most SOC workflows tbh.
    """
    source = ctx.get("source_ip", "unknown")
    dest = ctx.get("dest_ip", "unknown")
    threat = ctx.get("ioc_threat_type", "unknown")
    count = ctx.get("event_count", 0)
    hours = ctx.get("duration_hours", 0)
    score = ctx.get("risk_score", 0)
    confidence = ctx.get("ioc_confidence", 0)

    severity_word = "Critical" if score > 75 else "High" if score > 50 else "Medium" if score > 25 else "Low"

    summary = (
        f"[{severity_word}] Host {source} made {count} connection(s) to "
        f"{dest} (flagged as {threat}, confidence {confidence}%) "
        f"over {hours:.1f} hours. Risk score: {score}. "
    )

    if threat == "c2_server":
        summary += "Pattern consistent with C2 beaconing. Recommend network isolation."
    elif threat == "malware":
        summary += "Possible malware callback detected. Check endpoint for IOCs."
    elif threat == "phishing":
        summary += "Suspected phishing infrastructure contact. Review user activity."
    elif threat == "ransomware":
        summary += "Potential ransomware communication. Immediate response recommended."
    else:
        summary += "Review event details for further triage."

    return summary


def _summarize_openai(ctx):
    """call openai API for a more natural summary"""
    try:
        import openai
        client = openai.OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
        prompt = _build_prompt(ctx)
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a SOC analyst writing alert summaries. Be concise and actionable."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=200,
            temperature=0.3,
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        # graceful degradation
        print(f"openai call failed ({e}), falling back to template")
        return _summarize_template(ctx)


def _summarize_ollama(ctx):
    """call local ollama for summary (no API key needed)"""
    try:
        import requests
        prompt = _build_prompt(ctx)
        resp = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "llama3",
                "prompt": f"You are a SOC analyst. Summarize this alert concisely:\n{prompt}",
                "stream": False,
            },
            timeout=30,
        )
        return resp.json().get("response", _summarize_template(ctx))
    except Exception as e:
        print(f"ollama call failed ({e}), falling back to template")
        return _summarize_template(ctx)


def _build_prompt(ctx):
    return (
        f"Security alert: Source IP {ctx.get('source_ip')} connected to "
        f"destination {ctx.get('dest_ip')} (known {ctx.get('ioc_threat_type', 'threat')}) "
        f"{ctx.get('event_count', 0)} times over {ctx.get('duration_hours', 0):.1f} hours. "
        f"IOC confidence: {ctx.get('ioc_confidence', 0)}%. "
        f"Risk score: {ctx.get('risk_score', 0)}/100. "
        f"Summarize this for a SOC analyst in 2-3 sentences."
    )
