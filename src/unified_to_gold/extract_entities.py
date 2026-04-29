import logging
from typing import Any

import pandas as pd

from src.unified_to_gold.common_utill import is_ip

logger = logging.getLogger(__name__)
ip_bucket: dict[str, dict] = {}
domain_bucket: dict[str, dict] = {}
alert_bucket: dict[str, dict] = {}


def _update_ip(ip, ts, sid, orig=0, resp=0):
    if not ip:
        return
    b = ip_bucket.setdefault(
        ip,
        {
            "first_seen": ts,
            "last_seen": ts,
            "sessions_df": set(),
            "orig_bytes": 0,
            "resp_bytes": 0,
        },
    )
    if ts:
        if not b["first_seen"] or ts < b["first_seen"]:
            b["first_seen"] = ts
        if not b["last_seen"] or ts > b["last_seen"]:
            b["last_seen"] = ts
    b["sessions_df"].add(sid)
    b["orig_bytes"] += orig
    b["resp_bytes"] += resp


def _update_domain(domain, ts, sid):
    if not domain:
        return
    b = domain_bucket.setdefault(
        domain,
        {
            "first_seen": ts,
            "last_seen": ts,
            "sessions_df": set(),
        },
    )
    if ts:
        if not b["first_seen"] or ts < b["first_seen"]:
            b["first_seen"] = ts
        if not b["last_seen"] or ts > b["last_seen"]:
            b["last_seen"] = ts
    b["sessions_df"].add(sid)


def _update_alert(sig_id, sig, category, severity, ts, sid):
    if not sig_id and not sig:
        return
    key = str(sig_id or sig)
    b = alert_bucket.setdefault(
        key,
        {
            "first_seen": ts,
            "last_seen": ts,
            "sessions_df": set(),
            "signature": sig,
            "signature_id": sig_id,
            "category": category,
        },
    )
    if ts:
        if not b["first_seen"] or ts < b["first_seen"]:
            b["first_seen"] = ts
        if not b["last_seen"] or ts > b["last_seen"]:
            b["last_seen"] = ts
    b["sessions_df"].add(sid)


def extract_entities(
    sessions_df: pd.DataFrame,
    raw_df: pd.DataFrame,
) -> list[dict[str, Any]]:

    for sess in sessions_df:
        sid = sess["session_id"]
        ts = sess.get("flow_start")
        _update_ip(sess.get("src_ip"), ts, sid)
        _update_ip(sess.get("dest_ip"), ts, sid)
        http_host = sess.get("http_host")
        if http_host:
            (_update_ip if is_ip(http_host) else _update_domain)(http_host, ts, sid)
        if sess.get("tls_sni"):
            _update_domain(sess["tls_sni"], ts, sid)
        if sess.get("dns_query"):
            _update_domain(sess["dns_query"], ts, sid)

    cid_to_sid = {
        s["community_id"]: s["session_id"] for s in sessions_df if s.get("community_id")
    }

    for raw_df_sess in raw_df:
        sid = cid_to_sid.get(raw_df_sess.get("community_id"), "unknown")
        for ev in raw_df_sess.get("timeline", []):
            source = ev.get("source", "")
            ts = ev.get("ts")
            if source == "zeek_conn":
                _update_ip(ev.get("orig_h"), ts, sid, int(ev.get("orig_bytes") or 0), 0)
                _update_ip(ev.get("resp_h"), ts, sid, 0, int(ev.get("resp_bytes") or 0))
            elif source == "suricata":
                _update_ip(ev.get("src_ip"), ts, sid)
                _update_ip(ev.get("dest_ip"), ts, sid)
                if ev.get("event_type") == "alert" and ev.get("signature"):
                    _update_alert(
                        ev.get("signature_id"),
                        ev.get("signature"),
                        ev.get("category"),
                        ev.get("severity"),
                        ts,
                        sid,
                    )
            elif source == "zeek_dns":
                _update_domain(ev.get("query"), ts, sid)
                answers_raw_df = ev.get("answers")
                if answers_raw_df:
                    for ans in str(answers_raw_df).split(","):
                        ans = ans.strip()
                        if not ans:
                            continue
                        parts = ans.split(".")
                        (
                            _update_ip
                            if (len(parts) == 4 and all(p.isdigit() for p in parts))
                            else _update_domain
                        )(ans, ts, sid)
            elif source == "zeek_ssl":
                if ev.get("server_name"):
                    _update_domain(ev["server_name"], ts, sid)

    records: list[dict] = []
    for ip, b in ip_bucket.items():
        records.append(
            {
                "entity_type": "ip",
                "entity_value": ip,
                "first_seen": b["first_seen"],
                "last_seen": b["last_seen"],
                "related_session_count": len(b["sessions_df"]),
                "total_orig_bytes": b["orig_bytes"],
                "total_resp_bytes": b["resp_bytes"],
                "signature": None,
                "category": None,
            }
        )
    for domain, b in domain_bucket.items():
        records.append(
            {
                "entity_type": "domain",
                "entity_value": domain,
                "first_seen": b["first_seen"],
                "last_seen": b["last_seen"],
                "related_session_count": len(b["sessions_df"]),
                "total_orig_bytes": None,
                "total_resp_bytes": None,
                "signature": None,
                "category": None,
            }
        )
    for key, b in alert_bucket.items():
        records.append(
            {
                "entity_type": "alert",
                "entity_value": key,
                "first_seen": b["first_seen"],
                "last_seen": b["last_seen"],
                "related_session_count": len(b["sessions_df"]),
                "total_orig_bytes": None,
                "total_resp_bytes": None,
                "signature": b["signature"],
                "category": b["category"],
            }
        )
    return records


logger.info(
    "extract_entities 완료 — ip:%d domain:%d alert:%d → %s",
    len(ip_bucket),
    len(domain_bucket),
    len(alert_bucket),
)
