import json

from src.unified_to_gold.common_utill import make_session_id


def extract_conn(row: dict, timeline: list[dict]) -> dict:
    base = {
        "uid": row.get("uid"),
        "ts": row.get("flow_start"),
        "src_ip": row.get("src_ip"),
        "src_port": row.get("src_port"),
        "dest_ip": row.get("dest_ip"),
        "dest_port": row.get("dest_port"),
        "proto": row.get("proto"),
        "service": row.get("service"),
        "duration": None,
        "orig_bytes": None,
        "resp_bytes": None,
        "conn_state": None,
        "missed_bytes": None,
        "history": None,
        "orig_pkts": None,
        "resp_pkts": None,
    }
    for ev in timeline:
        if ev.get("source") != "zeek_conn":
            continue
        if not base["uid"]:
            base["uid"] = ev.get("uid")
        if not base["src_ip"]:
            base["src_ip"] = ev.get("orig_h")
        if not base["dest_ip"]:
            base["dest_ip"] = ev.get("resp_h")
        if not base["src_port"]:
            base["src_port"] = ev.get("orig_p")
        if not base["dest_port"]:
            base["dest_port"] = ev.get("resp_p")
        base["duration"] = ev.get("duration")
        base["orig_bytes"] = ev.get("orig_bytes")
        base["resp_bytes"] = ev.get("resp_bytes")
        base["conn_state"] = ev.get("conn_state")
        base["missed_bytes"] = ev.get("missed_bytes")
        base["history"] = ev.get("history")
        base["orig_pkts"] = ev.get("orig_pkts")
        base["resp_pkts"] = ev.get("resp_pkts")
        break
    if not base["src_ip"] or not base["dest_ip"]:
        for ev in timeline:
            if ev.get("source") != "suricata":
                continue
            if not base["src_ip"]:
                base["src_ip"] = ev.get("src_ip")
            if not base["dest_ip"]:
                base["dest_ip"] = ev.get("dest_ip")
            if not base["src_port"]:
                base["src_port"] = ev.get("src_port")
            if not base["dest_port"]:
                base["dest_port"] = ev.get("dest_port")
            if not base["proto"] and ev.get("proto"):
                base["proto"] = ev["proto"].lower()
            break
    return base


def extract_http(timeline: list[dict]) -> dict:
    _null = {
        k: None
        for k in [
            "http_method",
            "http_host",
            "http_uri",
            "http_user_agent",
            "http_request_body_len",
            "http_response_body_len",
            "http_status_code",
            "http_status_msg",
            "http_version",
        ]
    }
    for ev in timeline:
        if ev.get("source") != "zeek_http":
            continue
        host = ev.get("host")
        if host and ":" in host:
            host = host.rsplit(":", 1)[0]
        return {
            "http_method": ev.get("method"),
            "http_host": host,
            "http_uri": ev.get("uri"),
            "http_user_agent": ev.get("user_agent"),
            "http_request_body_len": ev.get("request_body_len"),
            "http_response_body_len": ev.get("response_body_len"),
            "http_status_code": ev.get("status_code"),
            "http_status_msg": ev.get("status_msg"),
            "http_version": ev.get("version"),
        }
    return _null


def extract_dns(timeline: list[dict]) -> dict:
    _null = {
        k: None
        for k in [
            "dns_query",
            "dns_qtype_name",
            "dns_rcode_name",
            "dns_answers",
            "dns_rtt",
        ]
    }
    for ev in timeline:
        if ev.get("source") == "zeek_dns":
            return {
                "dns_query": ev.get("query"),
                "dns_qtype_name": ev.get("qtype_name"),
                "dns_rcode_name": ev.get("rcode_name"),
                "dns_answers": ev.get("answers"),
                "dns_rtt": ev.get("rtt"),
            }
    return _null


def extract_ssl(timeline: list[dict]) -> dict:
    _null = {
        k: None
        for k in [
            "tls_version",
            "tls_cipher",
            "tls_curve",
            "tls_sni",
            "tls_ssl_history",
            "tls_established",
            "tls_resumed",
        ]
    }
    for ev in timeline:
        if ev.get("source") == "zeek_ssl":
            return {
                "tls_version": ev.get("version"),
                "tls_cipher": ev.get("cipher"),
                "tls_curve": ev.get("curve"),
                "tls_sni": ev.get("server_name"),
                "tls_ssl_history": ev.get("ssl_history"),
                "tls_established": ev.get("established"),
                "tls_resumed": ev.get("resumed"),
            }
    return _null


def extract_suricata_stats(row: dict, timeline: list[dict]) -> dict:
    alert_count = row.get("alert_count") or 0
    max_severity = row.get("threat_level")
    flow_ev: dict = {}
    for ev in timeline:
        if ev.get("source") == "suricata" and ev.get("event_type") == "flow":
            flow_ev = ev
            break
    if max_severity is None:
        severities = [
            int(ev["severity"])
            for ev in timeline
            if ev.get("source") == "suricata"
            and ev.get("event_type") == "alert"
            and ev.get("severity") is not None
        ]
        max_severity = min(severities) if severities else None
    return {
        "alert_count": alert_count,
        "max_severity": max_severity,
        "flow_state": flow_ev.get("flow_state"),
        "flow_reason": flow_ev.get("flow_reason"),
        "pkts_toserver": flow_ev.get("pkts_toserver"),
        "pkts_toclient": flow_ev.get("pkts_toclient"),
        "bytes_toserver": flow_ev.get("bytes_toserver"),
        "bytes_toclient": flow_ev.get("bytes_toclient"),
    }


def extract_sessions(raw_session_list: list[dict]) -> dict:
    seen_cids: dict[str, str] = {}
    orphan_idx = 0
    records: list[dict] = []

    for session in raw_session_list:
        cid = session.get("community_id")
        if cid and cid in seen_cids:
            session_id = seen_cids[cid]
        elif cid:
            session_id = make_session_id(cid, 0)
            seen_cids[cid] = session_id
        else:
            session_id = make_session_id(None, orphan_idx)
            orphan_idx += 1

        timeline = session.get("timeline", [])
        conn = extract_conn(session, timeline)
        http = extract_http(timeline)
        dns = extract_dns(timeline)
        ssl = extract_ssl(timeline)
        suri = extract_suricata_stats(session, timeline)

        records.append(
            {
                "session_id": session_id,
                "community_id": cid,
                "uid": conn.get("uid"),
                "ts": conn.get("ts"),
                "src_ip": conn.get("src_ip"),
                "src_port": conn.get("src_port"),
                "dest_ip": conn.get("dest_ip"),
                "dest_port": conn.get("dest_port"),
                "proto": conn.get("proto"),
                "service": conn.get("service"),
                "duration": conn.get("duration"),
                "orig_bytes": conn.get("orig_bytes"),
                "resp_bytes": conn.get("resp_bytes"),
                "conn_state": conn.get("conn_state"),
                "missed_bytes": conn.get("missed_bytes"),
                "history": conn.get("history"),
                "orig_pkts": conn.get("orig_pkts"),
                "resp_pkts": conn.get("resp_pkts"),
                **http,
                **dns,
                **ssl,
                "alert_count": suri["alert_count"],
                "max_severity": suri["max_severity"],
                "is_threat": session.get("is_threat", False),
                "timeline": json.dumps(timeline, ensure_ascii=False),
                "flow_state": suri["flow_state"],
                "flow_reason": suri["flow_reason"],
                "pkts_toserver": suri["pkts_toserver"],
                "pkts_toclient": suri["pkts_toclient"],
                "bytes_toserver": suri["bytes_toserver"],
                "bytes_toclient": suri["bytes_toclient"],
                "flow_start": session.get("flow_start"),
                "flow_end": session.get("flow_end"),
            }
        )
