import json
import re

# ══════════════════════════════════════════════════════════════════════════════
# RAG 추론 공통 헬퍼
# ══════════════════════════════════════════════════════════════════════════════


def fix_json_escapes(raw: str) -> str:
    return re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: f"\\u00{m.group(1)}", raw)


def parse_response(raw: str, suspicion_score: int = 0) -> dict:
    for text in (raw, raw.replace("```json", "").replace("```", "").strip()):
        try:
            result = json.loads(text)
            if "threat_score" not in result:
                result["threat_score"] = max(0, min(100, int(suspicion_score)))
            return result
        except json.JSONDecodeError:
            pass
    fixed = _fix_json_escapes(raw)
    try:
        result = json.loads(fixed)
        if "threat_score" not in result:
            result["threat_score"] = max(0, min(100, int(suspicion_score)))
        return result
    except json.JSONDecodeError:
        pass
    return {
        "parse_error": True,
        "raw_response": raw,
        "threat_score": max(0, min(100, int(suspicion_score))),
    }


def subgraph_to_text(subgraph: dict) -> str:
    s = subgraph["session"]
    alerts = [
        ev
        for ev in s.get("timeline", [])
        if ev.get("source") == "suricata" and ev.get("signature")
    ]
    lines = [
        "[현재 세션 정보]",
        f"  session_id   : {s.get('session_id')}",
        f"  src_ip       : {s.get('src_ip')}  →  dest_ip : {s.get('dest_ip')}",
        f"  proto        : {s.get('proto')}       port    : {s.get('dest_port')}",
        f"  alert_count  : {s.get('alert_count')}   max_severity : {s.get('max_severity')}",
        f"  conn_state   : {s.get('conn_state') or 'N/A'}",
        f"  tls_sni      : {s.get('tls_sni') or 'N/A'}",
        f"  http_host    : {s.get('http_host') or 'N/A'}",
        f"  http_uri     : {s.get('http_uri') or 'N/A'}",
        f"  http_version : {s.get('http_version') or 'N/A'}",
        f"  dns_query    : {s.get('dns_query') or 'N/A'}",
        f"  flow_start   : {s.get('flow_start')}",
        "",
    ]
    if alerts:
        lines.append("[Suricata Alerts]")
        for av in alerts:
            lines.append(
                f"  severity={av.get('severity')}  "
                f"category={av.get('category') or 'N/A'}  "
                f"signature={av.get('signature')}"
            )
        lines.append("")

    neighbors = subgraph.get("neighbors", [])
    if neighbors:
        lines.append("[Neo4j 과거 행위 (1-hop)]")
        for nb in neighbors:
            label = (nb.get("node_labels") or ["?"])[0]
            value = nb.get("node_value", "")
            rel = nb.get("rel_type", "")
            extra = (
                f"  signature={nb['signature']}  category={nb.get('category')}"
                if nb.get("signature")
                else ""
            )
            lines.append(f"  -[{rel}]→ :{label} '{value}'{extra}")
    else:
        lines.append("[Neo4j 과거 행위] 없음 (신규 세션 또는 미수집)")
    return "\n".join(lines)