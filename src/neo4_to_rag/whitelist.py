from collections import defaultdict
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from src.security_metadata import CATEGORY_TO_CLASSTYPE, CLASSTYPE_RANK

KST = ZoneInfo("Asia/Seoul")
# ══════════════════════════════════════════════════════════════════════════════
# whitelist 로직
# TODO
# SUSPICION_THRESHOLD -> Airflow web variable로 관리 추가
# WHITELIST_IPS -> Configmap으로 관리 추가
# WHITELIST_CIDRS -> Configmap으로 관리 추가
# ══════════════════════════════════════════════════════════════════════════════

WHITELIST_IPS: set[str] = {
    "10.0.0.1",
    "10.0.0.2",
    "192.168.0.1",
    "192.168.0.10",
}
WHITELIST_CIDRS: list[str] = ["10.0.2.0/24"]
REPEAT_WINDOW_SEC = 10


def in_whitelist(ip: str | None) -> bool:
    if not ip:
        return False
    if ip in WHITELIST_IPS:
        return True
    import ipaddress

    try:
        addr = ipaddress.ip_address(ip)
        return any(
            addr in ipaddress.ip_network(c, strict=False) for c in WHITELIST_CIDRS
        )
    except ValueError:
        return False


def is_whitelisted_session(session: dict) -> bool:
    if session.get("src_ip") is not None:
        return in_whitelist(session["src_ip"])
    for ev in session.get("timeline", []):
        if ev.get("source") == "zeek_conn":
            return in_whitelist(ev.get("orig_h"))
        if ev.get("source") == "suricata":
            return in_whitelist(ev.get("src_ip"))
    return False


def get_session_src_ip(session: dict) -> str | None:
    if session.get("src_ip") is not None:
        return session["src_ip"]
    for ev in session.get("timeline", []):
        if ev.get("source") == "zeek_conn" and ev.get("orig_h"):
            return ev["orig_h"]
    for ev in session.get("timeline", []):
        if ev.get("source") == "suricata" and ev.get("src_ip"):
            return ev["src_ip"]
    return None


def get_session_flow_start(session: dict) -> float | None:
    ts = session.get("flow_start")
    if not ts:
        return None
    if isinstance(ts, (int, float)):
        v = float(ts)
        return v / 1000.0 if v > 1e10 else v
    try:
        s = str(ts).replace(" ", "T")
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=KST)
        return dt.astimezone(timezone.utc).timestamp()
    except Exception:
        return None


def build_repeat_count_map(sessions: list[dict]) -> dict[str, int]:

    ip_ts: dict[str, list[float]] = defaultdict(list)
    cid_to_ip: dict[str, str] = {}

    for sess in sessions:
        src_ip = get_session_src_ip(sess)
        ts = get_session_flow_start(sess)
        cid = str(sess.get("community_id") or id(sess))
        if src_ip and ts is not None:
            ip_ts[src_ip].append(ts)
            cid_to_ip[cid] = src_ip

    ip_max_count: dict[str, int] = {}
    for ip, ts_list in ip_ts.items():
        ts_list.sort()
        max_count, left = 1, 0
        for right in range(len(ts_list)):
            while ts_list[right] - ts_list[left] > REPEAT_WINDOW_SEC:
                left += 1
            max_count = max(max_count, right - left + 1)
        ip_max_count[ip] = max_count

    result: dict[str, int] = {}
    for sess in sessions:
        cid = str(sess.get("community_id") or id(sess))
        src_ip = cid_to_ip.get(cid)
        result[cid] = ip_max_count.get(src_ip, 1) if src_ip else 1
    return result


def calc_suspicion_score(session: dict, repeat_count: int = 1) -> int:
    classtypes: list[str] = []
    severities: list[int] = []
    for ev in session.get("timeline", []):
        if ev.get("source") != "suricata" or not ev.get("signature"):
            continue
        ct = CATEGORY_TO_CLASSTYPE.get(ev.get("category", ""), "unknown")
        classtypes.append(ct)
        sev = ev.get("severity")
        if sev is not None:
            try:
                severities.append(int(sev))
            except (ValueError, TypeError):
                pass

    highest_ct = max(
        classtypes, key=lambda c: CLASSTYPE_RANK.get(c, 0), default="unknown"
    )
    highest_sev = min(severities) if severities else 4

    def _ct_score(ct: str) -> int:
        HIGH = {
            "web-application-attack",
            "trojan-activity",
            "command-and-control",
            "misc-attack",
            "exploit-kit",
            "shellcode-detect",
            "targeted-activity",
            "attempted-admin",
            "successful-admin",
            "credential-theft",
            "domain-c2",
        }
        MID = {
            "bad-unknown",
            "network-scan",
            "attempted-user",
            "successful-user",
            "policy-violation",
            "attempted-dos",
            "denial-of-service",
            "coin-mining",
            "social-engineering",
        }
        if ct in HIGH:
            return 30
        if ct in MID:
            return 20
        if ct in {"not-suspicious", "unknown", "tcp-connection"}:
            return 5
        return 10

    def _sev_score(s: int) -> int:
        return {1: 30, 2: 20, 3: 10}.get(s, 0)

    def _repeat_score(cnt: int) -> int:
        if cnt >= 5:
            return 20
        if cnt >= 3:
            return 10
        return 0

    return _ct_score(highest_ct) + _sev_score(highest_sev) + _repeat_score(repeat_count)
