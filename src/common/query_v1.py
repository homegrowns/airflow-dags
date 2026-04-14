from typing import Final

SESSION_QUERY: Final[str] = """
UNWIND $rows AS r
MERGE (s:Session {session_id: r.session_id})
SET
  s.community_id           = r.community_id,
  s.uid                    = r.uid,
  s.ts                     = r.ts,
  s.src_ip                 = r.src_ip,
  s.src_port               = r.src_port,
  s.dest_ip                = r.dest_ip,
  s.dest_port              = r.dest_port,
  s.proto                  = r.proto,
  s.service                = r.service,
  s.duration               = r.duration,
  s.orig_bytes             = r.orig_bytes,
  s.resp_bytes             = r.resp_bytes,
  s.conn_state             = r.conn_state,
  s.missed_bytes           = r.missed_bytes,
  s.history                = r.history,
  s.orig_pkts              = r.orig_pkts,
  s.resp_pkts              = r.resp_pkts,
  s.http_method            = r.http_method,
  s.http_host              = r.http_host,
  s.http_uri               = r.http_uri,
  s.http_user_agent        = r.http_user_agent,
  s.http_request_body_len  = r.http_request_body_len,
  s.http_response_body_len = r.http_response_body_len,
  s.http_status_code       = r.http_status_code,
  s.http_status_msg        = r.http_status_msg,
  s.dns_query              = r.dns_query,
  s.dns_qtype_name         = r.dns_qtype_name,
  s.dns_rcode_name         = r.dns_rcode_name,
  s.dns_answers            = r.dns_answers,
  s.dns_rtt                = r.dns_rtt,
  s.tls_version            = r.tls_version,
  s.tls_cipher             = r.tls_cipher,
  s.tls_curve              = r.tls_curve,
  s.tls_sni                = r.tls_sni,
  s.tls_ssl_history        = r.tls_ssl_history,
  s.tls_established        = r.tls_established,
  s.tls_resumed            = r.tls_resumed,
  s.alert_count            = r.alert_count,
  s.max_severity           = r.max_severity,
  s.is_threat              = r.is_threat,
  s.flow_state             = r.flow_state,
  s.flow_reason            = r.flow_reason,
  s.pkts_toserver          = r.pkts_toserver,
  s.pkts_toclient          = r.pkts_toclient,
  s.bytes_toserver         = r.bytes_toserver,
  s.bytes_toclient         = r.bytes_toclient,
  s.flow_start             = r.flow_start,
  s.flow_end               = r.flow_end
"""


# ══════════════════════════════════════════════════════════════════════════════
# Task 3 : load_entities
# ══════════════════════════════════════════════════════════════════════════════

IP_QUERY: Final[str] = """
UNWIND $rows AS r
MERGE (n:IP {value: r.entity_value})
SET n.first_seen=r.first_seen, n.last_seen=r.last_seen,
    n.related_session_count=r.related_session_count,
    n.total_orig_bytes=r.total_orig_bytes, n.total_resp_bytes=r.total_resp_bytes
"""
DOMAIN_QUERY: Final[str] = """
UNWIND $rows AS r
MERGE (n:Domain {value: r.entity_value})
SET n.first_seen=r.first_seen, n.last_seen=r.last_seen,
    n.related_session_count=r.related_session_count
"""
ALERT_QUERY: Final[str] = """
UNWIND $rows AS r
MERGE (n:Alert {value: r.entity_value})
SET n.first_seen=r.first_seen, n.last_seen=r.last_seen,
    n.related_session_count=r.related_session_count,
    n.signature=r.signature, n.category=r.category
"""


# ══════════════════════════════════════════════════════════════════════════════
# Task 4 : load_relations
# ══════════════════════════════════════════════════════════════════════════════

SESSION_CONN_QUERY: Final[str] = """
UNWIND $rows AS r
MATCH (src:Session {session_id: r.session_id})
MATCH (dst:IP      {value:      r.dest_ip})
MERGE (src)-[:CONNECTED_TO {session_id: r.session_id}]->(dst)
"""
SESSION_ORIG_QUERY: Final[str] = """
UNWIND $rows AS r
MATCH (src:Session {session_id: r.session_id})
MATCH (dst:IP      {value:      r.src_ip})
MERGE (src)-[:ORIGINATED_FROM {session_id: r.session_id}]->(dst)
"""
RELATION_QUERIES: Final[dict[str, str]] = {
    "REQUESTED_domain": "UNWIND $rows AS r MATCH (src:IP {value:r.src_value}) MATCH (dst:Domain {value:r.dst_value}) MERGE (src)-[:REQUESTED {session_id:r.session_id}]->(dst)",
    "REQUESTED_ip": "UNWIND $rows AS r MATCH (src:IP {value:r.src_value}) MATCH (dst:IP     {value:r.dst_value}) MERGE (src)-[:REQUESTED {session_id:r.session_id}]->(dst)",
    "RESOLVED_BY_ip": "UNWIND $rows AS r MATCH (src:Domain {value:r.src_value}) MATCH (dst:IP     {value:r.dst_value}) MERGE (src)-[:RESOLVED_BY {session_id:r.session_id}]->(dst)",
    "RESOLVED_BY_domain": "UNWIND $rows AS r MATCH (src:Domain {value:r.src_value}) MATCH (dst:Domain {value:r.dst_value}) MERGE (src)-[:RESOLVED_BY {session_id:r.session_id}]->(dst)",
    "TRIGGERED": "UNWIND $rows AS r MATCH (src:Session {session_id:r.src_value}) MATCH (dst:Alert {value:r.dst_value}) MERGE (src)-[:TRIGGERED {session_id:r.session_id}]->(dst)",
    "SERVED_OVER_TLS": "UNWIND $rows AS r MATCH (src:Session {session_id:r.src_value}) MERGE (dst:Domain {value:r.dst_value}) MERGE (src)-[:SERVED_OVER_TLS {session_id:r.session_id}]->(dst)",
    "ENCRYPTED_WITH": "UNWIND $rows AS r MATCH (src:Session {session_id:r.src_value}) MERGE (dst:Cipher {value:r.dst_value}) MERGE (src)-[:ENCRYPTED_WITH {session_id:r.session_id}]->(dst)",
}

# ══════════════════════════════════════════════════════════════════════════════
# Task 5 : create_indexes
# ══════════════════════════════════════════════════════════════════════════════

CONSTRAINTS: Final[list[str]] = [
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Session) REQUIRE n.session_id IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:IP)      REQUIRE n.value IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Domain)  REQUIRE n.value IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Alert)   REQUIRE n.value IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Cipher)  REQUIRE n.value IS UNIQUE",
]
INDEXES: Final[list[str]] = [
    "CREATE INDEX IF NOT EXISTS FOR (n:Session) ON (n.community_id)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Session) ON (n.uid)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Session) ON (n.ts)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Session) ON (n.is_threat)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Session) ON (n.src_ip)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Session) ON (n.dest_ip)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Session) ON (n.flow_start)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Session) ON (n.conn_state)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Session) ON (n.tls_sni)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Session) ON (n.tls_version)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Session) ON (n.http_status_code)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Session) ON (n.dns_query)",
    "CREATE INDEX IF NOT EXISTS FOR (n:IP)      ON (n.first_seen)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Alert)   ON (n.category)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Domain)  ON (n.first_seen)",
]

BATCH_QUERY: Final[str] = """
    UNWIND $session_ids AS sid
    MATCH (s:Session {session_id: sid})-[r]->(n)
    RETURN
        sid                       AS session_id,
        type(r)                   AS rel_type,
        labels(n)                 AS node_labels,
        n.value                   AS node_value,
        n.signature               AS signature,
        n.category                AS category,
        n.first_seen              AS first_seen,
        n.last_seen               AS last_seen,
        n.related_session_count   AS related_session_count,
        n.total_orig_bytes        AS total_orig_bytes,
        n.total_resp_bytes        AS total_resp_bytes
    """