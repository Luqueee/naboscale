use crate::error::Result;
use rusqlite::Connection;
use std::sync::{Arc, Mutex};

pub type Db = Arc<Mutex<Connection>>;

/// Default token lifetime: 30 days. Override via
/// `NABOSCALE_COORD_TOKEN_TTL_SECS` env var in `main.rs`.
pub const DEFAULT_TOKEN_TTL_SECS: i64 = 30 * 24 * 60 * 60;

pub fn open(path: &str) -> Result<Db> {
    let conn = Connection::open(path)?;
    init_schema(&conn)?;
    Ok(Arc::new(Mutex::new(conn)))
}

pub fn open_in_memory() -> Result<Db> {
    let conn = Connection::open_in_memory()?;
    init_schema(&conn)?;
    Ok(Arc::new(Mutex::new(conn)))
}

fn init_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS nodes (
            node_id TEXT PRIMARY KEY,
            identity_pubkey BLOB NOT NULL UNIQUE,
            wg_pubkey BLOB NOT NULL UNIQUE,
            ip TEXT NOT NULL UNIQUE,
            last_endpoint TEXT,
            via_relay TEXT,
            last_seen INTEGER,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY,
            node_id TEXT NOT NULL REFERENCES nodes(node_id),
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_nodes_identity ON nodes(identity_pubkey);
        CREATE INDEX IF NOT EXISTS idx_nodes_wg ON nodes(wg_pubkey);
        CREATE INDEX IF NOT EXISTS idx_tokens_node ON tokens(node_id);
        "#,
    )?;
    // Idempotent migrations for older databases.
    let _ = conn.execute("ALTER TABLE nodes ADD COLUMN via_relay TEXT", []);
    let _ = conn.execute(
        "ALTER TABLE tokens ADD COLUMN expires_at INTEGER NOT NULL DEFAULT 0",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE tokens ADD COLUMN revoked INTEGER NOT NULL DEFAULT 0",
        [],
    );
    // Backfill: tokens created before expires_at existed get a default TTL
    // measured from created_at so existing databases keep working after
    // upgrade without invalidating every live session.
    conn.execute(
        "UPDATE tokens SET expires_at = created_at + ? WHERE expires_at = 0",
        rusqlite::params![DEFAULT_TOKEN_TTL_SECS],
    )?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct NodeRecord {
    pub node_id: String,
    pub identity_pubkey: Vec<u8>,
    pub wg_pubkey: Vec<u8>,
    pub ip: String,
    pub last_endpoint: Option<String>,
    pub via_relay: Option<String>,
    pub last_seen: Option<i64>,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct TokenRecord {
    pub token: String,
    pub node_id: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub revoked: bool,
}

pub fn insert_node(db: &Db, node: &NodeRecord, token: &str, ttl_secs: i64) -> Result<()> {
    let conn = db.lock().expect("db mutex poisoned");
    conn.execute(
        "INSERT INTO nodes (node_id, identity_pubkey, wg_pubkey, ip, via_relay, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        rusqlite::params![node.node_id, node.identity_pubkey, node.wg_pubkey, node.ip, node.via_relay, node.created_at],
    )?;
    conn.execute(
        "INSERT INTO tokens (token, node_id, created_at, expires_at, revoked) VALUES (?, ?, ?, ?, 0)",
        rusqlite::params![token, node.node_id, node.created_at, node.created_at + ttl_secs],
    )?;
    Ok(())
}

/// Look up a node by its auth token. Returns `None` if the token doesn't
/// exist, has been revoked, or is past its `expires_at`. Callers translate
/// `None` into a 401.
pub fn get_node_by_token(db: &Db, token: &str, now: i64) -> Result<Option<NodeRecord>> {
    let conn = db.lock().expect("db mutex poisoned");
    let mut stmt = conn.prepare(
        "SELECT n.node_id, n.identity_pubkey, n.wg_pubkey, n.ip, n.last_endpoint, n.via_relay, n.last_seen, n.created_at
         FROM nodes n
         JOIN tokens t ON t.node_id = n.node_id
         WHERE t.token = ? AND t.revoked = 0 AND t.expires_at > ?",
    )?;
    let mut rows = stmt.query(rusqlite::params![token, now])?;
    if let Some(row) = rows.next()? {
        Ok(Some(row_to_node(row)?))
    } else {
        Ok(None)
    }
}

pub fn list_peers(db: &Db, exclude_node_id: Option<&str>) -> Result<Vec<NodeRecord>> {
    let conn = db.lock().expect("db mutex poisoned");
    let mut stmt = conn.prepare(
        "SELECT node_id, identity_pubkey, wg_pubkey, ip, last_endpoint, via_relay, last_seen, created_at FROM nodes",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(NodeRecord {
            node_id: row.get(0)?,
            identity_pubkey: row.get(1)?,
            wg_pubkey: row.get(2)?,
            ip: row.get(3)?,
            last_endpoint: row.get(4)?,
            via_relay: row.get(5)?,
            last_seen: row.get(6)?,
            created_at: row.get(7)?,
        })
    })?;
    let mut result = Vec::new();
    for row in rows {
        let r = row?;
        if let Some(exclude) = exclude_node_id {
            if r.node_id == exclude {
                continue;
            }
        }
        result.push(r);
    }
    Ok(result)
}

pub fn update_endpoint(db: &Db, node_id: &str, endpoint: &str, last_seen: i64) -> Result<()> {
    let conn = db.lock().expect("db mutex poisoned");
    conn.execute(
        "UPDATE nodes SET last_endpoint = ?, last_seen = ? WHERE node_id = ?",
        rusqlite::params![endpoint, last_seen, node_id],
    )?;
    Ok(())
}

pub fn update_heartbeat(
    db: &Db,
    node_id: &str,
    endpoint: &str,
    via_relay: Option<&str>,
    last_seen: i64,
) -> Result<()> {
    let conn = db.lock().expect("db mutex poisoned");
    conn.execute(
        "UPDATE nodes SET last_endpoint = ?, via_relay = COALESCE(?, via_relay), last_seen = ? WHERE node_id = ?",
        rusqlite::params![endpoint, via_relay, last_seen, node_id],
    )?;
    Ok(())
}

/// Revoke every active token belonging to `node_id`. Returns the number of
/// rows affected. Used by `POST /v1/token/refresh` (kills the old token once
/// the new one is issued) and by `DELETE /v1/node`.
pub fn revoke_all_tokens_for_node(db: &Db, node_id: &str) -> Result<usize> {
    let conn = db.lock().expect("db mutex poisoned");
    let n = conn.execute(
        "UPDATE tokens SET revoked = 1 WHERE node_id = ? AND revoked = 0",
        rusqlite::params![node_id],
    )?;
    Ok(n)
}

/// Issue a new token row for `node_id`. Caller is responsible for revoking
/// any prior tokens first (or accepting that both are valid until the old
/// one expires).
pub fn create_token(
    db: &Db,
    node_id: &str,
    token: &str,
    created_at: i64,
    ttl_secs: i64,
) -> Result<()> {
    let conn = db.lock().expect("db mutex poisoned");
    conn.execute(
        "INSERT INTO tokens (token, node_id, created_at, expires_at, revoked) VALUES (?, ?, ?, ?, 0)",
        rusqlite::params![token, node_id, created_at, created_at + ttl_secs],
    )?;
    Ok(())
}

/// Look up a token row (without the expiry/revoked filter — for admin /
/// refresh flows that need to know WHY auth failed).
pub fn get_token(db: &Db, token: &str) -> Result<Option<TokenRecord>> {
    let conn = db.lock().expect("db mutex poisoned");
    let mut stmt = conn.prepare(
        "SELECT token, node_id, created_at, expires_at, revoked FROM tokens WHERE token = ?",
    )?;
    let mut rows = stmt.query(rusqlite::params![token])?;
    if let Some(row) = rows.next()? {
        Ok(Some(TokenRecord {
            token: row.get(0)?,
            node_id: row.get(1)?,
            created_at: row.get(2)?,
            expires_at: row.get(3)?,
            revoked: row.get::<_, i64>(4)? != 0,
        }))
    } else {
        Ok(None)
    }
}

/// Delete the node and ALL its tokens. IP goes back to the allocator when
/// the coordinator restarts the allocator; for an in-process allocator the
/// pool is updated by `IpAllocator::release`. Returns the released IP if any.
pub fn delete_node(db: &Db, node_id: &str) -> Result<Option<String>> {
    let conn = db.lock().expect("db mutex poisoned");
    let ip: Option<String> = conn
        .query_row(
            "SELECT ip FROM nodes WHERE node_id = ?",
            rusqlite::params![node_id],
            |row| row.get(0),
        )
        .ok();
    conn.execute(
        "DELETE FROM tokens WHERE node_id = ?",
        rusqlite::params![node_id],
    )?;
    conn.execute(
        "DELETE FROM nodes WHERE node_id = ?",
        rusqlite::params![node_id],
    )?;
    Ok(ip)
}

fn row_to_node(row: &rusqlite::Row<'_>) -> rusqlite::Result<NodeRecord> {
    Ok(NodeRecord {
        node_id: row.get(0)?,
        identity_pubkey: row.get(1)?,
        wg_pubkey: row.get(2)?,
        ip: row.get(3)?,
        last_endpoint: row.get(4)?,
        via_relay: row.get(5)?,
        last_seen: row.get(6)?,
        created_at: row.get(7)?,
    })
}
