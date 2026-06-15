use crate::error::Result;
use rusqlite::Connection;
use std::sync::{Arc, Mutex};

pub type Db = Arc<Mutex<Connection>>;

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
            last_seen INTEGER,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY,
            node_id TEXT NOT NULL REFERENCES nodes(node_id),
            created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_nodes_identity ON nodes(identity_pubkey);
        CREATE INDEX IF NOT EXISTS idx_nodes_wg ON nodes(wg_pubkey);
        "#,
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
    pub last_seen: Option<i64>,
    pub created_at: i64,
}

pub fn insert_node(db: &Db, node: &NodeRecord, token: &str) -> Result<()> {
    let conn = db.lock().expect("db mutex poisoned");
    conn.execute(
        "INSERT INTO nodes (node_id, identity_pubkey, wg_pubkey, ip, created_at) VALUES (?, ?, ?, ?, ?)",
        rusqlite::params![node.node_id, node.identity_pubkey, node.wg_pubkey, node.ip, node.created_at],
    )?;
    conn.execute(
        "INSERT INTO tokens (token, node_id, created_at) VALUES (?, ?, ?)",
        rusqlite::params![token, node.node_id, node.created_at],
    )?;
    Ok(())
}

pub fn get_node_by_token(db: &Db, token: &str) -> Result<Option<NodeRecord>> {
    let conn = db.lock().expect("db mutex poisoned");
    let mut stmt = conn.prepare(
        "SELECT n.node_id, n.identity_pubkey, n.wg_pubkey, n.ip, n.last_endpoint, n.last_seen, n.created_at
         FROM nodes n
         JOIN tokens t ON t.node_id = n.node_id
         WHERE t.token = ?",
    )?;
    let mut rows = stmt.query(rusqlite::params![token])?;
    if let Some(row) = rows.next()? {
        Ok(Some(row_to_node(row)?))
    } else {
        Ok(None)
    }
}

pub fn list_peers(db: &Db, exclude_node_id: Option<&str>) -> Result<Vec<NodeRecord>> {
    let conn = db.lock().expect("db mutex poisoned");
    let mut stmt = conn.prepare(
        "SELECT node_id, identity_pubkey, wg_pubkey, ip, last_endpoint, last_seen, created_at FROM nodes",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(NodeRecord {
            node_id: row.get(0)?,
            identity_pubkey: row.get(1)?,
            wg_pubkey: row.get(2)?,
            ip: row.get(3)?,
            last_endpoint: row.get(4)?,
            last_seen: row.get(5)?,
            created_at: row.get(6)?,
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

fn row_to_node(row: &rusqlite::Row<'_>) -> rusqlite::Result<NodeRecord> {
    Ok(NodeRecord {
        node_id: row.get(0)?,
        identity_pubkey: row.get(1)?,
        wg_pubkey: row.get(2)?,
        ip: row.get(3)?,
        last_endpoint: row.get(4)?,
        last_seen: row.get(5)?,
        created_at: row.get(6)?,
    })
}
