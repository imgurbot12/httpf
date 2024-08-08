//! Simple Sqlite Database for Dynamic but Persistant Firewall Configuration

use std::{net::IpAddr, str::FromStr};

use anyhow::{Context, Result};
use chrono::{DateTime, NaiveDateTime, Utc};
use rusqlite::{Connection, OptionalExtension};

static SCHEMA: &'static str = include_str!("./sql/schema.sql");
static INSERT_WHITELIST: &'static str = "INSERT INTO Whitelist VALUES (?1, ?2)";
static INSERT_BLACKLIST: &'static str = "INSERT INTO Blacklist VALUES (?1, ?2)";
static REMOVE_WHITELIST: &'static str = "DELETE FROM Whitelist WHERE IpAddr=?1";
static REMOVE_BLACKLIST: &'static str = "DELETE FROM Blacklist WHERE IpAddr=?1";
static CLEAN_WHITELIST: &'static str = "DELETE FROM Whitelist WHERE Expires<=?1";
static CLEAN_BLACKLIST: &'static str = "DELETE FROM Whitelist WHERE Expires<=?1";

static LIST_WHITELIST: &'static str = "SELECT * FROM Whitelist";
static LIST_BLACKLIST: &'static str = "SELECT * FROM Blacklist";

static CHECK_WHITELIST: &'static str =
    "SELECT 1 FROM Whitelist WHERE IpAddr=?1 AND (Expires IS NULL or Expires >=?2)";
static CHECK_BLACKLIST: &'static str =
    "SELECT 1 FROM Blacklist WHERE IpAddr=?1 AND (Expires IS NULL or Expires >=?2)";

#[derive(Debug)]
pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn new(path: &str) -> Result<Self> {
        let conn = Connection::open(path).context("failed to open sqlite database")?;
        conn.execute_batch(SCHEMA)
            .context("failed to build schema")?;
        Ok(Self { conn })
    }
    fn clean_tables(&self) -> Result<()> {
        self.conn
            .execute(CLEAN_WHITELIST, (Utc::now(),))
            .context("failed to clean whitelist")?;
        self.conn
            .execute(CLEAN_BLACKLIST, (Utc::now(),))
            .context("failed to clean blacklist")?;
        Ok(())
    }
    pub fn add_whitelist(&self, ip: &IpAddr, expires: Option<DateTime<Utc>>) -> Result<bool> {
        if self.whitelist_contains(ip)? {
            return Ok(false);
        }
        self.conn
            .execute(INSERT_WHITELIST, (&ip.to_string(), &expires))
            .context("insert into whitelist failed")?;
        Ok(true)
    }
    pub fn add_blacklist(&self, ip: &IpAddr, expires: Option<DateTime<Utc>>) -> Result<bool> {
        if self.blacklist_contains(ip)? {
            return Ok(false);
        }
        self.conn
            .execute(INSERT_BLACKLIST, (&ip.to_string(), &expires))
            .context("insert into whitelist failed")?;
        Ok(true)
    }
    pub fn remove_whitelist(&self, ip: &IpAddr) -> Result<bool> {
        self.clean_tables()?;
        Ok(self
            .conn
            .execute(REMOVE_WHITELIST, (&ip.to_string(),))
            .context("delete from whitelist failed")?
            == 1)
    }
    pub fn remove_blacklist(&self, ip: &IpAddr) -> Result<bool> {
        self.clean_tables()?;
        Ok(self
            .conn
            .execute(REMOVE_BLACKLIST, (&ip.to_string(),))
            .context("delete from whitelist failed")?
            == 1)
    }
    pub fn whitelist_contains(&self, ip: &IpAddr) -> Result<bool> {
        let args = (&ip.to_string(), Utc::now());
        self.conn
            .query_row(CHECK_WHITELIST, args, |row| row.get(0))
            .optional()
            .context("failed to query whitelist")
            .map(|r| r.unwrap_or(false))
    }
    pub fn blacklist_contains(&self, ip: &IpAddr) -> Result<bool> {
        let args = (&ip.to_string(), Utc::now());
        self.conn
            .query_row(CHECK_BLACKLIST, args, |row| row.get(0))
            .optional()
            .context("failed to query blacklist")
            .map(|r| r.unwrap_or(false))
    }
    pub fn list_whitelist(&self) -> Result<Vec<ListEntry>> {
        self.clean_tables()?;
        let mut stmt = self
            .conn
            .prepare(LIST_WHITELIST)
            .context("failed to prepare whitelist query")?;
        let entries = stmt
            .query_map((), |row| {
                let ip: String = row.get(0)?;
                Ok(ListEntry {
                    ip: IpAddr::from_str(&ip).expect("invalid whitelist ip"),
                    expires: row.get(1)?,
                })
            })
            .into_iter()
            .flatten()
            .filter_map(|r| r.ok())
            .collect();
        Ok(entries)
    }
    pub fn list_blacklist(&self) -> Result<Vec<ListEntry>> {
        self.clean_tables()?;
        let mut stmt = self
            .conn
            .prepare(LIST_BLACKLIST)
            .context("failed to prepare blacklist query")?;
        let entries = stmt
            .query_map((), |row| {
                let ip: String = row.get(0)?;
                Ok(ListEntry {
                    ip: IpAddr::from_str(&ip).expect("invalid blacklist ip"),
                    expires: row.get(1)?,
                })
            })
            .into_iter()
            .flatten()
            .filter_map(|r| r.ok())
            .collect();
        Ok(entries)
    }
}

#[derive(Debug)]
pub struct ListEntry {
    pub ip: IpAddr,
    pub expires: Option<NaiveDateTime>,
}
