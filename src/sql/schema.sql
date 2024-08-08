-- Database Schema SQL

CREATE TABLE IF NOT EXISTS Blacklist (
  IpAddr  VARCHAR(50),
  Expires DATETIME
);
CREATE INDEX IF NOT EXISTS Blacklist_1 ON Blacklist (IpAddr, Expires);

CREATE TABLE IF NOT EXISTS Whitelist (
  IpAddr  VARCHAR(50),
  Expires DATETIME
);
CREATE INDEX IF NOT EXISTS Whitelist_1 ON Whitelist (IpAddr, Expires);
