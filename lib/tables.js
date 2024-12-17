'use strict'

const tables = [
  `CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    roles TEXT NOT NULL,
    password TEXT
  )`,
  `CREATE TABLE IF NOT EXISTS auth_tokens (
    token TEXT NOT NULL PRIMARY KEY,
    userId INTEGER NOT NULL,
    ips TEXT NOT NULL,
    metadata TEXT,
    created INT NOT NULL,
    ttl INT NOT NULL
  )`
]

module.exports = tables
