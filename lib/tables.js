'use strict'

const tables = [
  `CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    name TEXT,
    roles TEXT NOT NULL,
    password TEXT,
    lastActiveAt INT
  )`
]

module.exports = tables
