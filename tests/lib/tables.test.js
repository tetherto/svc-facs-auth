'use strict'

const test = require('brittle')
const tables = require('../../lib/tables')

test('tables', async (t) => {
  const sqlite3 = require('sqlite3').verbose()
  const db = new sqlite3.Database(':memory:')

  let autoInc = 0

  // Create tables
  db.serialize(() => {
    tables.forEach((table) => {
      if (table.includes('AUTOINCREMENT')) {
        autoInc = 1
      }
      db.run(table)
    })
  })

  // Check if tables are created
  await new Promise((resolve, reject) => {
    db.all("SELECT name FROM sqlite_master WHERE type='table'", (err, rows) => {
      if (err) {
        reject(err)
      }

      t.is(rows.length, tables.length + autoInc, 'tables are ok')
      resolve()
    })
  })
})
