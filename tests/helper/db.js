'use strict'

const sqlite3 = require('sqlite3').verbose()

const newDb = () => {
  const db = new sqlite3.Database(':memory:')

  return {
    db,
    close: () => db.close()
  }
}

module.exports = newDb