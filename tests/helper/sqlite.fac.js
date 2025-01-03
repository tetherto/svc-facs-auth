'use strict'

const newDb = require('./db')
const { promisify } = require('util')

module.exports = () => {
  const { db, stop } = newDb()

  return {
    getAsync: promisify(db.get.bind(db)),
    allAsync: promisify(db.all.bind(db)),
    runAsync: (sql, params = []) => {
      return new Promise((resolve, reject) => {
        return db.run(sql, params, function (err, res) { // passing an arrow function won't work
          if (err) return reject(err)
          return resolve(this)
        })
      })
    },
    execAsync: promisify(db.exec.bind(db)),
    stop
  }
}
