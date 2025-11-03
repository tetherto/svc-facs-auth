'use strict'

const net = require('net')

const dateNowSec = () => Math.floor(Date.now() / 1000)

const extractIps = (req) => {
  const ips = new Set()

  if (req.headers?.['x-forwarded-for']) {
    req.headers['x-forwarded-for'].split(',').forEach(ip => {
      ips.add(ip.trim())
    })
  }

  if (req.ip) {
    ips.add(req.ip)
  }

  if (req.ips) {
    req.ips.map(ip => ips.add(ip))
  }

  if (req.socket?.remoteAddress) {
    ips.add(req.socket.remoteAddress)
  }

  if (!ips.size) {
    throw new Error('ERR_IP_RESOLVE_FAIL')
  }

  return Array.from(ips.values())
}

const isValidIp = (ip) => typeof ip === 'string' && net.isIP(ip) !== 0

const parseSql = (sql) => {
  // read table name
  const tableMatch = sql.match(/CREATE TABLE IF NOT EXISTS (\w+)/i)
  const table = tableMatch[1]

  // parse each column definition
  const columns = {}
  const columnsMatch = sql.match(/\((.*)\)/s)
  for (const definition of columnsMatch[1].split(',').map(s => s.trim())) {
    const name = definition.split(/\s+/)[0]
    columns[name] = definition
  }
  return { table, columns }
}

module.exports = {
  dateNowSec,
  extractIps,
  isValidIp,
  parseSql
}
