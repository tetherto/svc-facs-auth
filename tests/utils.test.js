'use strict'

const test = require('brittle')
const { dateNowSec, extractIps, isValidIp, parseSql } = require('../lib/utils')

test('utils', async (t) => {
  t.test('dateNowSec', async (t) => {
    const now = Math.floor(Date.now() / 1000)
    const resp = dateNowSec()

    t.is(resp, now, 'returns current time in seconds')
    t.is(typeof resp, 'number', 'returns a Number')
  })

  t.test('extractIps', async (t) => {
    // Default: only socket.remoteAddress is trusted; spoofable header / framework
    // values are ignored unless trustProxy is explicitly enabled.
    t.exception(() => extractIps({ headers: { 'x-forwarded-for': '127.0.0.1' } }), /ERR_IP_RESOLVE_FAIL/, 'ignores x-forwarded-for by default')
    t.exception(() => extractIps({ ip: '1.1.1.1' }), /ERR_IP_RESOLVE_FAIL/, 'ignores req.ip by default')
    t.exception(() => extractIps({ ips: ['1.1.1.1', '2.2.2.2'] }), /ERR_IP_RESOLVE_FAIL/, 'ignores req.ips by default')
    t.alike(extractIps({ socket: { remoteAddress: '3.3.3.3' } }), ['3.3.3.3'], 'reads IP from req.socket.remoteAddress')
    t.exception(() => extractIps({}), /ERR_IP_RESOLVE_FAIL/, 'throws if no IP found')

    // With trustProxy: framework-derived values are honoured, raw header is still ignored.
    t.alike(extractIps({ ip: '1.1.1.1' }, { trustProxy: true }), ['1.1.1.1'], 'reads req.ip when trustProxy')
    t.alike(extractIps({ ips: ['1.1.1.1', '2.2.2.2'] }, { trustProxy: true }), ['1.1.1.1', '2.2.2.2'], 'reads req.ips when trustProxy')
    t.alike(
      extractIps({ ip: '1.1.1.1', socket: { remoteAddress: '3.3.3.3' } }, { trustProxy: true }),
      ['1.1.1.1', '3.3.3.3'],
      'unions req.ip with socket.remoteAddress when trustProxy'
    )
    t.exception(
      () => extractIps({ headers: { 'x-forwarded-for': '127.0.0.1' } }, { trustProxy: true }),
      /ERR_IP_RESOLVE_FAIL/,
      'still ignores raw x-forwarded-for header when trustProxy'
    )
  })

  t.test('isValidIp', async (t) => {
    t.ok(isValidIp('::1'), '::1 is a valid IPv6 address')
    t.ok(isValidIp('127.0.0.1'), '127.0.0.1 is a valid IPv4 address')
    t.absent(isValidIp('foo'), 'foo is not a valid IP address')
    t.absent(isValidIp('127.000.000.001'), '127.000.000.001 is not a valid IP address')
    t.absent(isValidIp('127.0.0.1/24'), 'subnet is not a valid IP address')
  })

  t.test('parseSql', async (t) => {
    const sql = `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY,
      name TEXT,
      email TEXT
    )`
    const result = parseSql(sql)
    t.is(result.table, 'users', 'extracts table name correctly')
    t.ok(result.columns.id, 'extracts id column')
    t.ok(result.columns.name, 'extracts name column')
    t.ok(result.columns.email, 'extracts email column')
    t.is(result.columns.id, 'id INTEGER PRIMARY KEY', 'preserves full column definition for id')
    t.is(result.columns.name, 'name TEXT', 'preserves full column definition for name')
    t.is(result.columns.email, 'email TEXT', 'preserves full column definition for email')
  })
})
