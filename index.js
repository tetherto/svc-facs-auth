'use strict'

const async = require('async')
const Base = require('bfx-facs-base')
const TABLES = require('./lib/tables')
const { dateNowSec, extractIps, isValidIp } = require('./lib/utils')
const { isNil, isPlainObject, getArrayUniq } = require('@bitfinexcom/lib-js-util-base')
const crypto = require('crypto')

class AuthFacility extends Base {
  constructor (caller, opts, ctx) {
    super(caller, opts, ctx)

    this.name = 'auth'
    this._lru = opts.lru
    this._sqlite = opts.sqlite
    this._httpc = opts.httpc
    this._httpd = opts.httpd

    this._authHandlers = {}
    this._hasConf = true
  }

  async _initDb () {
    this.init()
    await async.mapSeries(TABLES, async (tbl) => {
      await this._sqlite.execAsync(tbl)
    })
  }

  addHandlers (handlers) {
    Object.assign(this._authHandlers, handlers)
  }

  _validateTokenOpts ({ ips, userId, ttl, metadata, pfx, scope, caps, write }) {
    if (!Array.isArray(ips) || !ips.length || !ips.every(ip => isValidIp(ip))) {
      throw new Error('ERR_IPS_INVALID')
    }

    if (!Number.isInteger(userId) || userId < 1) {
      throw new Error('ERR_USERID_INVALID')
    }

    if (!Number.isInteger(ttl) || ttl < 5 || ttl > 86400) { // min 5s, max 1d
      throw new Error('ERR_TTL_INVALID')
    }

    if (!isNil(metadata) && !isPlainObject(metadata)) {
      throw new Error('ERR_METADATA_INVALID')
    }

    if (pfx !== 'pub') {
      throw new Error('ERR_PFX_INVALID')
    }

    if (scope !== 'api') {
      throw new Error('ERR_SCOPE_INVALID')
    }

    if (!Array.isArray(caps) || !caps.every(c => typeof c === 'string')) {
      throw new Error('ERR_CAPS_INVALID')
    }

    if (typeof write !== 'boolean') {
      throw new Error('ERR_WRITE_INVALID')
    }
  }

  async genToken ({ ips, userId, ttl = 300, metadata = {}, pfx = 'pub', scope = 'api', caps = [], write = false }) {
    const now = dateNowSec()

    this._validateTokenOpts({ ips, userId, ttl, metadata, pfx, scope, caps, write })

    let strCaps = ''
    if (caps.length) {
      strCaps = '-caps:' + caps.join(':')
    }
    const optag = write ? 'write' : 'read'
    const token = `${pfx}:${scope}:${crypto.randomUUID()}-${userId}${strCaps}-${optag}`

    await this._sqlite.runAsync(
      'INSERT INTO auth_tokens(token, userId, ips, metadata, created, ttl) VALUES (?, ?, ?, ?, ?, ?)',
      [token, userId, JSON.stringify(getArrayUniq(ips)), JSON.stringify(metadata), now, ttl]
    )

    return token
  }

  async regenerateToken ({ oldToken, ips = null, ttl = 300, pfx = 'pub', scope = 'api', caps = [], write = false }) {
    const old = await this._getTokenFromDb(oldToken)
    if (!old) {
      throw new Error('ERR_OLD_TOKEN_INVALID')
    }

    ips = ips || old.ips
    const userId = old.userId

    const oldWrite = oldToken.endsWith('-write')
    if (!oldWrite && write) {
      throw new Error('ERR_WRITE_PERM_DENIED')
    }

    const oldCaps = []
    const capsMatch = oldToken.match(/(caps:[a-z:]*)/)
    if (capsMatch && capsMatch[1]) {
      oldCaps.push(...(capsMatch[1].replace('caps:', '').split(':')))
    }
    if (!caps.every(c => oldCaps.includes(c))) {
      throw new Error('ERR_CAPS_INVALID')
    }

    const newToken = await this.genToken({ ips, userId, ttl, metadata: old.metadata, pfx, scope, caps, write })
    return newToken
  }

  async createUser ({ email, caps = [], write = false }) {
    const user = await this._sqlite.getAsync(
      'SELECT * FROM users WHERE email = ? LIMIT 1', email
    )

    if (user) {
      throw new Error('ERR_USER_EXISTS')
    }

    await this._sqlite.runAsync(
      'INSERT INTO users (email, caps, write) VALUES (?, ?, ?)', email, JSON.stringify(caps), write
    )
  }

  getTokenPerms (token, inverse = false) {
    const write = token.endsWith('-write')
    let caps = token.substring(token.indexOf('-caps:'))
      .replace('-caps', '')
      .replace(write ? '-write' : '-read', '')
      .split(':')
      .filter(Boolean)

    if (inverse) {
      caps = caps.map(c => this.conf.auth_caps[c])
    }

    return { write, caps }
  }

  async resolveToken (token, ips) {
    const res = await this._getTokenFromDb(token)
    if (!res || res.created + res.ttl < dateNowSec() || !ips.some(ip => res.ips.includes(ip))) {
      return null
    }

    return res
  }

  tokenHasPerms (token, write, caps, matchAll = false) {
    const perms = this.getTokenPerms(token)
    if (write && !perms.write) {
      return false
    }

    return matchAll
      ? perms.caps.every(c => caps.includes(c))
      : perms.caps.some(c => caps.includes(c))
  }

  async _getTokenFromDb (token) {
    if (typeof token !== 'string' || /^[a-zA-Z0-9:\-]$/.test(token)) { //eslint-disable-line
      return null
    }

    const ckey = `gotokens:${token}`
    let res = this._lru.get(ckey)

    if (!res) {
      res = await this._sqlite.getAsync(
        'SELECT * FROM auth_tokens WHERE token = ? LIMIT 1',
        token)

      if (res) {
        res.metadata = res.metadata ? JSON.parse(res.metadata) : {}
        res.ips = JSON.parse(res.ips)
        this._lru.set(ckey, res)
      }
    }

    return res
  }

  async cleanupTokens () {
    await this._sqlite.runAsync(
      'DELETE FROM auth_tokens WHERE created + ttl < ?',
      dateNowSec()
    )
  }

  async authCallbackHandler (type, req) {
    const token = await this._resolveAuth(type, req)

    if (!token) {
      throw new Error('ERR_AUTH_FAIL')
    }

    return token
  }

  async _resolveAuth (type, req) {
    const handler = this._authHandlers[type]
    if (!handler || typeof handler !== 'function') {
      throw new Error('ERR_INVALID_HANDLER')
    }

    const info = await handler(this.caller, req)
    if (!info || !info.email) {
      return null
    }

    // read user from table `users`
    const user = await this._sqlite.getAsync(
      'SELECT * FROM users WHERE email = ? LIMIT 1', info.email
    )
    if (!user) {
      return null
    }

    user.write = user.write === 1
    const userId = user.id

    const metadata = { ...info, ...user }
    const ips = extractIps(req)

    const caps = []
    if (metadata.caps?.length) {
      caps.push(...JSON.parse(metadata.caps))
    }
    if (!metadata.write && !caps.length) {
      caps.push(...Object.keys(this.conf.auth_caps))
    }

    const token = await this.genToken({ ips, userId, ttl: this.conf.ttl, metadata, write: metadata.write, caps })
    return token
  }

  async _start (cb) {
    async.series([
      next => { super._start(next) },
      async () => {
        await this._initDb()
      }
    ], cb)
  }
}

module.exports = AuthFacility
