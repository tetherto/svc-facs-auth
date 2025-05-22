'use strict'

const async = require('async')
const Base = require('bfx-facs-base')
const TABLES = require('./lib/tables')
const { dateNowSec, extractIps, isValidIp } = require('./lib/utils')
const { isEqual, isNil, isPlainObject, getArrayUniq, union } = require('@bitfinexcom/lib-js-util-base')
const crypto = require('crypto')
const bcrypt = require('bcrypt')

class AuthFacility extends Base {
  constructor (caller, opts, ctx) {
    super(caller, opts, ctx)

    this.name = 'auth'
    this._lru = opts.lru
    this._sqlite = opts.sqlite

    this._authHandlers = {}
    this._mfaHandlers = {}

    this._hasConf = true

    super.init()
  }

  // test added
  async _initDb () {
    await async.mapSeries(TABLES, async (tbl) => {
      await this._sqlite.execAsync(tbl)
    })

    const admin = this.conf.superAdmin
    if (!admin) {
      throw new Error('ERR_SUPER_ADMIN_MISSING')
    }

    const user = await this._sqlite.getAsync('SELECT * FROM users WHERE id = 1 LIMIT 1')
    if (!user) {
      await this._sqlite.runAsync(
        'INSERT INTO users (email, roles) VALUES (?, ?)', [admin, JSON.stringify(['*'])]
      )
    } else if (user.email !== admin) {
      const existingUser = await this.getUserByEmail(admin)
      if (existingUser) {
        await this.deleteUser(existingUser.id)
      }

      await this._sqlite.runAsync(
        'UPDATE users SET email = ? WHERE id = 1', [admin]
      )
    }
  }

  addHandlers (handlers) {
    Object.assign(this._authHandlers, handlers)
  }

  addMfaHandlers (handlers) {
    Object.assign(this._mfaHandlers, handlers)
  }

  _validateTokenOpts ({ ips, userId, ttl, metadata, pfx, scope, roles }) {
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

    if (!Array.isArray(roles) || !roles.every(c => typeof c === 'string')) {
      throw new Error('ERR_ROLES_INVALID')
    }
  }

  async genToken ({ ips, userId, ttl = this.conf.ttl || 300, metadata = {}, pfx = 'pub', scope = 'api', roles = [] }) {
    const now = dateNowSec()

    this._validateTokenOpts({ ips, userId, ttl, metadata, pfx, scope, roles })

    let strRoles = ''
    if (roles.length) {
      strRoles = '-roles:' + roles.join(':')
    }
    const token = `${pfx}:${scope}:${crypto.randomUUID()}-${userId}${strRoles}`

    await this._sqlite.runAsync(
      'INSERT INTO auth_tokens(token, userId, ips, metadata, created, ttl) VALUES (?, ?, ?, ?, ?, ?)',
      [token, userId, JSON.stringify(getArrayUniq(ips)), JSON.stringify(metadata), now, ttl]
    )

    return token
  }

  async regenerateToken ({ oldToken, ips = null, pfx = 'pub', scope = 'api', roles = [] }) {
    const old = await this._getTokenFromDb(oldToken)
    if (!old) {
      throw new Error('ERR_OLD_TOKEN_INVALID')
    }

    ips = ips || old.ips
    const userId = old.userId

    const oldRoles = []
    const rolesMatch = oldToken.match(/(roles:[a-z_*:]*)/)
    if (rolesMatch && rolesMatch[1]) {
      oldRoles.push(...(rolesMatch[1].replace('roles:', '').split(':')))
    }
    if (!roles.every(c => oldRoles.includes(c))) {
      throw new Error('ERR_ROLES_INVALID')
    }

    const newToken = await this.genToken({ ips, userId, ttl: this.conf.ttl || 300, metadata: old.metadata, pfx, scope, roles })
    return newToken
  }

  async createUser ({ email, roles = [], password = null }) {
    const user = await this._sqlite.getAsync(
      'SELECT * FROM users WHERE email = ? LIMIT 1', email
    )

    if (user) {
      throw new Error('ERR_USER_EXISTS')
    }

    if (!email) {
      throw new Error('ERR_MISSING_EMAIL')
    }

    if (!Array.isArray(roles) || !roles.length) {
      throw new Error('ERR_MISSING_ROLES')
    }

    password = password ? await bcrypt.hash(password, this.conf.saltRounds || 10) : null

    await this._sqlite.runAsync(
      'INSERT INTO users (email, roles, password) VALUES (?, ?, ?)', [email, JSON.stringify(roles), password]
    )
  }

  async updateUser ({ token, email, roles = [], password = null }) {
    let user = await this._getTokenFromDb(token)
    const userId = user?.userId
    if (!userId) {
      throw new Error('ERR_TOKEN_INVALID')
    }

    user = await this._sqlite.getAsync(
      'SELECT * FROM users WHERE id = ? LIMIT 1', userId
    )
    if (!user) {
      throw new Error('ERR_USER_NOT_FOUND')
    }

    password = password ? await bcrypt.hash(password, this.conf.saltRounds || 10) : null

    await this._sqlite.runAsync(
      'UPDATE users SET email = ?, roles = ?, password = ? WHERE id = ?', [email, JSON.stringify(roles), password, userId]
    )

    await this._deleteTokensOfUser(userId)
  }

  async compareUser ({ token, email = null, roles = null, password = null }) {
    const user = await this._getTokenFromDb(token)
    const userId = user?.userId
    if (!userId) {
      throw new Error('ERR_TOKEN_INVALID')
    }

    const dbUser = await this._sqlite.getAsync('SELECT * FROM users WHERE id = ? LIMIT 1', userId)
    if (!dbUser) {
      throw new Error('ERR_USER_NOT_FOUND')
    }

    if (!email && !roles && !password) {
      throw new Error('ERR_NO_FIELDS_PROVIDED')
    }

    const checks = [
      !email || dbUser.email === email,
      !roles || isEqual(JSON.parse(dbUser.roles || '[]').sort(), roles.sort()),
      !password || await bcrypt.compare(password, dbUser.password)
    ]

    return checks.every(Boolean)
  }

  _mergePerms (arr) {
    if (!Array.isArray(arr) || !arr.length) {
      return
    }

    const perms = arr.reduce((acc, perm) => {
      const [key, val] = perm.split(':')
      acc[key] = new Set([...(acc[key] ?? ''), ...val])
      return acc
    }, {})

    return Object.entries(perms).map(([key, val]) => `${key}:${[...val].sort().join('')}`)
  }

  getTokenPerms (token) {
    let roles = token.substring(token.indexOf('-roles:'))
      .replace('-roles', '')
      .split(':')
      .filter(Boolean)

    roles = roles.map(c => {
      if (c === '*') {
        return '*'
      }
      return this.conf.roles[c]
    })

    return {
      superadmin: roles.includes('*'),
      perms: this._mergePerms(union(...roles))
    }
  }

  async resolveToken (token, ips) {
    const res = await this._getTokenFromDb(token)
    if (!res || res.created + res.ttl < dateNowSec() || !ips.some(ip => res.ips.includes(ip))) {
      return null
    }

    return res
  }

  tokenHasPerms (token, perm) {
    const { superadmin, perms } = this.getTokenPerms(token)

    if (superadmin) {
      return true
    }

    const [key, required] = perm.split(':')
    const av = perms.find(p => p.startsWith(`${key}:`))?.split(':')[1] ?? ''
    return [...required].every(c => av.includes(c))
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

  async mfaHandler (type, req) {
    const handler = this._mfaHandlers[type]
    if (!handler || typeof handler !== 'function') {
      throw new Error('ERR_HANDLER_INVALID')
    }

    return await handler(this.caller, req)
  }

  async mfaCallbackHandler (type, req, getUserMfaMethods) {
    const token = await this.authCallbackHandler(type, req)

    if (!getUserMfaMethods || typeof getUserMfaMethods !== 'function') {
      throw new Error('ERR_MFA_METHOD_HANDLER_INVALID')
    }

    const mfaMethods = await getUserMfaMethods(this.caller, token, req)

    if (mfaMethods && mfaMethods.length > 0) {
      const csrfToken = crypto.randomUUID()
      this._lru.set(csrfToken, token)

      return {
        csrf_token: csrfToken,
        mfa_required: true,
        mfa_methods: mfaMethods
      }
    }

    return { token }
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
      throw new Error('ERR_HANDLER_INVALID')
    }

    const info = await handler(this.caller, req)
    if (!info || !info.email) {
      throw new Error('ERR_EMAIL_INVALID')
    }

    // read user from table `users`
    const user = await this._sqlite.getAsync(
      'SELECT * FROM users WHERE email = ? LIMIT 1', info.email
    )
    if (!user) {
      throw new Error('ERR_USER_NOT_EXIST')
    }

    // check if password matches
    if (info.password) {
      if (!user.password) {
        throw new Error('ERR_PASSWORD_NOT_SET')
      }
      if (!await bcrypt.compare(info.password, user.password)) {
        throw new Error('ERR_PASSWORD_INVALID')
      }
    }

    const userId = user.id

    if (info.password) delete info.password
    const metadata = { ...info, ...user }
    const ips = extractIps(req)

    const roles = []
    if (metadata.roles?.length) {
      roles.push(...JSON.parse(metadata.roles))
    }

    const token = await this.genToken({ ips, userId, ttl: this.conf.ttl, metadata, roles })
    return token
  }

  async getUserById (id) {
    if (!id) {
      return
    }

    return await this._sqlite.getAsync(
      'SELECT id, email, roles FROM users WHERE id = ? LIMIT 1', id
    )
  }

  async getUserByEmail (email) {
    if (!email) {
      return
    }

    return await this._sqlite.getAsync(
      'SELECT id, email, roles FROM users WHERE email = ? LIMIT 1', email
    )
  }

  async listUsers () {
    return await this._sqlite.allAsync('SELECT id, email, roles FROM users')
  }

  async deleteUser (id) {
    if (!id) {
      return false
    }

    if (id.toString() === '1') {
      throw new Error('ERR_NOT_ALLOWED')
    }

    await this._sqlite.runAsync(
      'DELETE from users WHERE id=?', [id]
    )

    await this._deleteTokensOfUser(id)

    return true
  }

  async _deleteTokensOfUser (id) {
    const tokens = await this._sqlite.allAsync(
      'SELECT * from auth_tokens WHERE userId=?', [id]
    )

    tokens.forEach(({ token }) => this._lru.remove(`gotokens:${token}`))

    await this._sqlite.allAsync(
      'DELETE from auth_tokens WHERE userId=?', [id]
    )
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
