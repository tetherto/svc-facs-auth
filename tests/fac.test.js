'use strict'

const test = require('brittle')
const { promiseSleep } = require('@bitfinex/lib-js-util-promise')
const { omit } = require('@bitfinexcom/lib-js-util-base')
const async = require('async')
const jwt = require('jsonwebtoken')

const Fac = require('..')
const caller = { ctx: { root: __dirname } }

const sqliteFac = require('./helper/sqlite.fac')()
const lruFac = require('./helper/lru.fac')()

const authFac = new Fac(caller, {
  sqlite: sqliteFac,
  ns: 'a0',
  lru: lruFac
}, { env: 'test' })

const verify = (token) => jwt.verify(token, authFac.conf.jwtSecret, { algorithms: ['HS256'] })

test('init', async (t) => {
  // init the database
  await new Promise((resolve, _reject) => authFac.start(resolve))

  // check if users table is created
  const usersTable = await authFac._sqlite.getAsync(
    'SELECT name FROM sqlite_master WHERE type="table" AND name="users"'
  )
  t.ok(usersTable, 'users table created')

  // check if superadmin is created
  const superAdmin = await authFac._sqlite.getAsync(
    'SELECT * FROM users WHERE email = ?', 'superadmin@localhost'
  )
  t.alike(superAdmin, {
    id: 1,
    email: 'superadmin@localhost',
    roles: JSON.stringify(['*']),
    password: null,
    name: null,
    lastActiveAt: null
  }, 'superAdmin created')
})

test('createUser', async (t) => {
  // create a user with correct email, roles as array of strings
  await authFac.createUser({ email: 'test1@localhost', name: 'Test User 1', roles: ['user'] })

  const user = await authFac._sqlite.getAsync(
    'SELECT * FROM users WHERE email = ?', 'test1@localhost'
  )

  t.alike(user, {
    id: 2,
    email: 'test1@localhost',
    roles: JSON.stringify(['user']),
    password: null,
    name: 'Test User 1',
    lastActiveAt: null
  }, 'valid user created')

  // create a user with missing email
  await t.exception(
    async () => await authFac.createUser({ roles: ['user'] }),
    /ERR_MISSING_EMAIL/,
    'throw error on missing email'
  )

  // create a user with missing roles
  await t.exception(
    async () => await authFac.createUser({ email: 'test2@localhost' }),
    /ERR_MISSING_ROLES/,
    'throw error on missing roles'
  )

  // create a user with existing email
  await t.exception(
    async () => await authFac.createUser({ email: 'test1@localhost', roles: ['user'] }),
    /ERR_USER_EXISTS/,
    'throw error on existing email'
  )
})

test('createToken', async (t) => {
  const token = await authFac.genToken({
    ips: ['127.0.0.1'],
    userId: 2,
    roles: ['normal_user']
  })

  const decoded = verify(token)
  t.is(decoded.sub, 2, 'sub claim is userId')
  t.alike(decoded.roles, ['normal_user'], 'roles claim matches')
  t.alike(decoded.ips, ['127.0.0.1'], 'ips claim matches')
  t.is(decoded.pfx, 'pub', 'pfx claim is pub')
  t.is(decoded.scope, 'api', 'scope claim is api')
  t.ok(decoded.jti, 'jti claim is present')
  t.ok(decoded.iat, 'iat claim is present')
  t.ok(decoded.exp, 'exp claim is present')
})

test('regenerateToken', async (t) => {
  const oldToken = await authFac.genToken({
    ips: ['127.0.0.1'],
    userId: 2,
    roles: ['user', 'site_manager']
  })

  const newToken = await authFac.regenerateToken({ oldToken, roles: ['user', 'site_manager'] })

  const newDecoded = verify(newToken)
  t.is(newDecoded.sub, 2, 'new token sub is userId')
  t.alike(newDecoded.roles, ['user', 'site_manager'], 'new token roles match')
  t.not(newDecoded.jti, verify(oldToken).jti, 'new token has a fresh jti')

  await t.exception(
    async () => await authFac.regenerateToken({ oldToken: 'incorrect' }),
    /ERR_OLD_TOKEN_INVALID/,
    'throw error on incorrect old token'
  )

  await t.exception(
    async () => await authFac.regenerateToken({ oldToken, roles: ['admin'] }),
    /ERR_ROLES_INVALID/,
    'throw error on incorrect roles'
  )

  const oldSuperAdminToken = await authFac.genToken({
    ips: ['127.0.0.1'],
    userId: 2,
    roles: ['*']
  })

  await t.execution(
    async () => await authFac.regenerateToken({ oldToken: oldSuperAdminToken, roles: ['*'] }),
    'valid super admin token regenerated'
  )
})

test('tokenPerms', async (t) => {
  // create a token with correct email and password
  const token = await authFac.genToken({
    ips: ['127.0.0.1'],
    userId: 2,
    roles: ['user']
  })

  // check if token has correct permissions
  t.is(await authFac.tokenHasPerms(token, 'jobs:r'), true, 'token has jobs:r')
  t.is(await authFac.tokenHasPerms(token, 'jobs:w'), true, 'token has jobs:w')
  t.not(await authFac.tokenHasPerms(token, 'miner:r'), true, 'token does not have miner:r')

  // check if superadmin token has all permissions
  const superAdminToken = await authFac.genToken({
    ips: ['127.0.0.1'],
    userId: 1,
    roles: ['*']
  })

  t.is(await authFac.tokenHasPerms(superAdminToken, 'jobs:r'), true, 'superadmin token has jobs:r')
  t.is(await authFac.tokenHasPerms(superAdminToken, 'jobs:xyz'), true, 'superadmin token has unknown permission')
})

test('updateUser', async (t) => {
  const userId = 2
  const mintedTokens = []
  const firstToken = await authFac.genToken({
    ips: ['127.0.0.1'],
    userId,
    roles: ['user']
  })
  mintedTokens.push(firstToken)

  await async.times(3, async () => {
    const tk = await authFac.genToken({
      ips: ['127.0.0.1'],
      userId,
      roles: ['user']
    })
    mintedTokens.push(tk)
  })

  await authFac.updateUser({ token: firstToken, email: 'test3@localhost', roles: ['user'], password: 'newpassword' })

  const user = await authFac._sqlite.getAsync(
    'SELECT * FROM users WHERE email = ?', 'test3@localhost'
  )

  t.alike(omit(user, ['password', 'name', 'lastActiveAt']), {
    id: 2,
    email: 'test3@localhost',
    roles: JSON.stringify(['user'])
  }, 'user updated correctly')

  for (const tk of mintedTokens) {
    const resolved = await authFac.resolveToken(tk, ['127.0.0.1'])
    t.is(resolved, null, 'cannot resolve old token after user update')
  }
})

test('compareUser', async (t) => {
  // Create a user with email, roles, and password
  const password = 'securepassword'
  await authFac.createUser({ email: 'compare@localhost', name: 'Test User', roles: ['user'], password })

  // Fetch the user from the database
  const user = await authFac._sqlite.getAsync(
    'SELECT * FROM users WHERE email = ?', 'compare@localhost'
  )

  // Generate an authentication token for the user
  const token = await authFac.genToken({
    ips: ['127.0.0.1'],
    userId: user.id,
    roles: ['user']
  })

  // Test with correct email
  t.is(
    await authFac.compareUser({ token, email: 'compare@localhost' }),
    true,
    'compareUser should return true for matching email'
  )

  // Test with incorrect email
  t.is(
    await authFac.compareUser({ token, email: 'wrong@localhost' }),
    false,
    'compareUser should return false for incorrect email'
  )

  // Test with correct name
  t.is(
    await authFac.compareUser({ token, name: 'Test User' }),
    true,
    'compareUser should return true for matching name'
  )

  // Test with incorrect name
  t.is(
    await authFac.compareUser({ token, name: 'Wrong User' }),
    false,
    'compareUser should return false for incorrect name'
  )

  // Test with correct roles
  t.is(
    await authFac.compareUser({ token, roles: ['user'] }),
    true,
    'compareUser should return true for matching roles'
  )

  // Test with incorrect roles
  t.is(
    await authFac.compareUser({ token, roles: ['admin'] }),
    false,
    'compareUser should return false for incorrect roles'
  )

  // Test with correct password
  t.is(
    await authFac.compareUser({ token, password }),
    true,
    'compareUser should return true for matching password'
  )

  // Test with incorrect password
  t.is(
    await authFac.compareUser({ token, password: 'wrongpassword' }),
    false,
    'compareUser should return false for incorrect password'
  )

  // Test with multiple correct fields (email, password, roles)
  t.is(
    await authFac.compareUser({ token, email: 'compare@localhost', password, roles: ['user'] }),
    true,
    'compareUser should return true when all fields match'
  )

  // Test with one incorrect field
  t.is(
    await authFac.compareUser({ token, email: 'compare@localhost', password, roles: ['admin'] }),
    false,
    'compareUser should return false if one field does not match'
  )

  // Test with missing fields (should throw error)
  await t.exception(
    async () => await authFac.compareUser({ token }),
    /ERR_NO_FIELDS_PROVIDED/,
    'compareUser should throw error if no fields are provided'
  )
})

test('authHandlers', async (t) => {
  // add a simple auth handler
  authFac.addHandlers({
    password: (ctx, req) => {
      if (!req.email || !req.password) {
        throw new Error('ERR_MISSING_EMAIL_PASSWORD')
      }
      return req
    },
    nonPassword: (ctx, req) => {
      if (!req.email) {
        throw new Error('ERR_MISSING_EMAIL')
      }
      return req
    }
  })

  // create a token with correct email and password
  const token = await authFac.authCallbackHandler('password', { email: 'test3@localhost', password: 'newpassword', ip: '127.0.0.1' })
  const decoded = verify(token)
  t.is(decoded.sub, 2, 'password auth token has sub=2')
  t.alike(decoded.roles, ['user'], 'password auth token has user role')
  t.is(decoded.metadata.password, undefined, 'password is not leaked in token payload')

  // throw error in wrong password
  await t.exception(
    async () => await authFac.authCallbackHandler('password', { email: 'test3@localhost', password: 'incorrect', ip: '127.0.0.1' }),
    /ERR_PASSWORD_INVALID/,
    'throw error on incorrect password'
  )

  // create a valid token with non-password auth handler
  const token2 = await authFac.authCallbackHandler('nonPassword', { email: 'test3@localhost', ip: '127.0.0.1' })
  const decoded2 = verify(token2)
  t.is(decoded2.sub, 2, 'nonPassword auth token has sub=2')
  t.alike(decoded2.roles, ['user'], 'nonPassword auth token has user role')

  // create a token with incorrect email and password
  await t.exception(
    async () => await authFac.authCallbackHandler('password', { email: 'test100@localhost', password: 'incorrect', ip: '127.0.0.1' }),
    /ERR_USER_INVALID/,
    'throw error on incorrect email and password'
  )
})

test('mfaHandler', async t => {
  authFac.addMfaHandlers({
    totp: async (ctx, req) => ({ ok: true, ctx, req })
  })

  const result = await authFac.mfaHandler('totp', { foo: 1 })
  t.is(result.ok, true)
  t.ok(result.ctx)
  t.alike(result.req, { foo: 1 })
  await t.exception(
    async () => await authFac.mfaHandler('notfound', {}),
    /ERR_HANDLER_INVALID/
  )
})

test('mfaCallbackHandler', async t => {
  // No MFA required
  authFac.authCallbackHandler = async () => 'token123'
  const getUserMfaMethodsNone = async () => []
  const resultNone = await authFac.mfaCallbackHandler('any', {}, getUserMfaMethodsNone)
  t.alike(resultNone, { token: 'token123' })

  // MFA required
  authFac.authCallbackHandler = async () => 'token456'
  const getUserMfaMethodsSome = async () => ['totp', 'passkey']
  const resultSome = await authFac.mfaCallbackHandler('any', {}, getUserMfaMethodsSome)
  t.ok(resultSome.csrf_token)
  t.is(resultSome.mfa_required, true)
  t.alike(resultSome.mfa_methods, ['totp', 'passkey'])
  t.is(authFac._lru.get(resultSome.csrf_token), 'token456')

  // Invalid getUserMfaMethods
  authFac.authCallbackHandler = async () => 'token789'
  await t.exception(
    async () => await authFac.mfaCallbackHandler('any', {}, null),
    /ERR_MFA_METHOD_HANDLER_INVALID/
  )
  await t.exception(
    async () => await authFac.mfaCallbackHandler('any', {}, 123),
    /ERR_MFA_METHOD_HANDLER_INVALID/
  )
})

test('cleanupTokens', async (t) => {
  const shortToken = await authFac.genToken({
    ips: ['127.0.0.1'],
    userId: 2,
    roles: ['user'],
    ttl: 5
  })
  const longToken = await authFac.genToken({
    ips: ['127.0.0.1'],
    userId: 2,
    roles: ['user'],
    ttl: 3000
  })

  const shortJti = verify(shortToken).jti
  const longJti = verify(longToken).jti

  t.ok(authFac._userJtis.get(2)?.has(shortJti), 'short jti tracked')
  t.ok(authFac._userJtis.get(2)?.has(longJti), 'long jti tracked')

  await promiseSleep(6000)
  await authFac.cleanupTokens()

  t.absent(authFac._userJtis.get(2)?.has(shortJti), 'short jti swept after expiry')
  t.ok(authFac._userJtis.get(2)?.has(longJti), 'long jti still tracked')
})

test('getUser', async (t) => {
  await authFac.createUser({ email: 'test6@localhost', roles: ['user'] })
  const user = await authFac._sqlite.getAsync(
    'SELECT * FROM users WHERE email = ?', 'test6@localhost'
  )
  const expected = {
    id: user.id,
    email: user.email,
    name: user.name,
    roles: user.roles,
    lastActiveAt: user.lastActiveAt
  }

  let res = await authFac.getUserById(user.id)
  t.alike(res, expected, 'user fetched by id')
  t.is(res.password, undefined, 'password is not returned')

  res = await authFac.getUserByEmail(user.email)
  t.alike(res, expected, 'user fetched by email')
  t.is(res.password, undefined, 'password is not returned')
})

test('listUsers', async (t) => {
  await authFac.createUser({ email: 'test4@localhost', roles: ['user'] })

  const users = await authFac.listUsers()

  t.is(Array.isArray(users), true, 'list of users returned')
  t.is(users.every(user => user.id !== undefined && user.email !== undefined && user.roles !== undefined), true, 'user has details')
  t.is(users.every(user => user.password === undefined), true, 'password is not returned')
})

test('deleteUser', async (t) => {
  await authFac.createUser({ email: 'test5@localhost', roles: ['user'] })

  const user = await authFac._sqlite.getAsync(
    'SELECT * FROM users WHERE email = ?', 'test5@localhost'
  )

  const mintedTokens = []
  await async.times(3, async () => {
    const tk = await authFac.genToken({
      ips: ['127.0.0.1'],
      userId: user.id,
      roles: ['normal_user']
    })
    mintedTokens.push(tk)
  })

  await t.execution(async () => await authFac.deleteUser(user.id), 'delete user is successful')

  const userToCheck = await authFac._sqlite.getAsync(
    'SELECT * FROM users WHERE email = ?', 'test5@localhost'
  )

  t.is(userToCheck, undefined, 'user is deleted')
  await t.exception(async () => await authFac.deleteUser(1), 'super user can not be deleted')

  for (const tk of mintedTokens) {
    const resolved = await authFac.resolveToken(tk, ['127.0.0.1'])
    t.is(resolved, null, 'cannot resolve old token after user delete')
  }
})

test('updateLastActive', async (t) => {
  await authFac.createUser({ email: 'test@localhost', roles: ['user'] })
  const user = await authFac._sqlite.getAsync(
    'SELECT * FROM users WHERE email = ?', 'test@localhost'
  )

  const userBefore = await authFac.getUserById(user.id)
  t.is(userBefore.lastActiveAt, null, 'lastActiveAt is initially null')

  await authFac.updateLastActive(user.id)

  const userAfter = await authFac.getUserById(user.id)
  t.ok(userAfter.lastActiveAt, 'lastActiveAt is set after update')
  t.is(typeof userAfter.lastActiveAt, 'number', 'lastActiveAt is a number')
})

test('jwt tampering rejected', async (t) => {
  const token = await authFac.genToken({
    ips: ['127.0.0.1'],
    userId: 2,
    roles: ['user']
  })

  const [header, payload, signature] = token.split('.')

  const tamperedPayload = payload.slice(0, -1) + (payload.slice(-1) === 'A' ? 'B' : 'A')
  const tamperedToken = `${header}.${tamperedPayload}.${signature}`

  const resolved = await authFac.resolveToken(tamperedToken, ['127.0.0.1'])
  t.is(resolved, null, 'tampered token is rejected')

  const tamperedSigToken = `${header}.${payload}.${signature.slice(0, -1)}X`
  const resolvedSig = await authFac.resolveToken(tamperedSigToken, ['127.0.0.1'])
  t.is(resolvedSig, null, 'tampered signature is rejected')
})

test('jwtSecret missing throws', async (t) => {
  const original = authFac.conf.jwtSecret
  authFac.conf.jwtSecret = null

  await t.exception(
    async () => await authFac.genToken({
      ips: ['127.0.0.1'],
      userId: 2,
      roles: ['user']
    }),
    /ERR_JWT_SECRET_MISSING/,
    'throws when jwtSecret is missing'
  )

  authFac.conf.jwtSecret = original
})

test('_assertTtlCoveredByLru rejects ttl > lru.maxAge', (t) => {
  // simulate a real LRU by attaching a cache with maxAge (test helper has none)
  const originalLru = authFac._lru
  const originalTtl = authFac.conf.ttl

  authFac._lru = { cache: { maxAge: 60_000 } } // 60 s
  authFac.conf.ttl = 120 // 120 s — exceeds

  t.exception(
    () => authFac._assertTtlCoveredByLru(),
    /ERR_TTL_EXCEEDS_LRU_MAXAGE/,
    'throws when conf.ttl exceeds lru.maxAge'
  )

  authFac.conf.ttl = 60 // exactly equal is allowed
  t.execution(() => authFac._assertTtlCoveredByLru(), 'boundary ttl === maxAge is accepted')

  authFac._lru = originalLru
  authFac.conf.ttl = originalTtl
})
