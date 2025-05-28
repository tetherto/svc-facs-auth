'use strict'

const test = require('brittle')
const { promiseSleep } = require('@bitfinex/lib-js-util-promise')
const { omit } = require('@bitfinexcom/lib-js-util-base')
const async = require('async')

const Fac = require('..')
const caller = { ctx: { root: __dirname } }

const sqliteFac = require('./helper/sqlite.fac')()
const lruFac = require('./helper/lru.fac')()

const authFac = new Fac(caller, {
  sqlite: sqliteFac,
  ns: 'a0',
  lru: lruFac
}, { env: 'test' })

test('init', async (t) => {
  // init the database
  await new Promise((resolve, _reject) => authFac.start(resolve))

  // check if users table is created
  const usersTable = await authFac._sqlite.getAsync(
    'SELECT name FROM sqlite_master WHERE type="table" AND name="users"'
  )
  t.ok(usersTable, 'users table created')

  // check if auth_tokens table is created
  const authTokensTable = await authFac._sqlite.getAsync(
    'SELECT name FROM sqlite_master WHERE type="table" AND name="auth_tokens"'
  )
  t.ok(authTokensTable, 'auth_tokens table created')

  // check if superadmin is created
  const superAdmin = await authFac._sqlite.getAsync(
    'SELECT * FROM users WHERE email = ?', 'superadmin@localhost'
  )
  t.alike(superAdmin, {
    id: 1,
    email: 'superadmin@localhost',
    roles: JSON.stringify(['*']),
    password: null
  }, 'superAdmin created')
})

test('createUser', async (t) => {
  // create a user with correct email, roles as array of strings
  await authFac.createUser({ email: 'test1@localhost', roles: ['user'] })

  const user = await authFac._sqlite.getAsync(
    'SELECT * FROM users WHERE email = ?', 'test1@localhost'
  )

  t.alike(user, {
    id: 2,
    email: 'test1@localhost',
    roles: JSON.stringify(['user']),
    password: null
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
  // create a token with correct email and password
  const token = await authFac.genToken({
    ips: ['127.0.0.1'],
    userId: 2,
    roles: ['normal_user']
  })

  // Token should be like 'pub:api:60f410c1-ea10-4ec8-95e0-bf06be87858d-2-roles:normal_user'
  // match all except uuid with regex
  t.is(token.match(/pub:api:[a-z0-9-]*-2-roles:normal_user/)[0], token, 'valid token created')
})

test('regenerateToken', async (t) => {
  // create a token with correct email and password
  const oldToken = await authFac.genToken({
    ips: ['127.0.0.1'],
    userId: 2,
    roles: ['user', 'site_manager']
  })

  // regenerate token with correct old token
  const newToken = await authFac.regenerateToken({ oldToken, roles: ['user', 'site_manager'] })

  // Token should be like 'pub:api:60f410c1-ea10-4ec8-95e0-bf06be87858d-2-roles:user'
  // match all except uuid with regex
  t.is(newToken.match(/pub:api:[a-z0-9-]*-2-roles:user:site_manager/)[0], newToken, 'valid token regenerated')

  // regenerate token with incorrect old token
  await t.exception(
    async () => await authFac.regenerateToken({ oldToken: 'incorrect' }),
    /ERR_OLD_TOKEN_INVALID/,
    'throw error on incorrect old token'
  )

  // regenerate token with incorrect roles
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

  // regenerate token with super admin role
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
  t.is(authFac.tokenHasPerms(token, 'jobs:r'), true, 'token has jobs:r')
  t.is(authFac.tokenHasPerms(token, 'jobs:w'), true, 'token has jobs:w')
  t.not(authFac.tokenHasPerms(token, 'miner:r'), true, 'token does not have miner:r')

  // check if superadmin token has all permissions
  const superAdminToken = await authFac.genToken({
    ips: ['127.0.0.1'],
    userId: 1,
    roles: ['*']
  })

  t.is(authFac.tokenHasPerms(superAdminToken, 'jobs:r'), true, 'superadmin token has jobs:r')
  t.is(authFac.tokenHasPerms(superAdminToken, 'jobs:xyz'), true, 'superadmin token has unknown permission')
})

test('updateUser', async (t) => {
  const userId = 2
  // create a token with correct email and password
  const token = await authFac.genToken({
    ips: ['127.0.0.1'],
    userId,
    roles: ['user']
  })

  await async.times(3, async () => (
    authFac.genToken({
      ips: ['127.0.0.1'],
      userId,
      roles: ['user']
    })
  ))

  const tokens = await authFac._sqlite.allAsync(
    'SELECT * FROM auth_tokens WHERE userId = ?', userId
  )

  // update user with new email and password
  // NOTE: password is hashed before storing
  await authFac.updateUser({ token, email: 'test3@localhost', roles: ['user'], password: 'newpassword' })

  const user = await authFac._sqlite.getAsync(
    'SELECT * FROM users WHERE email = ?', 'test3@localhost'
  )

  t.alike(omit(user, ['password']), {
    id: 2,
    email: 'test3@localhost',
    roles: JSON.stringify(['user'])
  }, 'user updated correctly')

  const dbTokensAfterUpdate = await authFac._sqlite.allAsync(
    'SELECT * FROM auth_tokens WHERE userId = ?', user.id
  )
  t.is(dbTokensAfterUpdate.length, 0, 'tokens of user deleted from db')

  const numCachedTokensAfterUpdate = tokens.map(token => authFac._lru.get(`gotokens:${token}`)).filter(token => !!token).length
  t.is(numCachedTokensAfterUpdate, 0, 'tokens of user deleted from cache')

  const resolvedToken = await authFac.resolveToken(tokens[0])
  t.is(resolvedToken, null, 'cannot resolve old token after user update')
})

test('compareUser', async (t) => {
  // Create a user with email, roles, and password
  const password = 'securepassword'
  await authFac.createUser({ email: 'compare@localhost', roles: ['user'], password })

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

  // Token should be like 'pub:api:60f410c1-ea10-4ec8-95e0-bf06be87858d-2-roles:user'
  // match all except uuid with regex
  t.is(token.match(/pub:api:[a-z0-9-]*-2-roles:user/)[0], token, 'valid token created with password auth handler')

  // throw error in wrong password
  await t.exception(
    async () => await authFac.authCallbackHandler('password', { email: 'test3@localhost', password: 'incorrect', ip: '127.0.0.1' }),
    /ERR_PASSWORD_INVALID/,
    'throw error on incorrect password'
  )

  // create a valid token with non-password auth handler
  const token2 = await authFac.authCallbackHandler('nonPassword', { email: 'test3@localhost', ip: '127.0.0.1' })

  // Token should be like 'pub:api:60f410c1-ea10-4ec8-95e0-bf06be87858d-2-roles:user'
  // match all except uuid with regex
  t.is(token2.match(/pub:api:[a-z0-9-]*-2-roles:user/)[0], token2, 'valid token created with non-password auth handler')

  // create a token with incorrect email and password
  await t.exception(
    async () => await authFac.authCallbackHandler('password', { email: 'test100@localhost', password: 'incorrect', ip: '127.0.0.1' }),
    / ERR_USER_INVALID/,
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
  // create a token with correct email and password
  const token = await authFac.genToken({
    ips: ['127.0.0.1'],
    userId: 2,
    roles: ['user'],
    ttl: 5
  })

  // check if token is created
  let authTokens = await authFac._sqlite.allAsync(
    'SELECT * FROM auth_tokens WHERE token = ?', token
  )

  t.is(authTokens.length, 1, 'token created')

  // wait 6s and cleanup tokens
  await promiseSleep(6000)
  await authFac.cleanupTokens()

  // check if token is deleted
  authTokens = await authFac._sqlite.allAsync(
    'SELECT * FROM auth_tokens WHERE token = ?', token
  )

  t.is(authTokens.length, 0, 'token deleted')
})

test('getUserIdFromToken', async (t) => {
  // Test valid token with roles
  const token1 = 'pub:api:60f410c1-ea10-4ec8-95e0-bf06be87858d-42-roles:user'
  const userId1 = authFac.getUserIdFromToken(token1)
  t.is(userId1, 42, 'correctly extracts userId from token with roles')
  
  // Test complex token with multiple hyphens
  const token3 = 'pub:api:60f410c1-ea10-4ec8-95e0-bf06be87858d-99-roles:admin:user:manager'
  const userId3 = authFac.getUserIdFromToken(token3)
  t.is(userId3, 99, 'correctly extracts userId from complex token')

  // Test invalid tokens
  t.is(authFac.getUserIdFromToken(null), null, 'returns null for null token')
  t.is(authFac.getUserIdFromToken(undefined), null, 'returns null for undefined token')
  t.is(authFac.getUserIdFromToken(123), null, 'returns null for non-string token')
  t.is(authFac.getUserIdFromToken('invalid-token'), null, 'returns null for invalid token format')
  t.is(authFac.getUserIdFromToken('pub:api:uuid-abc-roles:user'), null, 'returns null when userId is not a number')
  t.is(authFac.getUserIdFromToken('pub:api:uuid-0-roles:user'), null, 'returns null when userId is zero')
})

test('getUser', async (t) => {
  await authFac.createUser({ email: 'test6@localhost', roles: ['user'] })
  const user = await authFac._sqlite.getAsync(
    'SELECT * FROM users WHERE email = ?', 'test6@localhost'
  )
  const expected = {
    id: user.id,
    email: user.email,
    roles: user.roles
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

  await async.times(3, async () => authFac.genToken({
    ips: ['127.0.0.1'],
    userId: user.id,
    roles: ['normal_user']
  }))

  const tokens = await authFac._sqlite.allAsync(
    'SELECT * FROM auth_tokens WHERE userId = ?', user.id
  )

  await t.execution(async () => await authFac.deleteUser(user.id), 'delete user is successful')

  const userToCheck = await authFac._sqlite.getAsync(
    'SELECT * FROM users WHERE email = ?', 'test5@localhost'
  )

  t.is(userToCheck, undefined, 'user is deleted')
  await t.exception(async () => await authFac.deleteUser(1), 'super user can not be deleted')

  const dbTokensAfterDelete = await authFac._sqlite.allAsync(
    'SELECT * FROM auth_tokens WHERE userId = ?', user.id
  )
  t.is(dbTokensAfterDelete.length, 0, 'tokens of user deleted from db')

  const numCachedTokensAfterDelete = tokens.map(token => authFac._lru.get(`gotokens:${token}`)).filter(token => !!token).length
  t.is(numCachedTokensAfterDelete, 0, 'tokens of user deleted from cache')

  const resolvedToken = await authFac.resolveToken(tokens[0])
  t.is(resolvedToken, null, 'cannot resolve old token after user delete')
})
