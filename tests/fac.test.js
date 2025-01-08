'use strict'

const test = require('brittle')
const { promiseSleep } = require('@bitfinex/lib-js-util-promise')
const { omit } = require('@bitfinexcom/lib-js-util-base')

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
    password: null,
    name: 'Super Admin',
    picture: null
  }, 'superAdmin created')
})

test('createUser', async (t) => {
  // Create a user with correct email, roles, name, and profile picture
  await authFac.createUser({
    email: 'test1@localhost',
    roles: ['user'],
    name: 'Test User',
    picture: 'https://example.com/profile.jpg'
  })

  const user = await authFac._sqlite.getAsync(
    'SELECT * FROM users WHERE email = ?', 'test1@localhost'
  )

  t.alike(user, {
    id: 2,
    email: 'test1@localhost',
    roles: JSON.stringify(['user']),
    password: null,
    name: 'Test User',
    picture: 'https://example.com/profile.jpg'
  }, 'valid user created')

  // Create a user with missing email
  await t.exception(
    async () => await authFac.createUser({ roles: ['user'], name: 'Test User' }),
    /ERR_MISSING_EMAIL/,
    'throw error on missing email'
  )

  // Create a user with missing roles
  await t.exception(
    async () => await authFac.createUser({ email: 'test2@localhost', name: 'Test User' }),
    /ERR_MISSING_ROLES/,
    'throw error on missing roles'
  )

  // Create a user with missing name
  await t.exception(
    async () => await authFac.createUser({ email: 'test3@localhost', roles: ['user'] }),
    /ERR_MISSING_NAME/,
    'throw error on missing name'
  )

  // Create a user with existing email
  await t.exception(
    async () => await authFac.createUser({ email: 'test1@localhost', roles: ['user'], name: 'Test User' }),
    /ERR_USER_EXISTS/,
    'throw error on existing email'
  )
})

test('createToken', async (t) => {
  // create a token with correct email and password
  const token = await authFac.genToken({
    ips: ['127.0.0.1'],
    userId: 2,
    roles: ['user']
  })

  // Token should be like 'pub:api:60f410c1-ea10-4ec8-95e0-bf06be87858d-2-roles:user'
  // match all except uuid with regex
  t.is(token.match(/pub:api:[a-z0-9-]*-2-roles:user/)[0], token, 'valid token created')
})

test('regenerateToken', async (t) => {
  // create a token with correct email and password
  const oldToken = await authFac.genToken({
    ips: ['127.0.0.1'],
    userId: 2,
    roles: ['user']
  })

  // regenerate token with correct old token
  const newToken = await authFac.regenerateToken({ oldToken, roles: ['user'] })

  // Token should be like 'pub:api:60f410c1-ea10-4ec8-95e0-bf06be87858d-2-roles:user'
  // match all except uuid with regex
  t.is(newToken.match(/pub:api:[a-z0-9-]*-2-roles:user/)[0], newToken, 'valid token regenerated')

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
  // Create a token with correct email and password
  const token = await authFac.genToken({
    ips: ['127.0.0.1'],
    userId: 2,
    roles: ['user']
  })

  // Test ERR_NO_UPDATE_FIELDS: Attempt to update with no fields provided
  await t.exception(
    async () => await authFac.updateUser({ token }),
    /ERR_NO_UPDATE_FIELDS/,
    'throws error when no fields are provided'
  )

  // Test ERR_INVALID_ROLES: Attempt to update with invalid roles
  await t.exception(
    async () => {
      await authFac.updateUser({
        token,
        roles: ['invalid-role']
      })
    },
    /ERR_INVALID_ROLES/,
    'throws error for invalid role values'
  )

  // Update user with new email, password, name, and profile picture
  // NOTE: password is hashed before storing
  await authFac.updateUser({
    token,
    email: 'test3@localhost',
    roles: ['user'],
    password: 'newpassword',
    name: 'Updated User', // Update name
    picture: 'https://example.com/updated-profile.jpg' // Update profile picture
  })

  const user = await authFac._sqlite.getAsync(
    'SELECT * FROM users WHERE email = ?', 'test3@localhost'
  )

  t.alike(omit(user, ['password']), {
    id: 2,
    email: 'test3@localhost',
    roles: JSON.stringify(['user']),
    name: 'Updated User', // Validate updated name
    picture: 'https://example.com/updated-profile.jpg' // Validate updated profile picture
  }, 'user updated correctly')
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
    /ERR_AUTH_FAIL/,
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
    /ERR_AUTH_FAIL/,
    'throw error on incorrect email and password'
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
