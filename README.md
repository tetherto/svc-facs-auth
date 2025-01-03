# svc-facs-auth
 
This is a facility to handle user authentivcaton that extends from `bfx-facs-base` to provide authentication management with support for generating and validating tokens, managing users, and handling permissions. It uses SQLite for storing user and token information and LRU for caching.

## Configuration

This facility requires a config file in the following structure:

```javascript
{
  "a0": {
    "superAdmin": {
      "name": "Super Admin",
      "email": "superadmin@localhost"
    },
    "ttl": 5000, // Default token time-to-live in seconds
    "saltRounds": 10, // Number of salt rounds for password hashing
    "roles": { // Roles with associated permissions
      "admin": [
        "miner:rw",
        "container:rw",
        "user:rw"
      ],
      "site_manager": [
        "miner:rw",
        "container:rw",
        "user:r"
      ],
      "user": ["jobs:rw"]
    }
  }
}
```

## Documentation
### `auth.createUser(req)`
Creates a new user with specified roles, permissions, name, and optional profile picture.

**Parameters:**
- `req<object>`: Object with user creation details.
  - `email<string>`: Email address of the user.
  - `roles<string[]>`: Array of roles for the user.
  - `password<string>`: Password for the user.
  - `name<string>`: Full name of the user.
  - `picture<string>`: URL for the user's profile picture.

```javascript
const result = await auth.createUser({
  email: 'user@example.com',
  roles: ['admin'],
  password: 'securepassword',
  name: 'Example User',
  picture: 'https://example.com/profile.jpg'
});
```

### `auth.updateUser(req)`
Updates an existing user with new details such as roles, permissions, name, and profile picture.

**Parameters:**
- `req<object>`: Object with user update details.
    - `token<string>`: Authentication token for the user.
    - `email<string>`: New email address of the user.
    - `roles<string[]>`: Array of roles for the user.
    - `password<string>`: New password for the user.
    - `name<string>`: New name of the user.
    - `picture<string>`: URL for the new profile picture.

**Example Usage:**
```javascript
const result = await auth.updateUser({
  token: 'some-token',
  email: 'new@example.com',
  roles: ['admin'],
  name: 'New Name',
  picture: 'https://example.com/new-picture.jpg'
});
```

### `auth.genToken(req)`
Generates a new authentication token based on the provided parameters. It validates the input, allocates resources, and stores the token data.

**Parameters:**
- `req<object>`: Object containing token generation details.
    - `ips<string[]>`: List of IP addresses associated with the token.
    - `userId<number>`: User ID for whom the token is generated.
    - `ttl<number>`: Time-to-live for the token in seconds (default: 300).
    - `metadata<object>`: Optional metadata associated with the token.
    - `pfx<string>`: Prefix for the token (default: 'pub').
    - `scope<string>`: Scope for the token (default: 'api').
    - `roles<string[]>`: Array of roles for the token.

```javascript
const token = await auth.genToken({
  ips: ['192.168.1.1'],
  userId: 1,
  ttl: 3600,
  metadata: { key: 'value' },
  pfx: 'pub',
  scope: 'api',
  roles: ['admin']
})
```

### `auth.regenerateToken(req)`
Regenerates an existing authentication token. It validates the old token, checks permissions, and creates a new token.

**Parameters:**
- `req<object>`: Object with token regeneration details.
    - `oldToken<string>`: Existing token to be regenerated.
    - `ips<string[]>`: New IP addresses associated with the token (optional).
    - `ttl<number>`: Time-to-live for the new token in seconds (default: 300).
    - `pfx<string>`: Prefix for the new token (default: 'pub').
    - `scope<string>`: Scope for the new token (default: 'api').
    - `roles<string[]>`: Array of roles for the new token.

```javascript
const newToken = await auth.regenerateToken({
  oldToken: 'existing-token',
  ips: ['192.168.1.1'],
  ttl: 3600,
  pfx: 'pub',
  scope: 'api',
  roles: ['admin']
})
```

### `auth.getTokenPerms(token)`
Retrieves permissions associated with a token.

**Parameters:**
- `token<string>`: The token to get permissions for.

**Returns:**
- `{ superadmin: <boolean>, perms: <string[]> }` with token permissions.

```javascript
const perms = auth.getTokenPerms('some-token')
console.log('Token permissions:', perms)
```

### `auth.resolveToken(token, ips)`
Validates a token and checks if it is associated with the given IP addresses.

**Parameters:**
- `token<string>`: The token to resolve.
- `ips<string[]>`: List of IP addresses to validate.

```javascript
const token = await auth.resolveToken('some-token', ['192.168.1.1'])
```

### `auth.tokenHasPerms(token, perm)`
Checks if a token has the required permissions.

**Parameters:**
- `token<string>`: The token to check.
- `perm<string>`: Permission to check.

**Returns:**
- `true` if the token has the required permissions.
- `false` otherwise.

```javascript
const hasPerms = auth.tokenHasPerms('some-token', 'miner:r')
console.log('Token has required permissions:', hasPerms)
```

### `auth.cleanupTokens()`
Cleans up expired tokens from the database.

```javascript
await auth.cleanupTokens()
```

### `auth.addHandlers(handlers)`
Adds authentication handlers to the service.

**Parameters:**
- `handlers<object>`: Object containing authentication handlers, each key is a handler name and value is a handler function.

```javascript
auth.addHandlers({
  'handler-name': async (ctx, req) => {
    // Handler logic
  }
})
```

### `auth.authCallbackHandler(type, req)`
Handles authentication callbacks by resolving tokens and returning authentication results.

**Parameters:**
- `type<string>`: Type of authentication callback.
- `req<object>`: Request object containing callback details.

```javascript
const token = await auth.authCallbackHandler('callback-type', request)
```
