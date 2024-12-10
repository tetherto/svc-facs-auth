# svc-facs-auth
 
This is a facility to handel user authentivcaton that extends from `bfx-facs-base` to provide authentication management with support for generating and validating tokens, managing users, and handling permissions. It uses SQLite for storing user and token information and integrates with external HTTP services.

## Introduction

### Configuration

This facility requires configuration files. The configuration file should look like this:
We need to add this configuration file as `config/facs/auth.config.json`:

```json
{
  "a0": {
    "auth_caps": {
      "m": "miner",
      "c": "container"
    },
    "ttl": 5000
  }
}
```

This facility also requires that `lru`, `sqlite`, `httpc` and `httpd` be passed in `opts`.

## Documentation


### Initialization

The facility is initialized in the worker's facilities array (e.g. in cosmicac-app-node) as such:

```javascript
['fac', 'svc-facs-auth', 'a0', 'a0', () => ({
    lru: this.lru_15m,
    sqlite: this.dbSqlite_auth,
    httpc: this.http_c0,
    httpd: this.httpd_h0
}), 10]
```

### User Auth Operations

#### `auth.createUser(req)`
Creates a new user with specified capabilities and permissions.

**Parameters:**
- `req<object>`: Object with user creation details.
    - `email<string>`: Email address of the user.
    - `caps<string[]>`: Array of capabilities for the user.
    - `write<boolean>`: Write permission flag for the user (default: false).

**Returns:**
- `{ success: true }` if the user is created successfully.
- `{ success: false, message: <error message> }` if an error occurs.

```javascript
const result = await auth.createUser({
  email: 'user@example.com',
  caps: ['read'],
  write: true
});
if (result.success) {
  console.log('User created successfully');
} else {
  console.error('Failed to create user:', result.message);
}
```

#### `auth.genToken(req)`
Generates a new authentication token based on the provided parameters. It validates the input, allocates resources, and stores the token data.

**Parameters:**
- `req<object>`: Object containing token generation details.
    - `ips<string[]>`: List of IP addresses associated with the token.
    - `userId<number>`: User ID for whom the token is generated.
    - `ttl<number>`: Time-to-live for the token in seconds (default: 300).
    - `metadata<object>`: Optional metadata associated with the token.
    - `pfx<string>`: Prefix for the token (default: 'pub').
    - `scope<string>`: Scope for the token (default: 'api').
    - `caps<string[]>`: Array of capabilities for the token.
    - `write<boolean>`: Write permission flag for the token (default: false).

**Returns:**
- `{ success: true, token: <token> }` if the token is generated successfully.
- `{ success: false, message: <error message> }` if an error occurs.

```javascript
const token = await auth.genToken({
  ips: ['192.168.1.1'],
  userId: 1,
  ttl: 3600,
  metadata: { key: 'value' },
  pfx: 'pub',
  scope: 'api',
  caps: ['read'],
  write: false
});
if (token.success) {
  console.log('Token created successfully:', token.token);
} else {
  console.error('Failed to create token:', token.message);
}
```

#### `auth.regenerateToken(req)`
Regenerates an existing authentication token. It validates the old token, checks permissions, and creates a new token.

**Parameters:**
- `req<object>`: Object with token regeneration details.
    - `oldToken<string>`: Existing token to be regenerated.
    - `ips<string[]>`: New IP addresses associated with the token (optional).
    - `ttl<number>`: Time-to-live for the new token in seconds (default: 300).
    - `pfx<string>`: Prefix for the new token (default: 'pub').
    - `scope<string>`: Scope for the new token (default: 'api').
    - `caps<string[]>`: Array of capabilities for the new token.
    - `write<boolean>`: Write permission flag for the new token (default: false).

**Returns:**
- `{ success: true, token: <new token> }` if the token is regenerated successfully.
- `{ success: false, message: <error message> }` if an error occurs.

```javascript
const newToken = await auth.regenerateToken({
  oldToken: 'existing-token',
  ips: ['192.168.1.1'],
  ttl: 3600,
  pfx: 'pub',
  scope: 'api',
  caps: ['read'],
  write: false
});
if (newToken.success) {
  console.log('Token regenerated successfully:', newToken.token);
} else {
  console.error('Failed to regenerate token:', newToken.message);
}
```



#### `auth.getTokenPerms(token, inverse)`
Retrieves permissions associated with a token.

**Parameters:**
- `token<string>`: The token to get permissions for.
- `inverse<boolean>`: Flag to invert permissions (optional).

**Returns:**
- `{ write: <boolean>, caps: <string[]> }` with token permissions.

```javascript
const perms = auth.getTokenPerms('some-token');
console.log('Token permissions:', perms);
```

#### `auth.resolveToken(token, ips)`
Validates a token and checks if it is associated with the given IP addresses.

**Parameters:**
- `token<string>`: The token to resolve.
- `ips<string[]>`: List of IP addresses to validate.

**Returns:**
- `{ success: true, data: <token data> }` if the token is valid.
- `{ success: false, message: <error message> }` if the token is invalid or expired.

```javascript
const result = await auth.resolveToken('some-token', ['192.168.1.1']);
if (result.success) {
  console.log('Token resolved:', result.data);
} else {
  console.error('Failed to resolve token:', result.message);
}
```

#### `auth.tokenHasPerms(token, write, caps, matchAll)`
Checks if a token has the required permissions.

**Parameters:**
- `token<string>`: The token to check.
- `write<boolean>`: Flag to check for write permission.
- `caps<string[]>`: Array of required capabilities.
- `matchAll<boolean>`: Flag to match all capabilities (optional).

**Returns:**
- `true` if the token has the required permissions.
- `false` otherwise.

```javascript
const hasPerms = auth.tokenHasPerms('some-token', true, ['read'], false);
console.log('Token has required permissions:', hasPerms);
```

#### `auth.cleanupTokens()`
Cleans up expired tokens from the database.

**Returns:**
- `{ success: true }` if the cleanup is successful.
- `{ success: false, message: <error message> }` if an error occurs.

```javascript
const result = await auth.cleanupTokens();
if (result.success) {
  console.log('Tokens cleaned up successfully');
} else {
  console.error('Failed to clean up tokens:', result.message);
}
```

#### `auth.authCallbackHandler(type, req)`
Handles authentication callbacks by resolving tokens and returning authentication results.

**Parameters:**
- `type<string>`: Type of authentication callback.
- `req<object>`: Request object containing callback details.

**Returns:**
- `{ success: true, token: <token> }` if authentication is successful.
- `{ success: false, message: <error message> }` if authentication fails.

```javascript
const token = await auth.authCallbackHandler('callback-type', request);
if (token.success) {
  console.log('Authentication successful:', token.token);
} else {
  console.error('Authentication failed:', token.message);
}
```
