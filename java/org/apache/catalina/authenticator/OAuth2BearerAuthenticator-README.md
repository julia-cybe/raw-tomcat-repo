# OAuth2 Bearer Token Authenticator for Apache Tomcat

## Overview

The `OAuth2BearerAuthenticator` is a Tomcat authenticator that validates OAuth2 Bearer tokens (JWT) from the `Authorization` header. It integrates seamlessly with Tomcat's existing Realm infrastructure and works in the valve pipeline alongside other authenticators like `FormAuthenticator` and `BasicAuthenticator`.

This authenticator operates at the Tomcat container level, not in application code, providing centralized authentication for all web applications deployed in the container.

## Features

- **JWT Token Validation**: Validates JWT tokens with HMAC-SHA256 (HS256) signature verification
- **Realm Integration**: Works with any Tomcat Realm (MemoryRealm, JNDIRealm, DataSourceRealm, etc.)
- **Token Expiration**: Validates token expiration (`exp` claim) with configurable clock skew tolerance
- **Issuer & Audience Validation**: Optional validation of `iss` (issuer) and `aud` (audience) claims
- **Token Refresh Support**: Can indicate token refresh endpoint when tokens expire
- **Session Caching**: Optional session-based caching of authenticated principals
- **RFC 6750 Compliant**: Follows OAuth 2.0 Bearer Token Usage specification
- **Error Responses**: Returns proper `WWW-Authenticate` challenge headers with error codes

## Configuration

### Basic Configuration

To enable OAuth2 Bearer authentication for a web application, configure it in the application's `context.xml` or `server.xml`:

```xml
<Context>
    <!-- Your existing Realm configuration -->
    <Realm className="org.apache.catalina.realm.MemoryRealm" />

    <!-- OAuth2 Bearer Authenticator -->
    <Valve className="org.apache.catalina.authenticator.OAuth2BearerAuthenticator"
           jwtSecret="your-secret-key-for-hmac-sha256-must-be-long-enough"
           jwtIssuer="https://your-auth-server.com"
           jwtAudience="your-application"
           allowTokenRefresh="true"
           tokenRefreshEndpoint="https://your-auth-server.com/token/refresh"
           clockSkewSeconds="60" />
</Context>
```

### Configuration Properties

| Property | Required | Default | Description |
|----------|----------|---------|-------------|
| `jwtSecret` | Yes | `null` | The secret key used to validate JWT signatures (HS256). **Important**: Keep this secure and make it sufficiently long (recommended: 256+ bits). |
| `jwtIssuer` | No | `null` | Expected issuer (`iss` claim) in the JWT. If set, tokens with different issuers will be rejected. |
| `jwtAudience` | No | `null` | Expected audience (`aud` claim) in the JWT. If set, tokens with different audiences will be rejected. |
| `allowTokenRefresh` | No | `false` | Whether to include the token refresh endpoint in error responses for expired tokens. |
| `tokenRefreshEndpoint` | No | `null` | The URL of the token refresh endpoint. Required if `allowTokenRefresh` is `true`. |
| `clockSkewSeconds` | No | `60` | Clock skew tolerance in seconds for token expiration validation. Allows for small time differences between servers. |

### Web Application Configuration

In your web application's `web.xml`, define security constraints and specify the BEARER authentication method:

```xml
<web-app>
    <!-- Security constraint for protected resources -->
    <security-constraint>
        <web-resource-collection>
            <web-resource-name>Protected API</web-resource-name>
            <url-pattern>/api/*</url-pattern>
            <http-method>GET</http-method>
            <http-method>POST</http-method>
            <http-method>PUT</http-method>
            <http-method>DELETE</http-method>
        </web-resource-collection>
        <auth-constraint>
            <role-name>user</role-name>
        </auth-constraint>
    </security-constraint>

    <!-- Login configuration using BEARER authentication -->
    <login-config>
        <auth-method>BEARER</auth-method>
        <realm-name>My Application API</realm-name>
    </login-config>

    <!-- Security roles -->
    <security-role>
        <role-name>user</role-name>
    </security-role>
    <security-role>
        <role-name>admin</role-name>
    </security-role>
</web-app>
```

## Usage

### Client Request Format

Clients must include a valid JWT token in the `Authorization` header using the Bearer scheme:

```http
GET /api/protected-resource HTTP/1.1
Host: example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VybmFtZSIsImlzcyI6Imh0dHBzOi8vYXV0aC5leGFtcGxlLmNvbSIsImF1ZCI6Im15LWFwcGxpY2F0aW9uIiwiZXhwIjoxNzE2MjM5MDIyfQ.signature
```

### JWT Token Format

The JWT token must contain the following claims:

**Required Claims:**
- `sub` (subject): The username/user identifier. This must match a user in the configured Realm.

**Optional Claims (validated if authenticator is configured with them):**
- `iss` (issuer): The token issuer (validated if `jwtIssuer` is configured)
- `aud` (audience): The intended audience (validated if `jwtAudience` is configured)
- `exp` (expiration): Unix timestamp when the token expires
- `nbf` (not before): Unix timestamp before which the token is not valid
- `iat` (issued at): Unix timestamp when the token was issued

**Example JWT Payload:**
```json
{
  "sub": "john.doe",
  "iss": "https://auth.example.com",
  "aud": "my-application",
  "exp": 1716239022,
  "nbf": 1716235422,
  "iat": 1716235422,
  "roles": ["user", "admin"]
}
```

**Note**: The `roles` claim in the JWT is not used by this authenticator. User roles are obtained from the Tomcat Realm based on the username in the `sub` claim.

### Server Responses

#### Successful Authentication (200 OK)
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "message": "Resource data"
}
```

#### No Authorization Header (401 Unauthorized)
```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="My Application API"

Unauthorized
```

#### Invalid Token (401 Unauthorized)
```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="My Application API", error="invalid_token", error_description="Invalid JWT signature"

Unauthorized
```

#### Expired Token with Refresh Endpoint (401 Unauthorized)
```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="My Application API", error="invalid_token", error_description="Token expired", refresh_endpoint="https://auth.example.com/token/refresh"

Unauthorized
```

#### User Not Found in Realm (401 Unauthorized)
```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="My Application API", error="invalid_token", error_description="User not found"

Unauthorized
```

#### Insufficient Permissions (403 Forbidden)
```http
HTTP/1.1 403 Forbidden

Forbidden
```

## Authentication Flow

1. **Request Received**: Client sends HTTP request with `Authorization: Bearer <token>` header
2. **Cache Check**: Authenticator checks for cached authentication in session (if enabled)
3. **Token Extraction**: Extracts JWT token from Authorization header
4. **Token Validation**:
   - Validates JWT structure (3 parts: header.payload.signature)
   - Validates signature using configured `jwtSecret`
   - Validates expiration (`exp` claim) with clock skew tolerance
   - Validates not-before (`nbf` claim) if present
   - Validates issuer (`iss` claim) if configured
   - Validates audience (`aud` claim) if configured
5. **User Lookup**: Extracts username from `sub` claim and authenticates via Realm
6. **Authorization**: Realm checks if user has required roles for the resource
7. **Response**: Either grants access or returns appropriate error

## Integration with Realms

The OAuth2BearerAuthenticator integrates with any Tomcat Realm implementation:

### MemoryRealm Example
```xml
<Realm className="org.apache.catalina.realm.MemoryRealm"
       pathname="conf/tomcat-users.xml" />
```

**conf/tomcat-users.xml:**
```xml
<tomcat-users>
    <role rolename="user"/>
    <role rolename="admin"/>
    <user username="john.doe" password="" roles="user"/>
    <user username="jane.admin" password="" roles="user,admin"/>
</tomcat-users>
```

**Note**: Password field can be empty since authentication is done via JWT token, not password.

### DataSourceRealm Example
```xml
<Realm className="org.apache.catalina.realm.DataSourceRealm"
       dataSourceName="jdbc/UserDB"
       userTable="users"
       userNameCol="username"
       userCredCol="password"
       userRoleTable="user_roles"
       roleNameCol="role_name" />
```

### JNDIRealm Example
```xml
<Realm className="org.apache.catalina.realm.JNDIRealm"
       connectionURL="ldap://ldap.example.com:389"
       userPattern="uid={0},ou=users,dc=example,dc=com"
       roleBase="ou=groups,dc=example,dc=com"
       roleName="cn"
       roleSearch="(member={0})" />
```

## Session Caching

By default, the OAuth2BearerAuthenticator does not create sessions (stateless authentication). Each request must include a valid JWT token.

To enable session-based caching of authenticated principals:

```xml
<Valve className="org.apache.catalina.authenticator.OAuth2BearerAuthenticator"
       jwtSecret="your-secret-key"
       alwaysUseSession="true"
       cache="true" />
```

When enabled:
- First successful authentication creates a session
- Subsequent requests can use the session cookie instead of the JWT token
- Session expires based on container's session timeout configuration
- Prevents session fixation attacks by changing session ID after authentication

## Security Considerations

### JWT Secret Management
- **Keep the secret secure**: Never commit the `jwtSecret` to version control
- **Use strong secrets**: Minimum 256 bits of entropy recommended
- **Rotate secrets regularly**: Implement a key rotation strategy
- **Use environment variables**: Configure secrets via environment variables or secure vaults

### Token Security
- **Use HTTPS**: Always use TLS/SSL to prevent token interception
- **Short expiration times**: Set reasonable `exp` times (e.g., 15-60 minutes)
- **Implement refresh tokens**: Use separate refresh tokens for obtaining new access tokens
- **Validate all claims**: Configure `jwtIssuer` and `jwtAudience` to prevent token misuse

### Realm Integration
- **Principle of least privilege**: Assign minimal required roles to users
- **Regular audits**: Review user permissions and roles regularly
- **User validation**: Ensure JWT `sub` claim matches actual users in the Realm

## Testing

The implementation includes comprehensive integration tests in `TestOAuth2BearerAuthenticator.java`:

```bash
# Run the OAuth2 Bearer Authenticator tests
ant test -Dtest.entry=org.apache.catalina.authenticator.TestOAuth2BearerAuthenticator
```

Test coverage includes:
- Valid token authentication
- Invalid token rejection
- Expired token handling
- Missing/empty token handling
- Invalid signature detection
- Missing claims handling
- Unknown user handling
- Invalid issuer/audience handling
- Case-insensitive Bearer scheme
- Session caching

## Example: Complete Setup

### 1. Configure Context (conf/Catalina/localhost/myapp.xml)
```xml
<Context docBase="/path/to/myapp">
    <Realm className="org.apache.catalina.realm.DataSourceRealm"
           dataSourceName="jdbc/UserDB"
           userTable="users"
           userNameCol="username"
           userCredCol="password"
           userRoleTable="user_roles"
           roleNameCol="role_name" />

    <Valve className="org.apache.catalina.authenticator.OAuth2BearerAuthenticator"
           jwtSecret="${JWT_SECRET}"
           jwtIssuer="https://auth.example.com"
           jwtAudience="myapp"
           allowTokenRefresh="true"
           tokenRefreshEndpoint="https://auth.example.com/token/refresh"
           clockSkewSeconds="60" />
</Context>
```

### 2. Configure Web Application (WEB-INF/web.xml)
```xml
<web-app>
    <security-constraint>
        <web-resource-collection>
            <web-resource-name>API Endpoints</web-resource-name>
            <url-pattern>/api/*</url-pattern>
        </web-resource-collection>
        <auth-constraint>
            <role-name>user</role-name>
        </auth-constraint>
    </security-constraint>

    <login-config>
        <auth-method>BEARER</auth-method>
        <realm-name>MyApp API</realm-name>
    </login-config>

    <security-role>
        <role-name>user</role-name>
    </security-role>
</web-app>
```

### 3. Client Request
```bash
# Obtain JWT token from your authentication server
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Access protected resource
curl -H "Authorization: Bearer $TOKEN" \
     https://example.com/myapp/api/data
```

## Troubleshooting

### Problem: "Invalid JWT signature"
**Cause**: The `jwtSecret` doesn't match the secret used to sign the token.
**Solution**: Ensure the same secret is used for both token signing and validation.

### Problem: "Token expired"
**Cause**: The token's `exp` claim indicates it has expired.
**Solution**: Obtain a new token or implement token refresh logic.

### Problem: "User not found"
**Cause**: The username in the JWT's `sub` claim doesn't exist in the Realm.
**Solution**: Ensure the user exists in the configured Realm and the `sub` claim matches exactly.

### Problem: "Invalid issuer"
**Cause**: The token's `iss` claim doesn't match the configured `jwtIssuer`.
**Solution**: Verify the `jwtIssuer` configuration matches the token issuer.

### Problem: HTTP 403 Forbidden
**Cause**: User is authenticated but doesn't have the required role.
**Solution**: Check the user's roles in the Realm and the required roles in `web.xml`.

## Limitations

1. **Signature Algorithm**: Currently only supports HMAC-SHA256 (HS256). For RSA/ECDSA support, consider using a dedicated JWT library like nimbus-jose-jwt.

2. **Token Revocation**: This implementation does not support token revocation lists. Tokens remain valid until expiration.

3. **Token Refresh**: The authenticator can indicate a refresh endpoint but does not handle the refresh flow itself.

## Future Enhancements

Potential improvements for production use:

1. **Multiple Signature Algorithms**: Support RS256, ES256, and other algorithms
2. **JWKS Support**: Fetch public keys from JSON Web Key Set endpoints
3. **Token Revocation**: Integration with token revocation lists or blacklists
4. **Scope Validation**: Validate OAuth2 scopes in addition to roles
5. **Rate Limiting**: Built-in rate limiting for authentication attempts
6. **Audit Logging**: Enhanced logging of authentication events

## References

- [RFC 6750: OAuth 2.0 Bearer Token Usage](https://tools.ietf.org/html/rfc6750)
- [RFC 7519: JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [RFC 7617: The 'Basic' HTTP Authentication Scheme](https://tools.ietf.org/html/rfc7617)
- [Apache Tomcat Realm Configuration](https://tomcat.apache.org/tomcat-10.1-doc/realm-howto.html)
- [Apache Tomcat Valve Configuration](https://tomcat.apache.org/tomcat-10.1-doc/config/valve.html)
