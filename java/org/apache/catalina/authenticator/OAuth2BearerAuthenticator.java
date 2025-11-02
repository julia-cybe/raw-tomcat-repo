/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.catalina.authenticator;

import java.io.IOException;
import java.security.Principal;
import java.util.Base64;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.catalina.connector.Request;
import org.apache.catalina.realm.GenericPrincipal;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.buf.MessageBytes;
import org.apache.tomcat.util.json.JSONParser;

/**
 * An <b>Authenticator</b> and <b>Valve</b> implementation of OAuth2 Bearer Token Authentication
 * as outlined in RFC 6750: "The OAuth 2.0 Authorization Framework: Bearer Token Usage".
 * <p>
 * This authenticator validates JWT (JSON Web Token) tokens from the Authorization header,
 * integrates with Tomcat's existing Realm infrastructure, and works in the valve pipeline
 * like FormAuthenticator and BasicAuthenticator.
 * <p>
 * Configuration properties:
 * <ul>
 * <li><b>jwtSecret</b> - The secret key used to validate JWT signatures (HS256). Required.</li>
 * <li><b>jwtIssuer</b> - Expected issuer (iss claim) in the JWT. Optional.</li>
 * <li><b>jwtAudience</b> - Expected audience (aud claim) in the JWT. Optional.</li>
 * <li><b>allowTokenRefresh</b> - Whether to allow token refresh. Default: false.</li>
 * <li><b>tokenRefreshEndpoint</b> - Endpoint URL for token refresh. Required if allowTokenRefresh is true.</li>
 * </ul>
 */
public class OAuth2BearerAuthenticator extends AuthenticatorBase {

    private final Log log = LogFactory.getLog(OAuth2BearerAuthenticator.class);

    /**
     * Descriptive information about this implementation.
     */
    protected static final String AUTH_METHOD = "BEARER";

    /**
     * The secret key used to validate JWT signatures (HS256).
     */
    private String jwtSecret = null;

    /**
     * Expected issuer (iss claim) in the JWT.
     */
    private String jwtIssuer = null;

    /**
     * Expected audience (aud claim) in the JWT.
     */
    private String jwtAudience = null;

    /**
     * Whether to allow token refresh.
     */
    private boolean allowTokenRefresh = false;

    /**
     * Endpoint URL for token refresh.
     */
    private String tokenRefreshEndpoint = null;

    /**
     * Clock skew tolerance in seconds for token expiration validation.
     */
    private int clockSkewSeconds = 60;

    // ------------------------------------------------------------- Properties

    public String getJwtSecret() {
        return jwtSecret;
    }

    public void setJwtSecret(String jwtSecret) {
        this.jwtSecret = jwtSecret;
    }

    public String getJwtIssuer() {
        return jwtIssuer;
    }

    public void setJwtIssuer(String jwtIssuer) {
        this.jwtIssuer = jwtIssuer;
    }

    public String getJwtAudience() {
        return jwtAudience;
    }

    public void setJwtAudience(String jwtAudience) {
        this.jwtAudience = jwtAudience;
    }

    public boolean isAllowTokenRefresh() {
        return allowTokenRefresh;
    }

    public void setAllowTokenRefresh(boolean allowTokenRefresh) {
        this.allowTokenRefresh = allowTokenRefresh;
    }

    public String getTokenRefreshEndpoint() {
        return tokenRefreshEndpoint;
    }

    public void setTokenRefreshEndpoint(String tokenRefreshEndpoint) {
        this.tokenRefreshEndpoint = tokenRefreshEndpoint;
    }

    public int getClockSkewSeconds() {
        return clockSkewSeconds;
    }

    public void setClockSkewSeconds(int clockSkewSeconds) {
        this.clockSkewSeconds = clockSkewSeconds;
    }

    // --------------------------------------------------------- Public Methods

    @Override
    protected boolean doAuthenticate(Request request, HttpServletResponse response) throws IOException {

        // Check for cached authentication first
        if (checkForCachedAuthentication(request, response, true)) {
            return true;
        }

        // Extract the Authorization header
        MessageBytes authorization = request.getCoyoteRequest().getMimeHeaders().getValue("authorization");

        if (authorization == null) {
            // No Authorization header present
            if (log.isDebugEnabled()) {
                log.debug("No Authorization header found");
            }
            sendUnauthorizedResponse(response, "Bearer realm=\"" + getRealmName(context) + "\"");
            return false;
        }

        // Convert to String for processing
        String authHeader = authorization.toString();

        // Validate that it's a Bearer token
        String authHeaderLower = authHeader.toLowerCase();
        if (!authHeaderLower.startsWith("bearer")) {
            if (log.isDebugEnabled()) {
                log.debug("Authorization header does not start with 'Bearer'");
            }
            sendUnauthorizedResponse(response, "Bearer realm=\"" + getRealmName(context) +
                    "\", error=\"invalid_request\", error_description=\"Authorization header must use Bearer scheme\"");
            return false;
        }

        // Extract the token - handle both "Bearer token" and "Bearer " or just "Bearer"
        String token;
        if (authHeader.length() > 6 && Character.isWhitespace(authHeader.charAt(6))) {
            // Has space after "Bearer"
            token = authHeader.substring(7).trim();
        } else if (authHeader.length() > 6) {
            // No space after "Bearer" (invalid format but extract anyway for better error message)
            token = authHeader.substring(6).trim();
        } else {
            // Just "Bearer" with nothing after
            token = "";
        }

        if (token.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("Bearer token is empty");
            }
            sendUnauthorizedResponse(response, "Bearer realm=\"" + getRealmName(context) +
                    "\", error=\"invalid_token\", error_description=\"Token is empty\"");
            return false;
        }

        // Validate and parse the JWT token
        JwtToken jwtToken;
        try {
            jwtToken = parseAndValidateJwt(token);
        } catch (JwtValidationException e) {
            if (log.isDebugEnabled()) {
                log.debug("JWT validation failed: " + e.getMessage(), e);
            }

            // Check if token is expired and refresh is allowed
            if (e.isExpired() && allowTokenRefresh && tokenRefreshEndpoint != null) {
                sendUnauthorizedResponse(response, "Bearer realm=\"" + getRealmName(context) +
                        "\", error=\"invalid_token\", error_description=\"Token expired\"" +
                        ", refresh_endpoint=\"" + tokenRefreshEndpoint + "\"");
            } else {
                sendUnauthorizedResponse(response, "Bearer realm=\"" + getRealmName(context) +
                        "\", error=\"invalid_token\", error_description=\"" + e.getMessage() + "\"");
            }
            return false;
        }

        // Extract username from token
        String username = jwtToken.getSubject();
        if (username == null || username.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("JWT token does not contain a subject (sub) claim");
            }
            sendUnauthorizedResponse(response, "Bearer realm=\"" + getRealmName(context) +
                    "\", error=\"invalid_token\", error_description=\"Token missing subject claim\"");
            return false;
        }

        // Authenticate the user through the Realm
        // The Realm will validate the user exists and retrieve their roles
        Principal principal = context.getRealm().authenticate(username);

        if (principal == null) {
            // User not found in Realm
            if (log.isDebugEnabled()) {
                log.debug("User '" + username + "' not found in realm");
            }
            sendUnauthorizedResponse(response, "Bearer realm=\"" + getRealmName(context) +
                    "\", error=\"invalid_token\", error_description=\"User not found\"");
            return false;
        }

        // Successfully authenticated - register the principal
        if (log.isDebugEnabled()) {
            log.debug("Successfully authenticated user: " + username);
        }

        register(request, response, principal, AUTH_METHOD, username, null);
        return true;
    }

    @Override
    protected String getAuthMethod() {
        return AUTH_METHOD;
    }

    @Override
    protected boolean isPreemptiveAuthPossible(Request request) {
        MessageBytes authorizationHeader = request.getCoyoteRequest().getMimeHeaders().getValue("authorization");
        return authorizationHeader != null && authorizationHeader.startsWithIgnoreCase("bearer ", 0);
    }

    // ------------------------------------------------------ Protected Methods

    /**
     * Parse and validate a JWT token.
     *
     * @param token The JWT token string
     * @return A JwtToken object containing the parsed claims
     * @throws JwtValidationException if the token is invalid
     */
    protected JwtToken parseAndValidateJwt(String token) throws JwtValidationException {
        // Split the token into its three parts: header.payload.signature
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new JwtValidationException("Invalid JWT format: expected 3 parts separated by dots", false);
        }

        String headerEncoded = parts[0];
        String payloadEncoded = parts[1];
        String signatureEncoded = parts[2];

        // Decode the payload
        byte[] payloadBytes;
        try {
            payloadBytes = Base64.getUrlDecoder().decode(payloadEncoded);
        } catch (IllegalArgumentException e) {
            throw new JwtValidationException("Invalid JWT: payload is not valid Base64", false);
        }

        String payloadJson = new String(payloadBytes, java.nio.charset.StandardCharsets.UTF_8);

        // Parse the JSON payload
        JwtToken jwtToken;
        try {
            jwtToken = new JwtToken(payloadJson);
        } catch (Exception e) {
            throw new JwtValidationException("Invalid JWT: cannot parse payload JSON: " + e.getMessage(), false);
        }

        // Validate signature if secret is configured
        if (jwtSecret != null && !jwtSecret.isEmpty()) {
            if (!validateSignature(headerEncoded + "." + payloadEncoded, signatureEncoded, jwtSecret)) {
                throw new JwtValidationException("Invalid JWT signature", false);
            }
        }

        // Validate expiration
        Long exp = jwtToken.getExpiration();
        if (exp != null) {
            long currentTime = System.currentTimeMillis() / 1000L;
            if (currentTime > exp + clockSkewSeconds) {
                throw new JwtValidationException("Token has expired", true);
            }
        }

        // Validate not-before time
        Long nbf = jwtToken.getNotBefore();
        if (nbf != null) {
            long currentTime = System.currentTimeMillis() / 1000L;
            if (currentTime < nbf - clockSkewSeconds) {
                throw new JwtValidationException("Token not yet valid", false);
            }
        }

        // Validate issuer if configured
        if (jwtIssuer != null && !jwtIssuer.isEmpty()) {
            String tokenIssuer = jwtToken.getIssuer();
            if (tokenIssuer == null || !jwtIssuer.equals(tokenIssuer)) {
                throw new JwtValidationException("Invalid issuer: expected '" + jwtIssuer +
                        "' but got '" + tokenIssuer + "'", false);
            }
        }

        // Validate audience if configured
        if (jwtAudience != null && !jwtAudience.isEmpty()) {
            String tokenAudience = jwtToken.getAudience();
            if (tokenAudience == null || !jwtAudience.equals(tokenAudience)) {
                throw new JwtValidationException("Invalid audience: expected '" + jwtAudience +
                        "' but got '" + tokenAudience + "'", false);
            }
        }

        return jwtToken;
    }

    /**
     * Validate the JWT signature using HMAC-SHA256.
     *
     * @param message The message to validate (header.payload)
     * @param signatureEncoded The Base64-URL encoded signature
     * @param secret The secret key
     * @return true if the signature is valid, false otherwise
     */
    protected boolean validateSignature(String message, String signatureEncoded, String secret) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            javax.crypto.spec.SecretKeySpec secretKey = new javax.crypto.spec.SecretKeySpec(
                    secret.getBytes(java.nio.charset.StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(secretKey);
            byte[] calculatedSignature = mac.doFinal(message.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            String calculatedSignatureEncoded = Base64.getUrlEncoder().withoutPadding().encodeToString(calculatedSignature);
            return calculatedSignatureEncoded.equals(signatureEncoded);
        } catch (Exception e) {
            log.error("Error validating JWT signature", e);
            return false;
        }
    }

    /**
     * Send a 401 Unauthorized response with the appropriate WWW-Authenticate header.
     *
     * @param response The HTTP response
     * @param challenge The WWW-Authenticate challenge string
     * @throws IOException if an I/O error occurs
     */
    protected void sendUnauthorizedResponse(HttpServletResponse response, String challenge) throws IOException {
        response.setHeader(AUTH_HEADER_NAME, challenge);
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }

    // --------------------------------------------------------- Inner Classes

    /**
     * Represents a parsed JWT token with its claims.
     */
    protected static class JwtToken {
        private final java.util.Map<String, Object> claims;

        public JwtToken(String payloadJson) throws Exception {
            JSONParser parser = new JSONParser(payloadJson);
            this.claims = parser.parseObject();
        }

        public String getSubject() {
            return (String) claims.get("sub");
        }

        public String getIssuer() {
            return (String) claims.get("iss");
        }

        public String getAudience() {
            return (String) claims.get("aud");
        }

        public Long getExpiration() {
            Object exp = claims.get("exp");
            if (exp instanceof Number) {
                return ((Number) exp).longValue();
            }
            return null;
        }

        public Long getNotBefore() {
            Object nbf = claims.get("nbf");
            if (nbf instanceof Number) {
                return ((Number) nbf).longValue();
            }
            return null;
        }

        public Object getClaim(String name) {
            return claims.get(name);
        }
    }

    /**
     * Exception thrown when JWT validation fails.
     */
    protected static class JwtValidationException extends Exception {
        private static final long serialVersionUID = 1L;
        private final boolean expired;

        public JwtValidationException(String message, boolean expired) {
            super(message);
            this.expired = expired;
        }

        public boolean isExpired() {
            return expired;
        }
    }
}
