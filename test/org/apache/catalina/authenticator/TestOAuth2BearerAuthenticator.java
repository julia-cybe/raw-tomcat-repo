/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.catalina.authenticator;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import jakarta.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.Context;
import org.apache.catalina.startup.TesterServlet;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.startup.TomcatBaseTest;
import org.apache.tomcat.util.buf.ByteChunk;
import org.apache.tomcat.util.descriptor.web.LoginConfig;
import org.apache.tomcat.util.descriptor.web.SecurityCollection;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;

/**
 * Test OAuth2BearerAuthenticator with actual HTTP requests.
 * <p>
 * This test verifies the OAuth2 Bearer Token authentication flow including:
 * <ul>
 * <li>Valid JWT token authentication</li>
 * <li>Invalid token rejection</li>
 * <li>Expired token handling</li>
 * <li>Missing Authorization header handling</li>
 * <li>Token refresh endpoint notification</li>
 * <li>Integration with Tomcat's Realm infrastructure</li>
 * </ul>
 */
public class TestOAuth2BearerAuthenticator extends TomcatBaseTest {

    protected static final boolean USE_COOKIES = true;
    protected static final boolean NO_COOKIES = !USE_COOKIES;

    private static final String USER = "testuser";
    private static final String PWD = "testpwd";
    private static final String ROLE = "testrole";
    private static final String JWT_SECRET = "test-secret-key-for-hmac-sha256-signing-must-be-long-enough";
    private static final String JWT_ISSUER = "test-issuer";
    private static final String JWT_AUDIENCE = "test-audience";
    private static final String TOKEN_REFRESH_ENDPOINT = "https://auth.example.com/token/refresh";

    private static final String HTTP_PREFIX = "http://localhost:";
    private static final String CONTEXT_PATH = "/oauth2";
    private static final String URI_PROTECTED = "/protected";
    private static final String URI_PUBLIC = "/public";

    private static final String CLIENT_AUTH_HEADER = "authorization";
    private static final String SERVER_AUTH_HEADER = "WWW-Authenticate";

    private Tomcat tomcat;
    private Context bearerContext;

    /*
     * Try to access an unprotected resource without credentials. This should be permitted.
     */
    @Test
    public void testAccessPublicResource() throws Exception {
        doTest(CONTEXT_PATH + URI_PUBLIC, null, HttpServletResponse.SC_OK, null);
    }

    /*
     * Try to access a protected resource without credentials. This should be rejected with 401 Unauthorized.
     */
    @Test
    public void testAccessProtectedWithoutToken() throws Exception {
        String expectedChallenge = "Bearer realm=\"Authentication required\"";
        doTest(CONTEXT_PATH + URI_PROTECTED, null, HttpServletResponse.SC_UNAUTHORIZED, expectedChallenge);
    }

    /*
     * Try to access a protected resource with a valid JWT token. This should succeed.
     */
    @Test
    public void testAccessProtectedWithValidToken() throws Exception {
        String token = createValidToken(USER, 3600); // Valid for 1 hour
        doTest(CONTEXT_PATH + URI_PROTECTED, token, HttpServletResponse.SC_OK, null);
    }

    /*
     * Try to access a protected resource with an expired JWT token. This should be rejected with 401 and
     * include the refresh endpoint in the challenge.
     */
    @Test
    public void testAccessProtectedWithExpiredToken() throws Exception {
        String token = createExpiredToken(USER);
        String expectedChallenge = "Bearer realm=\"Authentication required\", error=\"invalid_token\", " +
                "error_description=\"Token expired\", refresh_endpoint=\"" + TOKEN_REFRESH_ENDPOINT + "\"";
        doTest(CONTEXT_PATH + URI_PROTECTED, token, HttpServletResponse.SC_UNAUTHORIZED, expectedChallenge);
    }

    /*
     * Try to access a protected resource with a token that has an invalid signature. This should be rejected.
     */
    @Test
    public void testAccessProtectedWithInvalidSignature() throws Exception {
        String token = createTokenWithInvalidSignature(USER);
        doTest(CONTEXT_PATH + URI_PROTECTED, token, HttpServletResponse.SC_UNAUTHORIZED, "error=\"invalid_token\"");
    }

    /*
     * Try to access a protected resource with a malformed JWT token. This should be rejected.
     */
    @Test
    public void testAccessProtectedWithMalformedToken() throws Exception {
        String token = "not.a.valid.jwt.token";
        doTest(CONTEXT_PATH + URI_PROTECTED, token, HttpServletResponse.SC_UNAUTHORIZED, "error=\"invalid_token\"");
    }

    /*
     * Try to access a protected resource with an empty Bearer token. This should be rejected.
     */
    @Test
    public void testAccessProtectedWithEmptyToken() throws Exception {
        String expectedChallenge = "Bearer realm=\"Authentication required\", error=\"invalid_token\", " +
                "error_description=\"Token is empty\"";
        doTest(CONTEXT_PATH + URI_PROTECTED, "", HttpServletResponse.SC_UNAUTHORIZED, expectedChallenge);
    }

    /*
     * Try to access a protected resource with a token that has no subject (sub) claim. This should be rejected.
     */
    @Test
    public void testAccessProtectedWithTokenMissingSubject() throws Exception {
        String token = createTokenWithoutSubject();
        String expectedChallenge = "Bearer realm=\"Authentication required\", error=\"invalid_token\", " +
                "error_description=\"Token missing subject claim\"";
        doTest(CONTEXT_PATH + URI_PROTECTED, token, HttpServletResponse.SC_UNAUTHORIZED, expectedChallenge);
    }

    /*
     * Try to access a protected resource with a token for a user that doesn't exist in the Realm.
     */
    @Test
    public void testAccessProtectedWithUnknownUser() throws Exception {
        String token = createValidToken("unknownuser", 3600);
        String expectedChallenge = "Bearer realm=\"Authentication required\", error=\"invalid_token\", " +
                "error_description=\"User not found\"";
        doTest(CONTEXT_PATH + URI_PROTECTED, token, HttpServletResponse.SC_UNAUTHORIZED, expectedChallenge);
    }

    /*
     * Try to access a protected resource with a token that has an invalid issuer.
     */
    @Test
    public void testAccessProtectedWithInvalidIssuer() throws Exception {
        String token = createTokenWithIssuer(USER, "wrong-issuer", 3600);
        doTest(CONTEXT_PATH + URI_PROTECTED, token, HttpServletResponse.SC_UNAUTHORIZED, "Invalid issuer");
    }

    /*
     * Try to access a protected resource with a token that has an invalid audience.
     */
    @Test
    public void testAccessProtectedWithInvalidAudience() throws Exception {
        String token = createTokenWithAudience(USER, "wrong-audience", 3600);
        doTest(CONTEXT_PATH + URI_PROTECTED, token, HttpServletResponse.SC_UNAUTHORIZED, "Invalid audience");
    }

    /*
     * Test case-insensitive Bearer scheme detection.
     */
    @Test
    public void testBearerSchemeIsCaseInsensitive() throws Exception {
        String token = createValidToken(USER, 3600);
        // The doTest method normally uses "Bearer " prefix, but we'll test with different cases
        Map<String,List<String>> reqHeaders = new HashMap<>();
        Map<String,List<String>> respHeaders = new HashMap<>();

        // Test with lowercase "bearer"
        List<String> auth = new ArrayList<>();
        auth.add("bearer " + token);
        reqHeaders.put(CLIENT_AUTH_HEADER, auth);

        ByteChunk bc = new ByteChunk();
        int rc = getUrl(HTTP_PREFIX + getPort() + CONTEXT_PATH + URI_PROTECTED, bc, reqHeaders, respHeaders);

        Assert.assertEquals(HttpServletResponse.SC_OK, rc);
        Assert.assertEquals("OK", bc.toString());
    }

    /*
     * Test accessing protected resource with session caching enabled.
     */
    @Test
    public void testBearerAuthenticationWithSession() throws Exception {
        setAlwaysUseSession();

        String token = createValidToken(USER, 3600);

        // First request with token - should create a session
        Map<String,List<String>> reqHeaders = new HashMap<>();
        Map<String,List<String>> respHeaders = new HashMap<>();
        List<String> auth = new ArrayList<>();
        auth.add("Bearer " + token);
        reqHeaders.put(CLIENT_AUTH_HEADER, auth);

        ByteChunk bc = new ByteChunk();
        int rc = getUrl(HTTP_PREFIX + getPort() + CONTEXT_PATH + URI_PROTECTED, bc, reqHeaders, respHeaders);

        Assert.assertEquals(HttpServletResponse.SC_OK, rc);
        Assert.assertEquals("OK", bc.toString());

        // Extract session cookie
        List<String> cookieHeaders = respHeaders.get("Set-Cookie");
        Assert.assertNotNull("Expected session cookie", cookieHeaders);

        // Second request with session cookie only (no token) - should still work
        Map<String,List<String>> reqHeaders2 = new HashMap<>();
        Map<String,List<String>> respHeaders2 = new HashMap<>();

        String sessionCookie = cookieHeaders.get(0).substring(0, cookieHeaders.get(0).indexOf(';'));
        List<String> cookieList = new ArrayList<>();
        cookieList.add(sessionCookie);
        reqHeaders2.put("Cookie", cookieList);

        ByteChunk bc2 = new ByteChunk();
        int rc2 = getUrl(HTTP_PREFIX + getPort() + CONTEXT_PATH + URI_PROTECTED, bc2, reqHeaders2, respHeaders2);

        Assert.assertEquals(HttpServletResponse.SC_OK, rc2);
        Assert.assertEquals("OK", bc2.toString());
    }

    // --------------------------------------------------------- Helper Methods

    private void doTest(String uri, String token, int expectedRC, String expectedChallengeFragment) throws Exception {
        Map<String,List<String>> reqHeaders = new HashMap<>();
        Map<String,List<String>> respHeaders = new HashMap<>();

        if (token != null) {
            List<String> auth = new ArrayList<>();
            auth.add("Bearer " + token);
            reqHeaders.put(CLIENT_AUTH_HEADER, auth);
        }

        ByteChunk bc = new ByteChunk();
        int rc = getUrl(HTTP_PREFIX + getPort() + uri, bc, reqHeaders, respHeaders);

        Assert.assertEquals(expectedRC, rc);

        if (expectedRC != HttpServletResponse.SC_OK) {
            Assert.assertTrue(bc.getLength() > 0);

            if (expectedRC == HttpServletResponse.SC_UNAUTHORIZED) {
                // Verify the WWW-Authenticate header
                List<String> authHeaders = respHeaders.get(SERVER_AUTH_HEADER);
                Assert.assertNotNull("Expected WWW-Authenticate header", authHeaders);
                Assert.assertTrue("Expected at least one WWW-Authenticate header", authHeaders.size() > 0);

                if (expectedChallengeFragment != null) {
                    boolean challengeFound = false;
                    for (String authHeader : authHeaders) {
                        if (authHeader.contains(expectedChallengeFragment)) {
                            challengeFound = true;
                            break;
                        }
                    }
                    Assert.assertTrue("Expected WWW-Authenticate header to contain: " + expectedChallengeFragment,
                            challengeFound);
                }
            }
        } else {
            Assert.assertEquals("OK", bc.toString());
        }
    }

    /**
     * Create a valid JWT token for testing.
     */
    private String createValidToken(String username, long expiresInSeconds) {
        return createToken(username, JWT_ISSUER, JWT_AUDIENCE, expiresInSeconds);
    }

    /**
     * Create an expired JWT token for testing.
     */
    private String createExpiredToken(String username) {
        return createToken(username, JWT_ISSUER, JWT_AUDIENCE, -3600); // Expired 1 hour ago
    }

    /**
     * Create a JWT token with a specific issuer.
     */
    private String createTokenWithIssuer(String username, String issuer, long expiresInSeconds) {
        return createToken(username, issuer, JWT_AUDIENCE, expiresInSeconds);
    }

    /**
     * Create a JWT token with a specific audience.
     */
    private String createTokenWithAudience(String username, String audience, long expiresInSeconds) {
        return createToken(username, JWT_ISSUER, audience, expiresInSeconds);
    }

    /**
     * Create a JWT token without a subject claim.
     */
    private String createTokenWithoutSubject() {
        long currentTime = System.currentTimeMillis() / 1000L;
        long expirationTime = currentTime + 3600;

        String payload = "{\"iss\":\"" + JWT_ISSUER + "\",\"aud\":\"" + JWT_AUDIENCE +
                "\",\"exp\":" + expirationTime + ",\"iat\":" + currentTime + "}";

        return buildJwt(payload, JWT_SECRET);
    }

    /**
     * Create a JWT token with an invalid signature.
     */
    private String createTokenWithInvalidSignature(String username) {
        String validToken = createValidToken(username, 3600);
        // Tamper with the signature part
        String[] parts = validToken.split("\\.");
        return parts[0] + "." + parts[1] + ".invalidSignature";
    }

    /**
     * Create a JWT token with the specified claims.
     */
    private String createToken(String username, String issuer, String audience, long expiresInSeconds) {
        long currentTime = System.currentTimeMillis() / 1000L;
        long expirationTime = currentTime + expiresInSeconds;

        String payload = "{\"sub\":\"" + username + "\",\"iss\":\"" + issuer + "\",\"aud\":\"" + audience +
                "\",\"exp\":" + expirationTime + ",\"iat\":" + currentTime + "}";

        return buildJwt(payload, JWT_SECRET);
    }

    /**
     * Build a JWT token from a JSON payload.
     */
    private String buildJwt(String payload, String secret) {
        // Create header
        String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";

        // Base64 URL encode header and payload
        String headerEncoded = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(header.getBytes(StandardCharsets.UTF_8));
        String payloadEncoded = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payload.getBytes(StandardCharsets.UTF_8));

        // Create signature
        String message = headerEncoded + "." + payloadEncoded;
        String signature = createHmacSha256Signature(message, secret);

        return message + "." + signature;
    }

    /**
     * Create HMAC-SHA256 signature for a message.
     */
    private String createHmacSha256Signature(String message, String secret) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            javax.crypto.spec.SecretKeySpec secretKey = new javax.crypto.spec.SecretKeySpec(
                    secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(secretKey);
            byte[] signatureBytes = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create signature", e);
        }
    }

    // --------------------------------------------------------- Setup Methods

    @Override
    public void setUp() throws Exception {
        super.setUp();

        // Create a Tomcat server using the default in-memory Realm
        tomcat = getTomcatInstance();

        // Add the test user and role to the Realm
        tomcat.addUser(USER, PWD);
        tomcat.addRole(USER, ROLE);

        // Setup OAuth2 Bearer authentication webapp
        setUpBearerContext();

        tomcat.start();
    }

    private void setUpBearerContext() throws Exception {
        // Must have a real docBase for webapps - just use temp
        bearerContext = tomcat.addContext(CONTEXT_PATH, System.getProperty("java.io.tmpdir"));

        // Add protected servlet to the context
        Tomcat.addServlet(bearerContext, "ProtectedServlet", new TesterServlet());
        bearerContext.addServletMappingDecoded(URI_PROTECTED, "ProtectedServlet");
        SecurityCollection protectedCollection = new SecurityCollection();
        protectedCollection.addPatternDecoded(URI_PROTECTED);
        SecurityConstraint protectedConstraint = new SecurityConstraint();
        protectedConstraint.addAuthRole(ROLE);
        protectedConstraint.addCollection(protectedCollection);
        bearerContext.addConstraint(protectedConstraint);

        // Add unprotected servlet to the context
        Tomcat.addServlet(bearerContext, "PublicServlet", new TesterServlet());
        bearerContext.addServletMappingDecoded(URI_PUBLIC, "PublicServlet");

        SecurityCollection publicCollection = new SecurityCollection();
        publicCollection.addPatternDecoded(URI_PUBLIC);
        SecurityConstraint publicConstraint = new SecurityConstraint();
        // Do not add a role - which signals access permitted without one
        publicConstraint.addCollection(publicCollection);
        bearerContext.addConstraint(publicConstraint);

        // Configure the OAuth2 Bearer authenticator
        LoginConfig lc = new LoginConfig();
        lc.setAuthMethod("BEARER");
        bearerContext.setLoginConfig(lc);

        OAuth2BearerAuthenticator bearerAuthenticator = new OAuth2BearerAuthenticator();
        bearerAuthenticator.setJwtSecret(JWT_SECRET);
        bearerAuthenticator.setJwtIssuer(JWT_ISSUER);
        bearerAuthenticator.setJwtAudience(JWT_AUDIENCE);
        bearerAuthenticator.setAllowTokenRefresh(true);
        bearerAuthenticator.setTokenRefreshEndpoint(TOKEN_REFRESH_ENDPOINT);
        bearerAuthenticator.setClockSkewSeconds(60);

        bearerContext.getPipeline().addValve(bearerAuthenticator);
    }

    private void setAlwaysUseSession() {
        ((AuthenticatorBase) bearerContext.getAuthenticator()).setAlwaysUseSession(true);
    }
}
