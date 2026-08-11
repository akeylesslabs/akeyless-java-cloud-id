package io.akeyless.cloudid;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Iterator;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Fully hermetic, offline end-to-end tests for {@link AwsCloudIdProvider}.
 *
 * <p>The provider resolves credentials through the AWS SDK
 * {@code DefaultCredentialsProvider} chain. The first link in that chain is the
 * {@code SystemPropertyCredentialsProvider}, which reads the {@code aws.accessKeyId},
 * {@code aws.secretAccessKey} and {@code aws.sessionToken} system properties with
 * <em>no</em> network access. By setting those properties to fake static values we
 * exercise the whole "sign an STS GetCallerIdentity request and package it as a
 * cloud-id token" flow without any real credentials or any outbound request.
 *
 * <p>SigV4 signing is a purely local computation, so these tests never contact STS.
 */
public class AwsCloudIdProviderTest {

    private static final String FAKE_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
    private static final String FAKE_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    private static final String FAKE_SESSION_TOKEN = "FAKESESSIONTOKEN/akeyless-test//////////wEXAMPLE";

    private static final String PROP_ACCESS_KEY = "aws.accessKeyId";
    private static final String PROP_SECRET_KEY = "aws.secretAccessKey";
    private static final String PROP_SESSION_TOKEN = "aws.sessionToken";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private String savedAccessKey;
    private String savedSecretKey;
    private String savedSessionToken;

    @Before
    public void injectFakeCredentials() {
        // Remember whatever the host/CI environment had so we can restore it.
        savedAccessKey = System.getProperty(PROP_ACCESS_KEY);
        savedSecretKey = System.getProperty(PROP_SECRET_KEY);
        savedSessionToken = System.getProperty(PROP_SESSION_TOKEN);

        System.setProperty(PROP_ACCESS_KEY, FAKE_ACCESS_KEY);
        System.setProperty(PROP_SECRET_KEY, FAKE_SECRET_KEY);
        // Session token is set per-test where needed; make sure we start clean.
        System.clearProperty(PROP_SESSION_TOKEN);
    }

    @After
    public void restoreCredentials() {
        restore(PROP_ACCESS_KEY, savedAccessKey);
        restore(PROP_SECRET_KEY, savedSecretKey);
        restore(PROP_SESSION_TOKEN, savedSessionToken);
    }

    private static void restore(String key, String value) {
        if (value == null) {
            System.clearProperty(key);
        } else {
            System.setProperty(key, value);
        }
    }

    // ---- The decoded token model -------------------------------------------------

    /** Decodes the outer base64+JSON envelope and the inner base64 fields. */
    private static DecodedToken decode(String cloudId) throws Exception {
        assertNotNull("cloud id must not be null", cloudId);
        byte[] outer = Base64.getDecoder().decode(cloudId);
        JsonNode root = MAPPER.readTree(new String(outer, StandardCharsets.UTF_8));

        DecodedToken token = new DecodedToken();
        token.method = root.get("sts_request_method").asText();
        token.url = decodeField(root, "sts_request_url");
        token.body = decodeField(root, "sts_request_body");
        token.headersJson = decodeField(root, "sts_request_headers");
        token.headers = MAPPER.readTree(token.headersJson);
        return token;
    }

    private static String decodeField(JsonNode root, String field) {
        JsonNode node = root.get(field);
        assertNotNull("missing token field: " + field, node);
        return new String(Base64.getDecoder().decode(node.asText()), StandardCharsets.UTF_8);
    }

    private static final class DecodedToken {
        String method;
        String url;
        String body;
        String headersJson;
        JsonNode headers;

        /** Case-insensitive header lookup; headers are serialized as name -> [values]. */
        String header(String name) {
            Iterator<Map.Entry<String, JsonNode>> fields = headers.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> e = fields.next();
                if (e.getKey().equalsIgnoreCase(name)) {
                    JsonNode v = e.getValue();
                    return v.isArray() && v.size() > 0 ? v.get(0).asText() : v.asText();
                }
            }
            return null;
        }

        boolean hasHeader(String name) {
            return header(name) != null;
        }
    }

    private static DecodedToken getDecodedToken() throws Exception {
        return decode(new AwsCloudIdProvider().getCloudId());
    }

    // ---- Envelope / payload shape ------------------------------------------------

    @Test
    public void tokenIsBase64EncodedJsonBundleWithAllFields() throws Exception {
        String cloudId = new AwsCloudIdProvider().getCloudId();
        assertFalse("cloud id must not be empty", cloudId.isEmpty());

        // Outer layer must be valid base64 of a JSON object carrying the 4 STS fields.
        JsonNode root = MAPPER.readTree(new String(Base64.getDecoder().decode(cloudId), StandardCharsets.UTF_8));
        assertTrue(root.isObject());
        assertTrue(root.has("sts_request_method"));
        assertTrue(root.has("sts_request_url"));
        assertTrue(root.has("sts_request_body"));
        assertTrue(root.has("sts_request_headers"));
    }

    @Test
    public void methodIsPost() throws Exception {
        assertEquals("POST", getDecodedToken().method);
    }

    @Test
    public void urlDecodesToGlobalStsEndpoint() throws Exception {
        assertEquals("https://sts.amazonaws.com/", getDecodedToken().url);
    }

    @Test
    public void bodyIsGetCallerIdentityAction() throws Exception {
        assertEquals("Action=GetCallerIdentity&Version=2011-06-15", getDecodedToken().body);
    }

    // ---- SigV4 signing correctness ----------------------------------------------

    @Test
    public void authorizationHeaderIsSigV4() throws Exception {
        String auth = getDecodedToken().header("Authorization");
        assertNotNull("Authorization header must be present", auth);
        assertTrue("Authorization must use SigV4 (AWS4-HMAC-SHA256), was: " + auth,
                auth.startsWith("AWS4-HMAC-SHA256"));
        assertTrue("Authorization must carry a Signature component", auth.contains("Signature="));
        assertTrue("Authorization must carry SignedHeaders", auth.contains("SignedHeaders="));
    }

    @Test
    public void credentialScopeTargetsUsEast1StsService() throws Exception {
        String auth = getDecodedToken().header("Authorization");
        assertNotNull(auth);
        // Credential scope is <access-key>/<yyyymmdd>/<region>/<service>/aws4_request
        assertTrue("credential scope must target us-east-1/sts, was: " + auth,
                auth.contains("/us-east-1/sts/aws4_request"));
        assertTrue("Authorization must reference the fake access key id",
                auth.contains("Credential=" + FAKE_ACCESS_KEY + "/"));
    }

    @Test
    public void hostHeaderIsGlobalStsHost() throws Exception {
        assertEquals("sts.amazonaws.com", getDecodedToken().header("Host"));
    }

    @Test
    public void xAmzDateHeaderIsPresentAndWellFormed() throws Exception {
        String date = getDecodedToken().header("X-Amz-Date");
        assertNotNull("X-Amz-Date header must be present", date);
        // Format is basic ISO8601: yyyyMMdd'T'HHmmss'Z'
        assertTrue("X-Amz-Date must match yyyyMMddTHHmmssZ, was: " + date,
                date.matches("^\\d{8}T\\d{6}Z$"));
    }

    @Test
    public void contentTypeHeaderIsFormUrlEncoded() throws Exception {
        String contentType = getDecodedToken().header("Content-Type");
        assertNotNull(contentType);
        assertTrue("Content-Type must be form-urlencoded, was: " + contentType,
                contentType.startsWith("application/x-www-form-urlencoded"));
    }

    // ---- Session-token handling --------------------------------------------------

    @Test
    public void includesSecurityTokenWhenSessionCredentialsUsed() throws Exception {
        System.setProperty(PROP_SESSION_TOKEN, FAKE_SESSION_TOKEN);
        DecodedToken token = getDecodedToken();
        assertEquals("X-Amz-Security-Token must echo the session token",
                FAKE_SESSION_TOKEN, token.header("X-Amz-Security-Token"));
        // Session-token requests must also fold the token into the signature.
        assertTrue(token.header("Authorization").contains("x-amz-security-token"));
    }

    @Test
    public void omitsSecurityTokenForStaticCredentials() throws Exception {
        // injectFakeCredentials() clears the session token, so basic creds are used.
        DecodedToken token = getDecodedToken();
        assertFalse("X-Amz-Security-Token must be absent without a session token",
                token.hasHeader("X-Amz-Security-Token"));
    }

    // ---- Determinism / independence ---------------------------------------------

    @Test
    public void structureIsDeterministicAcrossCalls() throws Exception {
        DecodedToken a = getDecodedToken();
        DecodedToken b = getDecodedToken();
        // Method/URL/body are fixed inputs and must never vary between invocations.
        assertEquals(a.method, b.method);
        assertEquals(a.url, b.url);
        assertEquals(a.body, b.body);
        assertEquals(a.header("Host"), b.header("Host"));
    }
}
