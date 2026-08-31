package io.akeyless.cloudid;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class AlibabaCloudIdProviderTest {
    private static final String TEST_TIMESTAMP = "2026-05-11T10:00:00Z";
    private static final String TEST_NONCE = "fixed-nonce";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    public void defaultRegionUsesHangzhouAndGlobalSts() throws Exception {
        DecodedToken token = decode(signedCloudId("", ""));
        assertEquals("POST", token.method);
        assertTrue(token.url.startsWith("https://sts.aliyuncs.com/?"));
        assertEquals("", token.body);
        assertEquals(AlibabaCloudIdProvider.DEFAULT_REGION, query(token.url).get("RegionId"));
        assertEquals(AlibabaCloudIdProvider.STS_API_ACTION, query(token.url).get("Action"));
        assertEquals(AlibabaCloudIdProvider.STS_API_VERSION, query(token.url).get("Version"));
        assertNotNull(query(token.url).get("Signature"));
    }

    @Test
    public void configuredRegionIsSigned() throws Exception {
        DecodedToken token = decode(signedCloudId("cn-beijing", ""));
        assertEquals("cn-beijing", query(token.url).get("RegionId"));
    }

    @Test
    public void includesSecurityToken() throws Exception {
        DecodedToken token = decode(signedCloudId("cn-hangzhou", "SESSION"));
        assertEquals("SESSION", query(token.url).get("SecurityToken"));
    }

    @Test
    public void payloadHasCompatibleHeaders() throws Exception {
        DecodedToken token = decode(signedCloudId("cn-hangzhou", ""));
        assertTrue(token.header("Content-Type").startsWith("application/x-www-form-urlencoded"));
        assertEquals(AlibabaCloudIdProvider.STS_API_ACTION, token.header("X-Acs-Action"));
        assertEquals(AlibabaCloudIdProvider.STS_API_VERSION, token.header("X-Acs-Version"));
    }

    @Test
    public void rpcStringToSignIsDeterministic() throws Exception {
        Map<String, String> queryParams = new TreeMap<String, String>();
        queryParams.put("AccessKeyId", "AKID");
        queryParams.put("Action", AlibabaCloudIdProvider.STS_API_ACTION);
        queryParams.put("Format", AlibabaCloudIdProvider.STS_API_FORMAT);
        queryParams.put("RegionId", AlibabaCloudIdProvider.DEFAULT_REGION);
        queryParams.put("SignatureMethod", AlibabaCloudIdProvider.SIGNATURE_METHOD);
        queryParams.put("SignatureNonce", TEST_NONCE);
        queryParams.put("SignatureType", "");
        queryParams.put("SignatureVersion", "1.0");
        queryParams.put("Timestamp", TEST_TIMESTAMP);
        queryParams.put("Version", AlibabaCloudIdProvider.STS_API_VERSION);

        String stringToSign = AlibabaCloudIdProvider.buildRpcStringToSign("POST", queryParams);
        String signature = AlibabaCloudIdProvider.shaHmac1(stringToSign, "SECRET&");

        assertEquals(
                "POST&%2F&AccessKeyId%3DAKID%26Action%3DGetCallerIdentity%26Format%3DJSON%26RegionId%3Dcn-hangzhou%26SignatureMethod%3DHMAC-SHA1%26SignatureNonce%3Dfixed-nonce%26SignatureType%3D%26SignatureVersion%3D1.0%26Timestamp%3D2026-05-11T10%253A00%253A00Z%26Version%3D2015-04-01",
                stringToSign);
        assertEquals("dSCqL2sSKYDmcOcAj2Grhpar/wE=", signature);
    }

    @Test
    public void ecsCredentialsUseImdsV2Token() throws Exception {
        AtomicInteger tokenPuts = new AtomicInteger();
        AtomicInteger unauthenticatedGets = new AtomicInteger();
        HttpServer server = startMetadataServer(tokenPuts, unauthenticatedGets, true, "my-role");
        try {
            AlibabaCloudIdProvider.AlibabaCredentials creds =
                    AlibabaCloudIdProvider.resolveEcsRamRoleCredentials(baseUrl(server), false);
            assertEquals("AKI", creds.accessKeyId);
            assertEquals("SECRET", creds.accessKeySecret);
            assertEquals("TOK", creds.securityToken);
            assertEquals(1, tokenPuts.get());
            assertEquals(0, unauthenticatedGets.get());
        } finally {
            server.stop(0);
        }
    }

    @Test
    public void ecsCredentialsFallBackToImdsV1WhenTokenUnavailable() throws Exception {
        AtomicInteger tokenPuts = new AtomicInteger();
        AtomicInteger unauthenticatedGets = new AtomicInteger();
        HttpServer server = startMetadataServer(tokenPuts, unauthenticatedGets, false, "my-role");
        try {
            AlibabaCloudIdProvider.AlibabaCredentials creds =
                    AlibabaCloudIdProvider.resolveEcsRamRoleCredentials(baseUrl(server), false);
            assertEquals("AKI", creds.accessKeyId);
            assertEquals(1, tokenPuts.get());
            assertTrue(unauthenticatedGets.get() >= 2);
        } finally {
            server.stop(0);
        }
    }

    @Test
    public void ecsCredentialsDoNotFallBackWhenImdsV1Disabled() throws Exception {
        AtomicInteger tokenPuts = new AtomicInteger();
        AtomicInteger unauthenticatedGets = new AtomicInteger();
        HttpServer server = startMetadataServer(tokenPuts, unauthenticatedGets, false, "my-role");
        try {
            AlibabaCloudIdProvider.resolveEcsRamRoleCredentials(baseUrl(server), true);
            fail("expected IMDSv2-required failure");
        } catch (IllegalStateException expected) {
            assertTrue(expected.getMessage().contains("IMDSv2"));
            assertEquals(1, tokenPuts.get());
            assertEquals(0, unauthenticatedGets.get());
        } finally {
            server.stop(0);
        }
    }

    @Test
    public void ecsCredentialsRejectUnsafeRoleName() throws Exception {
        AtomicInteger tokenPuts = new AtomicInteger();
        AtomicInteger unauthenticatedGets = new AtomicInteger();
        HttpServer server = startMetadataServer(tokenPuts, unauthenticatedGets, true, "../evil");
        try {
            AlibabaCloudIdProvider.resolveEcsRamRoleCredentials(baseUrl(server), false);
            fail("expected invalid role name");
        } catch (IllegalStateException expected) {
            assertTrue(expected.getMessage().contains("role name"));
        } finally {
            server.stop(0);
        }
    }

    @Test
    public void ramRoleNameAllowsAliyunCharsetAndRejectsTraversal() {
        assertTrue(AlibabaCloudIdProvider.isSafeRamRoleName("AliyunECSDefaultRole"));
        assertTrue(AlibabaCloudIdProvider.isSafeRamRoleName("my-role_1"));
        assertFalse(AlibabaCloudIdProvider.isSafeRamRoleName("../secret"));
        assertFalse(AlibabaCloudIdProvider.isSafeRamRoleName("role/name"));
        assertFalse(AlibabaCloudIdProvider.isSafeRamRoleName(""));
        assertEquals("my-role", AlibabaCloudIdProvider.firstLine("my-role\nother"));
    }

    private static String signedCloudId(String region, String securityToken) throws Exception {
        AlibabaCloudIdProvider.AlibabaCredentials creds =
                new AlibabaCloudIdProvider.AlibabaCredentials("AKID", "SECRET", securityToken);
        return new AlibabaCloudIdProvider().getCloudId(creds, region, TEST_TIMESTAMP, TEST_NONCE);
    }

    private static String baseUrl(HttpServer server) {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    private static HttpServer startMetadataServer(AtomicInteger tokenPuts, AtomicInteger unauthenticatedGets,
                                                 boolean issueToken, String roleName) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext(AlibabaCloudIdProvider.ECS_IMDS_TOKEN_PATH, exchange -> {
            tokenPuts.incrementAndGet();
            if (!issueToken) {
                send(exchange, 404, "");
                return;
            }
            if (!"PUT".equals(exchange.getRequestMethod())) {
                send(exchange, 405, "");
                return;
            }
            String ttl = exchange.getRequestHeaders().getFirst(AlibabaCloudIdProvider.ECS_METADATA_TOKEN_TTL_HEADER);
            if (ttl == null || ttl.isEmpty()) {
                send(exchange, 400, "");
                return;
            }
            send(exchange, 200, "imds-token");
        });
        server.createContext("/latest/meta-data/ram/security-credentials", exchange -> {
            String token = exchange.getRequestHeaders().getFirst(AlibabaCloudIdProvider.ECS_METADATA_TOKEN_HEADER);
            if (token == null) {
                unauthenticatedGets.incrementAndGet();
                if (issueToken) {
                    send(exchange, 403, "");
                    return;
                }
            } else if (!"imds-token".equals(token)) {
                send(exchange, 401, "");
                return;
            }
            String path = exchange.getRequestURI().getPath();
            if (path.equals(AlibabaCloudIdProvider.ECS_RAM_CREDENTIALS_PATH)
                    || path.equals("/latest/meta-data/ram/security-credentials")) {
                send(exchange, 200, roleName);
                return;
            }
            if (path.equals(AlibabaCloudIdProvider.ECS_RAM_CREDENTIALS_PATH + roleName)) {
                send(exchange, 200,
                        "{\"AccessKeyId\":\"AKI\",\"AccessKeySecret\":\"SECRET\",\"SecurityToken\":\"TOK\"}");
                return;
            }
            send(exchange, 404, "");
        });
        server.start();
        return server;
    }

    private static void send(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    private static Map<String, String> query(String url) throws Exception {
        URI uri = new URI(url);
        Map<String, String> out = new TreeMap<String, String>();
        if (uri.getRawQuery() == null) {
            return out;
        }
        for (String pair : uri.getRawQuery().split("&")) {
            String[] parts = pair.split("=", 2);
            String key = java.net.URLDecoder.decode(parts[0], "UTF-8");
            String value = parts.length > 1 ? java.net.URLDecoder.decode(parts[1], "UTF-8") : "";
            out.put(key, value);
        }
        return out;
    }

    private static DecodedToken decode(String cloudId) throws Exception {
        assertFalse(cloudId.isEmpty());
        JsonNode root = MAPPER.readTree(new String(Base64.getDecoder().decode(cloudId), StandardCharsets.UTF_8));
        DecodedToken token = new DecodedToken();
        token.method = root.get("sts_request_method").asText();
        token.url = decodeField(root, "sts_request_url");
        token.body = decodeField(root, "sts_request_body");
        token.headers = MAPPER.readTree(decodeField(root, "sts_request_headers"));
        return token;
    }

    private static String decodeField(JsonNode root, String field) {
        return new String(Base64.getDecoder().decode(root.get(field).asText()), StandardCharsets.UTF_8);
    }

    private static final class DecodedToken {
        String method;
        String url;
        String body;
        JsonNode headers;

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
    }
}
