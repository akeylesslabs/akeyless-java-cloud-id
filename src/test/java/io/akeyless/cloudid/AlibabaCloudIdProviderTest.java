package io.akeyless.cloudid;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Test;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

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

    private static String signedCloudId(String region, String securityToken) throws Exception {
        AlibabaCloudIdProvider.AlibabaCredentials creds =
                new AlibabaCloudIdProvider.AlibabaCredentials("AKID", "SECRET", securityToken);
        return new AlibabaCloudIdProvider().getCloudId(creds, region, TEST_TIMESTAMP, TEST_NONCE);
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
