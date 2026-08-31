package io.akeyless.cloudid;

import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public class AlibabaCloudIdProvider implements CloudIdProvider {
    static final String DEFAULT_REGION = "cn-hangzhou";
    static final String STS_DOMAIN = "sts.aliyuncs.com";
    static final String STS_API_VERSION = "2015-04-01";
    static final String STS_API_ACTION = "GetCallerIdentity";
    static final String STS_API_FORMAT = "JSON";
    static final String SIGNATURE_METHOD = "HMAC-SHA1";

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final DateTimeFormatter TIMESTAMP_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'").withZone(ZoneOffset.UTC);

    @Override
    public String getCloudId() throws Exception {
        AlibabaCredentials creds = resolveCredentials();
        String region = resolveRegion();
        if (region == null || region.isEmpty()) {
            region = DEFAULT_REGION;
        }
        return getCloudId(creds, region, TIMESTAMP_FMT.format(Instant.now()), randomNonce());
    }

    String getCloudId(AlibabaCredentials creds, String region, String timestamp, String nonce) throws Exception {
        if (region == null || region.isEmpty()) {
            region = DEFAULT_REGION;
        }
        if (creds.accessKeyId == null || creds.accessKeyId.isEmpty()
                || creds.accessKeySecret == null || creds.accessKeySecret.isEmpty()) {
            throw new IllegalStateException("alibaba credentials are missing access key id or secret");
        }

        Map<String, String> queryParams = new TreeMap<String, String>();
        queryParams.put("AccessKeyId", creds.accessKeyId);
        queryParams.put("Action", STS_API_ACTION);
        queryParams.put("Format", STS_API_FORMAT);
        queryParams.put("RegionId", region);
        queryParams.put("SignatureMethod", SIGNATURE_METHOD);
        queryParams.put("SignatureNonce", nonce);
        queryParams.put("SignatureType", "");
        queryParams.put("SignatureVersion", "1.0");
        queryParams.put("Timestamp", timestamp);
        queryParams.put("Version", STS_API_VERSION);
        if (creds.securityToken != null && !creds.securityToken.isEmpty()) {
            queryParams.put("SecurityToken", creds.securityToken);
        }

        String stringToSign = buildRpcStringToSign("POST", queryParams);
        queryParams.put("Signature", shaHmac1(stringToSign, creds.accessKeySecret + "&"));

        String requestUrl = "https://" + STS_DOMAIN + "/?" + encodeQueryParams(queryParams);

        Map<String, List<String>> headers = new LinkedHashMap<String, List<String>>();
        headers.put("Content-Type", Collections.singletonList("application/x-www-form-urlencoded"));
        headers.put("X-Acs-Action", Collections.singletonList(STS_API_ACTION));
        headers.put("X-Acs-Version", Collections.singletonList(STS_API_VERSION));

        Map<String, String> payload = new LinkedHashMap<String, String>();
        payload.put("sts_request_method", "POST");
        payload.put("sts_request_url", Base64.getEncoder().encodeToString(requestUrl.getBytes(StandardCharsets.UTF_8)));
        payload.put("sts_request_body", Base64.getEncoder().encodeToString(new byte[0]));
        payload.put("sts_request_headers", Base64.getEncoder().encodeToString(
                MAPPER.writeValueAsString(headers).getBytes(StandardCharsets.UTF_8)));

        return Base64.getEncoder().encodeToString(MAPPER.writeValueAsString(payload).getBytes(StandardCharsets.UTF_8));
    }

    static String buildRpcStringToSign(String method, Map<String, String> queryParams) throws Exception {
        String encoded = encodeQueryParams(queryParams);
        encoded = encoded.replace("+", "%20").replace("*", "%2A").replace("%7E", "~");
        return method + "&%2F&" + alibabaQueryEscape(encoded);
    }

    static String encodeQueryParams(Map<String, String> params) throws Exception {
        List<String> keys = new ArrayList<String>(params.keySet());
        Collections.sort(keys);
        StringBuilder out = new StringBuilder();
        for (String key : keys) {
            if (out.length() > 0) {
                out.append('&');
            }
            out.append(alibabaQueryEscape(key)).append('=').append(alibabaQueryEscape(params.get(key)));
        }
        return out.toString();
    }

    static String shaHmac1(String source, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA1"));
        return Base64.getEncoder().encodeToString(mac.doFinal(source.getBytes(StandardCharsets.UTF_8)));
    }

    static String alibabaQueryEscape(String value) throws Exception {
        return URLEncoder.encode(value, "UTF-8").replace("%7E", "~");
    }

    static String resolveRegion() {
        String[] keys = new String[]{"ALIBABA_CLOUD_REGION_ID", "ALIBABA_CLOUD_REGION", "REGION_ID"};
        for (String key : keys) {
            String value = System.getenv(key);
            if (value != null && !value.trim().isEmpty()) {
                return value.trim();
            }
        }
        return "";
    }

    static AlibabaCredentials resolveCredentials() throws Exception {
        String accessKeyId = firstEnv("ALIBABA_CLOUD_ACCESS_KEY_ID", "ALICLOUD_ACCESS_KEY");
        String accessKeySecret = firstEnv("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "ALICLOUD_SECRET_KEY");
        String securityToken = firstEnv("ALIBABA_CLOUD_SECURITY_TOKEN", "ALICLOUD_SECURITY_TOKEN");
        if (accessKeyId != null && !accessKeyId.isEmpty() && accessKeySecret != null && !accessKeySecret.isEmpty()) {
            return new AlibabaCredentials(accessKeyId, accessKeySecret, securityToken == null ? "" : securityToken);
        }
        return resolveEcsRamRoleCredentials();
    }

    private static AlibabaCredentials resolveEcsRamRoleCredentials() throws Exception {
        String roleName = httpGet("http://100.100.100.200/latest/meta-data/ram/security-credentials/");
        if (roleName == null || roleName.trim().isEmpty()) {
            throw new IllegalStateException("alibaba credentials are missing access key id or secret");
        }
        String body = httpGet("http://100.100.100.200/latest/meta-data/ram/security-credentials/" + roleName.trim());
        com.fasterxml.jackson.databind.JsonNode json = MAPPER.readTree(body);
        return new AlibabaCredentials(
                json.path("AccessKeyId").asText(),
                json.path("AccessKeySecret").asText(),
                json.path("SecurityToken").asText(""));
    }

    private static String httpGet(String url) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setConnectTimeout(2000);
        conn.setReadTimeout(2000);
        conn.setRequestMethod("GET");
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            return sb.toString();
        } finally {
            conn.disconnect();
        }
    }

    private static String firstEnv(String... keys) {
        for (String key : keys) {
            String value = System.getenv(key);
            if (value != null && !value.trim().isEmpty()) {
                return value.trim();
            }
        }
        return "";
    }

    private static String randomNonce() {
        byte[] buf = new byte[16];
        new SecureRandom().nextBytes(buf);
        StringBuilder hex = new StringBuilder(32);
        for (byte b : buf) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }

    static final class AlibabaCredentials {
        final String accessKeyId;
        final String accessKeySecret;
        final String securityToken;

        AlibabaCredentials(String accessKeyId, String accessKeySecret, String securityToken) {
            this.accessKeyId = accessKeyId;
            this.accessKeySecret = accessKeySecret;
            this.securityToken = securityToken;
        }
    }
}
