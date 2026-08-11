package io.akeyless.cloudid;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeNotNull;

/**
 * Credentials-gated, live-cloud end-to-end tests.
 *
 * <p>Every test here is SKIPPED (via JUnit {@code Assume}) unless the corresponding
 * real cloud credentials are present in the environment. This means the class is
 * always safe to run in CI with no secrets — it simply reports the tests as skipped —
 * yet it exercises the real provider flow whenever credentials are available.
 *
 * <p>Gating environment variables:
 * <ul>
 *   <li>AWS   - {@code AWS_ACCESS_KEY_ID}</li>
 *   <li>Azure - {@code AZURE_CLIENT_ID}</li>
 *   <li>GCP   - {@code GOOGLE_APPLICATION_CREDENTIALS}</li>
 * </ul>
 */
public class LiveCloudIdE2ETest {

    private static void assertNonEmptyBase64(String cloudId) {
        assertNotNull("cloud id must not be null", cloudId);
        assertTrue("cloud id must not be empty", cloudId.length() > 0);
        // Must be valid base64 (throws IllegalArgumentException otherwise).
        byte[] decoded = Base64.getDecoder().decode(cloudId);
        assertTrue("decoded cloud id must not be empty",
                new String(decoded, StandardCharsets.UTF_8).length() > 0);
    }

    @Test
    public void awsLiveGetCloudId() throws Exception {
        assumeNotNull(System.getenv("AWS_ACCESS_KEY_ID"));
        String cloudId = CloudProviderFactory.getCloudIdProvider("aws_iam").getCloudId();
        assertNonEmptyBase64(cloudId);
    }

    @Test
    public void azureLiveGetCloudId() throws Exception {
        assumeNotNull(System.getenv("AZURE_CLIENT_ID"));
        String cloudId = CloudProviderFactory.getCloudIdProvider("azure_ad").getCloudId();
        assertNonEmptyBase64(cloudId);
    }

    @Test
    public void gcpLiveGetCloudId() throws Exception {
        assumeNotNull(System.getenv("GOOGLE_APPLICATION_CREDENTIALS"));
        String cloudId = CloudProviderFactory.getCloudIdProvider("gcp").getCloudId();
        assertNonEmptyBase64(cloudId);
    }
}
