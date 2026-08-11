package io.akeyless.cloudid;

import org.junit.Test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Offline tests for {@link GcpCloudIdProvider}.
 *
 * <p>{@code getCloudId()} relies on {@code GoogleCredentials.getApplicationDefault()}
 * and a live GCP identity-token exchange, which cannot be exercised hermetically.
 * We therefore only assert the offline-provable facts: the provider is constructible,
 * implements the common interface, and is wired into the factory. A real end-to-end
 * exchange is covered (credentials-gated) in {@link LiveCloudIdE2ETest}.
 */
public class GcpCloudIdProviderTest {

    @Test
    public void providerIsConstructibleAndImplementsInterface() {
        GcpCloudIdProvider provider = new GcpCloudIdProvider();
        assertNotNull(provider);
        assertTrue(provider instanceof CloudIdProvider);
    }

    @Test
    public void factoryReturnsGcpProvider() {
        CloudIdProvider provider = CloudProviderFactory.getCloudIdProvider("gcp");
        assertTrue(provider instanceof GcpCloudIdProvider);
    }
}
