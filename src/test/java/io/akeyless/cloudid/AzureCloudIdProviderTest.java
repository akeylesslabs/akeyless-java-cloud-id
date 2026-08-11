package io.akeyless.cloudid;

import com.azure.identity.DefaultAzureCredential;
import com.azure.identity.DefaultAzureCredentialBuilder;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Offline tests for {@link AzureCloudIdProvider}.
 *
 * <p>The provider obtains a token from {@code DefaultAzureCredential}, which requires
 * live Azure AD / IMDS access. Per the task constraints we do NOT drive a real token
 * fetch here; we only assert what is provable offline: that the provider is
 * constructible, is wired into the factory, and that the underlying Azure credential
 * builder used by {@code getCloudId()} constructs without any network call.
 */
public class AzureCloudIdProviderTest {

    @Test
    public void providerIsConstructibleAndImplementsInterface() {
        AzureCloudIdProvider provider = new AzureCloudIdProvider();
        assertNotNull(provider);
        assertTrue(provider instanceof CloudIdProvider);
    }

    @Test
    public void factoryReturnsAzureProvider() {
        CloudIdProvider provider = CloudProviderFactory.getCloudIdProvider("azure_ad");
        assertTrue(provider instanceof AzureCloudIdProvider);
    }

    @Test
    public void defaultAzureCredentialBuilderConstructsWithoutNetwork() {
        // Mirrors the credential construction performed inside getCloudId(). Building
        // the credential is a local operation; no token request is issued here.
        DefaultAzureCredential credential = new DefaultAzureCredentialBuilder().build();
        assertNotNull("DefaultAzureCredential should build offline", credential);
    }
}
