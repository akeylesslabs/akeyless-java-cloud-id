package io.akeyless.cloudid;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Hermetic tests for {@link CloudProviderFactory} dispatch logic.
 * These tests never touch the network or real credentials; they only assert
 * that the factory maps access-type strings to the correct provider class and
 * rejects everything else.
 */
public class CloudProviderFactoryTest {

    @Test
    public void mapsAwsIamToAwsProvider() {
        CloudIdProvider provider = CloudProviderFactory.getCloudIdProvider("aws_iam");
        assertNotNull(provider);
        assertTrue("expected an AwsCloudIdProvider", provider instanceof AwsCloudIdProvider);
        assertTrue("provider must implement CloudIdProvider", provider instanceof CloudIdProvider);
    }

    @Test
    public void mapsAzureAdToAzureProvider() {
        CloudIdProvider provider = CloudProviderFactory.getCloudIdProvider("azure_ad");
        assertNotNull(provider);
        assertTrue("expected an AzureCloudIdProvider", provider instanceof AzureCloudIdProvider);
    }

    @Test
    public void mapsGcpToGcpProvider() {
        CloudIdProvider provider = CloudProviderFactory.getCloudIdProvider("gcp");
        assertNotNull(provider);
        assertTrue("expected a GcpCloudIdProvider", provider instanceof GcpCloudIdProvider);
    }

    @Test
    public void mapsAlicloudToAlibabaProvider() {
        CloudIdProvider provider = CloudProviderFactory.getCloudIdProvider("alicloud");
        assertNotNull(provider);
        assertTrue("expected an AlibabaCloudIdProvider", provider instanceof AlibabaCloudIdProvider);
    }

    @Test
    public void returnsFreshInstanceEachCall() {
        CloudIdProvider first = CloudProviderFactory.getCloudIdProvider("aws_iam");
        CloudIdProvider second = CloudProviderFactory.getCloudIdProvider("aws_iam");
        assertNotSame("factory must not cache/share provider instances", first, second);
    }

    @Test
    public void rejectsUnknownType() {
        try {
            CloudProviderFactory.getCloudIdProvider("kubernetes");
            fail("expected RuntimeException for unsupported type");
        } catch (RuntimeException e) {
            assertEquals("Unsupported type: kubernetes", e.getMessage());
        }
    }

    @Test
    public void rejectsEmptyType() {
        try {
            CloudProviderFactory.getCloudIdProvider("");
            fail("expected RuntimeException for empty type");
        } catch (RuntimeException e) {
            assertEquals("Unsupported type: ", e.getMessage());
        }
    }

    @Test
    public void rejectsNullType() {
        try {
            CloudProviderFactory.getCloudIdProvider(null);
            fail("expected RuntimeException for null type");
        } catch (RuntimeException e) {
            assertEquals("Unsupported type: null", e.getMessage());
        }
    }

    @Test
    public void typeMatchIsCaseSensitive() {
        // The factory uses exact string equality, so a differently-cased value
        // must be rejected rather than silently mapped.
        try {
            CloudProviderFactory.getCloudIdProvider("AWS_IAM");
            fail("expected RuntimeException for wrong-case type");
        } catch (RuntimeException e) {
            assertEquals("Unsupported type: AWS_IAM", e.getMessage());
        }
    }
}
