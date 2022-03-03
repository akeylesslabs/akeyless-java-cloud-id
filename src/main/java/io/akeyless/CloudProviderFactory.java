package io.akeyless;

import java.util.Objects;

public class CloudProviderFactory {
    public static CloudIdProvider getCloudIdProvider(String accType) throws RuntimeException {
        if (Objects.equals(accType, "aws_iam")) {
            return new AwsCloudIdProvider();
        } else if (Objects.equals(accType, "azure_ad")) {
            return new AzureCloudIdProvider();
        } else if (Objects.equals(accType, "gcp")) {
            return new GcpCloudIdProvider();
        }

        throw new RuntimeException("Unsupported type: " + accType);
    }
}
