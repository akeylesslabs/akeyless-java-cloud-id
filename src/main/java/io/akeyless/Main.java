package io.akeyless;

public class Main {

    public static void main(String[] args) {
        CloudIdProvider provider = CloudProviderFactory.getCloudIdProvider(args[1]);
        try {
            String cloudId = provider.getCloudId();
            System.out.println(cloudId);
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
    }
}
