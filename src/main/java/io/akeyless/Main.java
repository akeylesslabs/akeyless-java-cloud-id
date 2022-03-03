package io.akeyless;

public class Main {

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Please enter provider type");
            System.exit(1);
        }
        CloudIdProvider provider = CloudProviderFactory.getCloudIdProvider(args[0]);
        try {
            String cloudId = provider.getCloudId();
            System.out.println(cloudId);
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
    }
}
