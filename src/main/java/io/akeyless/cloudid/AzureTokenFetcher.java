package io.akeyless.cloudid;

public class AzureTokenFetcher {
    public static void main(String[] args) {
        try {
        CloudIdProvider p = new AzureCloudIdProvider();
        System.out.println(p.getCloudId());
        }
        catch (Exception e) {
            System.out.println(e);
        }
    }
}