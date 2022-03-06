# akeyless-java-cloud-id

Akeyless CloudId Provider

The purpose of this package is to exteact the required "cloudid" to authenticate to akeyless using cloud authorization providers.

For more information, please visit [http://akeyless.io](http://akeyless.io)

## Publishing a new version
Tag the commit with a new tag and push to the repository.
The workflow will build and publish a new version to the artifactory repository.

## Requirements

Using the cloudid provider requires:
1. Java 1.8+
2. Maven/Gradle

## Installation

### Maven users

Add the following repository definition to your Maven settings file (default
`~/.m2/settings.xml`) or your POM file:

```xml
<repository>
    <id>central</id>
    <url>https://akeyless.jfrog.io/artifactory/akeyless-java</url>
    <snapshots><enabled>false</enabled></snapshots>
</repository>
```

Add this dependency to your project's POM:

```xml
<dependency>
  <groupId>io.akeyless</groupId>
  <artifactId>cloudid</artifactId>
  <version>Specify the CloudId package version here</version>
</dependency>
```
To use akeyless java sdk, you should also add:
```xml
 <dependency>
    <groupId>io.akeyless</groupId>
    <artifactId>akeyless-java</artifactId>
    <version>Specify the SDK version here</version>
</dependency>
```
 
## Getting Started

Please follow the [installation](#installation) instruction and execute the following Java code:

```java
import io.akeyless.client.ApiException;
import io.akeyless.cloudid.CloudProviderFactory;
import io.akeyless.cloudid.CloudIdProvider;

import io.akeyless.client.ApiClient;
import io.akeyless.client.Configuration;
import io.akeyless.client.model.*;
import io.akeyless.client.api.V2Api;

public class Main {
    public static void main(String[] argv) {
        // Use azure_ad/aws_iam/gcp, according to your cloud provider
        String accessType = "azure_ad";
        CloudIdProvider idProvider = CloudProviderFactory.getCloudIdProvider(accessType);
        try {
            String cloudId = idProvider.getCloudId();

            ApiClient client = Configuration.getDefaultApiClient();
            client.setBasePath("https://api.akeyless.io");

            V2Api api = new V2Api(client);
            Auth auth = new Auth();
            auth.accessId("<Your auth method access id>");
            auth.accessType(accessType);
            auth.cloudId(cloudId);

            AuthOutput result = api.auth(auth);


            ListItems listBody = new ListItems();
            listBody.setToken(result.getToken());
            ListItemsInPathOutput listOut = api.listItems(listBody);
            System.out.println(listOut.getItems().size());
        } catch (ApiException e) {
            System.err.println("Status code: " + e.getCode());
            System.err.println("Reason: " + e.getResponseBody());
            System.err.println("Response headers: " + e.getResponseHeaders());
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("Reason: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
 ```

## Author
support@akeyless.io

