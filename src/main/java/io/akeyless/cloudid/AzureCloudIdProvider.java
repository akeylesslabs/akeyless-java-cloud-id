package io.akeyless.cloudid;

import com.azure.identity.DefaultAzureCredential;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenRequestContext;

import java.util.Collections;

import java.util.Base64;



public class AzureCloudIdProvider implements CloudIdProvider {
    @Override
    public String getCloudId() throws Exception {
       
       DefaultAzureCredential credential = new DefaultAzureCredentialBuilder().build();
        
        // Define the scope (for example, Azure Management)
        String scope = "https://management.azure.com/.default";

        try {
            // Request token
            AccessToken token = credential.getTokenSync(new TokenRequestContext()
                    .setScopes(Collections.singletonList(scope)));

            return Base64.getEncoder().encodeToString(token.getToken().getBytes());
        } catch (Exception e) {
            throw new Exception("Error finding access token in reponse");
        }
    }
}
