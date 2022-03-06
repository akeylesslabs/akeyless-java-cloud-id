package io.akeyless.cloudid;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Base64;

import com.fasterxml.jackson.core.*;

public class AzureCloudIdProvider implements CloudIdProvider {
    @Override
    public String getCloudId() throws Exception {
        URL msiEndpoint = new URL("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/");
        HttpURLConnection con = (HttpURLConnection) msiEndpoint.openConnection();
        con.setRequestMethod("GET");
        con.setRequestProperty("Metadata", "true");

        if (con.getResponseCode()!=200) {
            throw new Exception("Error calling managed identity token endpoint. Message: " + con.getResponseMessage());
        }

        InputStream responseStream = con.getInputStream();

        JsonFactory factory = new JsonFactory();
        JsonParser parser = factory.createParser(responseStream);
        JsonToken jsonToken;

        while((jsonToken = parser.nextToken()) != null){

            if(JsonToken.FIELD_NAME.equals(jsonToken)){
                String fieldName = parser.getCurrentName();

                if("access_token".equals(fieldName)){
                    parser.nextToken();
                    String accessToken = parser.getText();
                    return Base64.getEncoder().encodeToString(accessToken.getBytes());
                }
            }
        }
        throw new Exception("Error finind access token in reponse");
    }
}
