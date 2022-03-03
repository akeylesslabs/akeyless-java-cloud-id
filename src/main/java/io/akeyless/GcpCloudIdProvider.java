package io.akeyless;

import  com.google.auth.oauth2.IdToken;
import  com.google.auth.oauth2.IdTokenCredentials;
import  com.google.auth.oauth2.IdTokenProvider;
import  com.google.auth.oauth2.GoogleCredentials;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;

public class GcpCloudIdProvider implements CloudIdProvider{
    @Override
    public String getCloudId() throws Exception {
        GoogleCredentials credential = GoogleCredentials.getApplicationDefault();


        IdTokenCredentials tokenCredentials = IdTokenCredentials.newBuilder()
                .setIdTokenProvider((IdTokenProvider) credential)
                .setTargetAudience("akeyless.io")
                .setOptions(Arrays.asList(IdTokenProvider.Option.FORMAT_FULL, IdTokenProvider.Option.INCLUDE_EMAIL))
                .build();

        tokenCredentials.refresh();

        IdToken token = tokenCredentials.getIdToken();

        return Base64.getEncoder().encodeToString(token.getTokenValue().getBytes(StandardCharsets.UTF_8));
    }
}
