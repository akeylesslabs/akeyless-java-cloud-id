package io.akeyless.cloudid;

import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.signer.Aws4Signer;
import software.amazon.awssdk.auth.signer.params.Aws4SignerParams;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpMethod;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.utils.StringInputStream;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

public class AwsCloudIdProvider implements CloudIdProvider{
    @Override
    public String getCloudId() throws Exception {
        AwsCredentialsProvider credentialsProvider = DefaultCredentialsProvider.create();
        AwsCredentials credentials = credentialsProvider.resolveCredentials();

        String body = "Action=GetCallerIdentity&Version=2011-06-15";

        SdkHttpFullRequest unsignedRequest = SdkHttpFullRequest.builder()
                .method(SdkHttpMethod.POST)
                .uri(URI.create("https://sts.amazonaws.com"))
                .encodedPath("/")
                .putHeader("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
                .putHeader("Content-Length", String.valueOf(body.length()))
                .contentStreamProvider(() -> new StringInputStream(body))
                .build();

        Aws4Signer signer = Aws4Signer.create();

        Aws4SignerParams signerParams = Aws4SignerParams.builder()
                .signingName("sts")
                .signingRegion(Region.US_EAST_1)
                .awsCredentials(credentials)
                .build();

        SdkHttpFullRequest signedRequest = signer.sign(unsignedRequest, signerParams);

        String signedHeadersJson = new ObjectMapper().writeValueAsString(signedRequest.headers());

        Map<String, String> awsData = new LinkedHashMap<>();
        awsData.put("sts_request_method", SdkHttpMethod.POST.name());
        awsData.put("sts_request_url", Base64.getEncoder().encodeToString("https://sts.amazonaws.com/".getBytes(StandardCharsets.UTF_8)));
        awsData.put("sts_request_body", Base64.getEncoder().encodeToString(body.getBytes(StandardCharsets.UTF_8)));
        awsData.put("sts_request_headers", Base64.getEncoder().encodeToString(signedHeadersJson.getBytes(StandardCharsets.UTF_8)));

        String awsDataJson = new ObjectMapper().writeValueAsString(awsData);
        return Base64.getEncoder().encodeToString(awsDataJson.getBytes(StandardCharsets.UTF_8));
    }
}
