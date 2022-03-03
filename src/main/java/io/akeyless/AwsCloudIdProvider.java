package io.akeyless;

import com.amazonaws.DefaultRequest;
import com.amazonaws.auth.AWS4Signer;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.http.HttpMethodName;
import com.amazonaws.regions.Regions;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpHeaders;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

public class AwsCloudIdProvider implements CloudIdProvider{
    @Override
    public String getCloudId() throws Exception {
        AWSCredentialsProvider credentialsProvider = DefaultAWSCredentialsProviderChain.getInstance();
        AWSCredentials credentials = credentialsProvider.getCredentials();

        DefaultRequest<String> request = new DefaultRequest<>("sts");

        String body = "Action=GetCallerIdentity&Version=2011-06-15";
        request.setContent(new ByteArrayInputStream(body.getBytes()));

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put(HttpHeaders.CONTENT_LENGTH, "" + body.length());
        headers.put(HttpHeaders.CONTENT_TYPE,"application/x-www-form-urlencoded; charset=utf-8");
        request.setHeaders(headers);

        request.setHttpMethod(HttpMethodName.POST);
        request.setEndpoint(URI.create("https://sts.amazonaws.com"));

        AWS4Signer signer = new AWS4Signer();
        signer.setServiceName("sts");

        signer.sign(request, credentials);

        Map<String, String> signedHeaders = request.getHeaders();
        Map<String, String[]> signedHeadersArr = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry: signedHeaders.entrySet()
             ) {
            signedHeadersArr.put(entry.getKey(), new String[] {entry.getValue()});
        }


        String signedHeadersJson = new ObjectMapper().writeValueAsString(signedHeadersArr);

        Map<String, String> awsData = new LinkedHashMap<>();
        awsData.put("sts_request_method", String.valueOf(HttpMethodName.POST));
        awsData.put("sts_request_url", Base64.getEncoder().encodeToString("https://sts.amazonaws.com/".getBytes(StandardCharsets.UTF_8)));
        awsData.put("sts_request_body", Base64.getEncoder().encodeToString(body.getBytes(StandardCharsets.UTF_8)));
        awsData.put("sts_request_headers", Base64.getEncoder().encodeToString(signedHeadersJson.getBytes(StandardCharsets.UTF_8)));

        String awsDataJson = new ObjectMapper().writeValueAsString(awsData);
        return Base64.getEncoder().encodeToString(awsDataJson.getBytes(StandardCharsets.UTF_8));
    }
}
