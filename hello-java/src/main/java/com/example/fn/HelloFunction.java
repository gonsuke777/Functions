package com.example.fn;

import com.oracle.bmc.Region;
import com.oracle.bmc.auth.BasicAuthenticationDetailsProvider;
import com.oracle.bmc.auth.ConfigFileAuthenticationDetailsProvider;
import com.oracle.bmc.auth.ResourcePrincipalAuthenticationDetailsProvider;
import com.oracle.bmc.secrets.SecretsClient;
import com.oracle.bmc.secrets.model.Base64SecretBundleContentDetails;
import com.oracle.bmc.secrets.requests.GetSecretBundleRequest;
import com.oracle.bmc.secrets.responses.GetSecretBundleResponse;
import org.apache.commons.codec.binary.Base64;
import java.io.IOException;
import java.util.Map;
import java.util.Date;
import java.util.HashMap;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fnproject.fn.api.FnConfiguration;
import com.fnproject.fn.api.RuntimeContext;

public class HelloFunction {
    private String secret1Id;
    private String secret2Id;
    private BasicAuthenticationDetailsProvider provider;
    private SecretsClient secretsClient;
    private Map<String, String> config;

    @FnConfiguration
    public void setUp(RuntimeContext ctx) throws Exception {
        config = ctx.getConfiguration();
        secret1Id = config.get("SECRET1_ID");
        String version = System.getenv("OCI_RESOURCE_PRINCIPAL_VERSION");
        if( version != null ) {
            provider = ResourcePrincipalAuthenticationDetailsProvider.builder().build();
        } else {
            try {
                provider = new ConfigFileAuthenticationDetailsProvider("~/.oci/config", "DEFAULT");
            }
            catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static class Input {
        public String type;
        public String token;
    }

    public static class Result {
        // required
        public boolean active;
        public String principal;
        public String[] scope;
        public String expiresAt;

        // optional
        public String wwwAuthenticate;

        // optional
        public String clientId;

        // optional
        public Map<String, Object> context;
    }

    public Result handleRequest(Input input) {
        String secret1 = getSecret(secret1Id);
        Result result = falseResult();

        if (input == null || input.type == null || !"TOKEN".equals(input.type.trim())) {
            result.wwwAuthenticate = "Bearer realm=\"example.com\", error=\"invalid type\", error_description=\"type must be provided and the value should be \"TOKEN\"\"";
            return result;
        }

        if (input.token == null || "".equals(input.token.trim())) {
            result.wwwAuthenticate = "Bearer realm=\"example.com\", error=\"invalid request\", error_description=\"missing token\"";
            return result;
        }

        if (secret1.equals(input.token)) {
            result = trueResult();
        } else {
            result.wwwAuthenticate = "Bearer realm=\"example.com\", error=\"invalid token\", error_description=\"token should be \"Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1nHyDtTwR3SEJ3z489...\"\"";
            return result;
        }
        return result;
    }

    private String getSecret(String secretOcid) {
        try (SecretsClient secretsClient = new SecretsClient(provider)) {
            //region setting
            secretsClient.setRegion(Region.AP_TOKYO_1);
            GetSecretBundleRequest getSecretBundleRequest = GetSecretBundleRequest
                .builder()
                .secretId(secretOcid)
                .stage(GetSecretBundleRequest.Stage.Current)
                .build();
            GetSecretBundleResponse getSecretBundleResponse = secretsClient
                .getSecretBundle(getSecretBundleRequest);
            Base64SecretBundleContentDetails base64SecretBundleContentDetails =
                (Base64SecretBundleContentDetails) getSecretBundleResponse.
                        getSecretBundle().getSecretBundleContent();
            byte[] secretValueDecoded = Base64.decodeBase64(base64SecretBundleContentDetails.getContent());
            return new String(secretValueDecoded);
        } catch (Exception e) {
            throw new RuntimeException("Couldn't get content from secret - " + e.getMessage(), e);
        }
    }

    private Result trueResult() {
        Result trueResult = new Result();
        trueResult.active = true;
        trueResult.principal = "https://example.com/users/jdoe";
        trueResult.scope = new String[]{"list:hello", "read:hello", "create:hello", "update:hello", "delete:hello", "someScope"};
        trueResult.clientId = "host123";
        trueResult.expiresAt = new Date().toInstant().plusMillis(60000).toString();
        Map<String, Object> contextMap = new HashMap<>();
        contextMap.put("email", "john.doe@example.com");
        trueResult.context = contextMap;
        return trueResult;
    }

    private Result falseResult() {
        Result falseResult = new Result();
        falseResult.active = false;
        falseResult.expiresAt = "2020-04-30T10:15:30+01:00";
        Map<String, Object> contextMap = new HashMap<>();
        contextMap.put("email", "john.doe@example.com");
        falseResult.context = contextMap;
        falseResult.wwwAuthenticate = "Bearer realm=\"example.com\"";
        return falseResult;
    }
}
