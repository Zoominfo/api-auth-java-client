package com.zoominfo.api.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class AuthClient {
    private static final String ENTERPRISE_API_AUDIENCE = "enterprise_api";
    private static final String USERNAME_CLAIM = "username";
    private static final String CLIENT_ID_CLAIM = "client_id";
    private static final String ISSUER = "api-client@zoominfo.com";
    private static final String AUTHENTICATE_URL = "https://api.zoominfo.com/authenticate";
    private static final int EXPIRY_TIME_SECONDS = 60 * 5;
    private boolean usernameAndPassword;
    private String username;
    private String password;
    private String clientId;
    private String privateKey;
    private final RestTemplate restTemplate;

    private AuthClient() {
        this.restTemplate = new RestTemplate();
    }

    public AuthClient(String username,
               String password) {
        this();
        usernameAndPassword = true;
        this.username = username;
        this.password = password;
    }

    public AuthClient( String username,
                String clientId,
                String privateKey) {
        this();
        this.usernameAndPassword = false;
        this.username = username;
        this.clientId = clientId;
        this.privateKey = privateKey;
    }

    public String getAccessToken() {
        if (this.usernameAndPassword) {
            return usernamePasswordAuthentication();
        } else {
            return pkiAuthentication();
        }
    }

    private String pkiAuthentication() {

        String clientJwt = getClientJwt();

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Authorization", "Bearer " + clientJwt);
        httpHeaders.add("Accept", "application/json");
        httpHeaders.add("user-agent", ""); // Without user-agent you will get 403 error

        HttpEntity<Map<String, Object>> request = new HttpEntity<>(null, httpHeaders);

        return postAndGetJwt(request);
    }

    private String usernamePasswordAuthentication() {

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Accept", "application/json");
        httpHeaders.add("user-agent", ""); // Without user-agent you will get 403 error

        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put("username", username);
        requestBody.put("password", password);

        HttpEntity<Map<String, Object>> request = new HttpEntity<>(requestBody, httpHeaders);

        return postAndGetJwt(request);
    }

    private String postAndGetJwt(HttpEntity<Map<String, Object>> request) {
        ResponseEntity<Map> responseEntity = restTemplate.postForEntity(AUTHENTICATE_URL, request, Map.class);

        if (responseEntity.getBody() == null) {
            throw new RuntimeException("Could not authenticate, empty response body");
        }

        return String.valueOf(responseEntity.getBody().get("jwt"));
    }


    private String getClientJwt() {
        String clientJWT = "";
        try {
            clientJWT = this.generateClientToken();
            return clientJWT;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    private String generateClientToken() throws NoSuchAlgorithmException, InvalidKeySpecException {
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.MINUTE, -2);
        Date issuedAtDate = cal.getTime();
        Date expiryDate = Date.from(issuedAtDate.toInstant().plusSeconds(EXPIRY_TIME_SECONDS));
        return JWT
                .create()
                .withAudience(ENTERPRISE_API_AUDIENCE)
                .withIssuer(ISSUER)
                .withClaim(USERNAME_CLAIM, username)
                .withClaim(CLIENT_ID_CLAIM, clientId)
                .withIssuedAt(issuedAtDate)
                .withExpiresAt(expiryDate)
                .sign(generateSigningAlgorithm(privateKey));
    }

    private Algorithm generateSigningAlgorithm(String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String cleanedPrivateKey = privateKey.replaceAll("-----END PRIVATE KEY-----", "")
                .replaceAll("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll("\n", "").trim();
        byte[] privateKeyBytes = Base64.getDecoder().decode(cleanedPrivateKey);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA")
                .generatePrivate(privateKeySpec);
        RSAKeyProvider keyProvider = new AuthClientRSAKeyProvider(rsaPrivateKey);
        return Algorithm.RSA256(keyProvider);
    }

    private static class AuthClientRSAKeyProvider implements RSAKeyProvider {
        private final RSAPrivateKey privateKey;

        public AuthClientRSAKeyProvider(RSAPrivateKey privateKey) {
            this.privateKey = privateKey;
        }

        @Override
        public RSAPublicKey getPublicKeyById(String keyId) {
            return null;
        }

        @Override
        public RSAPrivateKey getPrivateKey() {
            return this.privateKey;
        }

        @Override
        public String getPrivateKeyId() {
            return null;
        }
    }

}
