package providers;

import com.auth0.jwt.interfaces.RSAKeyProvider;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class AuthClientRSAKeyProvider implements RSAKeyProvider {
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
