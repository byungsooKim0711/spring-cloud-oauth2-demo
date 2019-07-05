package org.kimbs.oauth2.security;

import org.springframework.stereotype.Component;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;


@Component
public class SecretKeyProvider {

    public String getKey() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        return new String(getKeyPair().getPublic().getEncoded(), "UTF-8");
    }

    public KeyPair getKeyPair() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        FileInputStream fileInputStream = new FileInputStream("myKeys.jks");

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(fileInputStream, "myPass".toCharArray());

        String alias = "myKeys";

        Key key = keyStore.getKey(alias, "myPass".toCharArray());
        if (key instanceof PrivateKey) {
            // Get certificate of public key
            Certificate certificate = keyStore.getCertificate(alias);

            // Get public key
            PublicKey publicKey = certificate.getPublicKey();

            // Return a key pair
            return new KeyPair(publicKey, (PrivateKey)key);
        } else {
            throw new UnrecoverableKeyException();
        }
    }
}
