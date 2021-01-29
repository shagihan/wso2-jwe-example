package com.example.sampleapi.utils;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.text.ParseException;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jwt.*;

public class JWEDecryptor {

    private static PrivateKey privateKey = null;

    public JWEDecryptor() {
        if (privateKey == null) {
            try {
                privateKey = getPrivateKey();
            } catch (KeyStoreException e) {
                e.printStackTrace();
            } catch (CertificateException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            } catch (UnrecoverableKeyException e) {
                e.printStackTrace();
            }
        }
    }

    public String getClaimSet(String jwe) throws ParseException, JOSEException {
        EncryptedJWT jwt = EncryptedJWT.parse(jwe);
        RSADecrypter decrypter = new RSADecrypter(privateKey);
        jwt.decrypt(decrypter);
        return jwt.getJWTClaimsSet().toJSONObject().toJSONString();
    }

    private PrivateKey getPrivateKey() throws KeyStoreException, CertificateException, NoSuchAlgorithmException,
            IOException, UnrecoverableKeyException {
        /*String keyStoreLocation = System.clearProperty("jks.location");
        String keyStorePassword = System.clearProperty("jks.password");
        String alias = System.clearProperty("jks.alias");
        String keyPassword = System.clearProperty("key.password");*/

        String keyStoreLocation = "/Users/user/.wum3/products/wso2am/3.2.0/full/wso2am-3.2.0/repository/resources/security/wso2carbon.jks";
        String keyStorePassword = "wso2carbon";
        String alias = "wso2carbon";
        String keyPassword = "wso2carbon";

        FileInputStream is = new FileInputStream(keyStoreLocation);
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(is, keyStorePassword.toCharArray());
        Key key = keystore.getKey(alias, keyPassword.toCharArray());
        return (PrivateKey) key;
    }
}
