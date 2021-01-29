package org.example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.gateway.dto.JWTInfoDto;
import org.wso2.carbon.apimgt.gateway.handlers.security.jwt.generator.APIMgtGatewayJWTGeneratorImpl;
import org.wso2.carbon.apimgt.gateway.handlers.security.jwt.generator.AbstractAPIMgtGatewayJWTGenerator;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.KeyStoreManager;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;

@Component(
        enabled = true,
        service = AbstractAPIMgtGatewayJWTGenerator.class,
        name = "APIMgtGatewayJWEGeneratorImpl"
)
public class APIMgtGatewayJWEGeneratorImpl extends APIMgtGatewayJWTGeneratorImpl {
    @Override
    public String generateToken(JWTInfoDto jwtInfoDto) throws APIManagementException {
        JWEAlgorithm alg = JWEAlgorithm.RSA_OAEP_256;
        EncryptionMethod enc = EncryptionMethod.A128CBC_HS256;
        String claimSet = super.buildBody(jwtInfoDto);
        //Generation of content encryption key
        KeyGenerator keyGen = null;
        try {
            keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey contentEncryptKey = keyGen.generateKey();

            JWEObject jwe = new JWEObject(new JWEHeader(alg, enc), new Payload(claimSet));
            jwe.encrypt(new RSAEncrypter(getPublicKey(), contentEncryptKey));
            return jwe.serialize();
        } catch (NoSuchAlgorithmException e) {
            throw new APIManagementException("No such Algorithm AES", e);
        } catch (JOSEException e) {
            throw new APIManagementException("Error while encrypting the token", e);
        }
    }

    private RSAPublicKey getPublicKey() throws APIManagementException {
        try {
            KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(MultitenantConstants.SUPER_TENANT_ID);
            return (RSAPublicKey) keyStoreManager.getDefaultPublicKey();
        } catch (Exception e) {
            throw new APIManagementException(e);
        }
    }
}