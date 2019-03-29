package com.venafi.vcert.sdk.certificate;

import com.venafi.vcert.sdk.SignatureAlgorithm;
import com.venafi.vcert.sdk.VCertException;
import lombok.Data;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

import java.math.BigInteger;
import java.net.InetAddress;
import java.security.*;
import java.time.Duration;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

@Data
public class CertificateRequest {
    private PKIXName subject;
    private Collection<String> dnsNames;
    private Collection<String> emailAddresses;
    private Collection<InetAddress> ipAddresses;
    private Collection<AttributeTypeAndValueSET> attributes;
    private SignatureAlgorithm signatureAlgorithm;
    private PublicKeyAlgorithm publicKeyAlgorithm;
    private String friendlyName;
    private KeyType keyType;
    private Integer keyLength;
    private EllipticCurve keyCurve;
    private Collection<Byte> csr; // Todo revisit
    private PrivateKey privateKey;
    private CsrOriginOption csrOrigin;
    private String pickupId;
    private ChainOption chainOption;
    private String keyPassword;
    private Boolean fetchPrivateKey;
    private String thumbprint;
    private Duration timeout;

    public void generatePrivateKey() throws VCertException {
        if(privateKey != null) {
            return;
        }
        switch (keyType) {
            case ECDSA: {
                privateKey = generateECDSAPrivateKey(keyCurve);
                break;
            }
            case RSA: {
                if(keyLength == 0) {
                    keyLength = KeyType.defaultRsaLength();
                    break;
                }
                privateKey = generateRSAPrivateKey(keyLength);
            }
            default: throw new VCertException(String.format("Unable to generate certificate request, key type %s is not supported", keyType.name()));
        }
    }

    private PrivateKey generateECDSAPrivateKey(EllipticCurve keyCurve) throws VCertException {
        throw new UnsupportedOperationException("Yet to implement key generation based on elliptic curves");
    }

    private PrivateKey generateRSAPrivateKey(Integer keyLength) throws VCertException {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(keyLength);
            return keyPairGenerator.generateKeyPair().getPrivate();
        } catch(NoSuchAlgorithmException e) {
            throw new VCertException("No security provider found for KeyFactory.RSA", e);
        }
    }

    @Data
    public static class PKIXName {
        private List<String> country;
        private List<String> organization;
        private List<String> organizationalUnit;
        private List<String> locality;
        private List<String> province;
        private List<String> streetAddress;
        private List<String> postalCode;
        private String serialNumber;
        private String commonName;

        private Collection<AttributeTypeAndValue> names;
        private Collection<AttributeTypeAndValue> extraNames;
    }

    // Todo do we need this?
    @Data
    public static class AttributeTypeAndValue {
        private Collection<Integer> type;
        private Object value;
    }

    // Todo do we need this?
    @Data
    public static class AttributeTypeAndValueSET {
        private Collection<Integer> type;
        private Collection<Collection<AttributeTypeAndValue>> value;
    }
}
