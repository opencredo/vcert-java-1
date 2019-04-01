package com.venafi.vcert.sdk.certificate;

import com.venafi.vcert.sdk.SignatureAlgorithm;
import com.venafi.vcert.sdk.VCertException;
import lombok.Data;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.X509Principal;
import sun.misc.BASE64Encoder;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Collection;
import java.util.List;

import static java.lang.String.format;

@Data
public class CertificateRequest {
    private PKIXName subject; // TODO change to X500Name
    private Collection<String> dnsNames;
    private Collection<String> emailAddresses;
    private Collection<InetAddress> ipAddresses;
    private Collection<AttributeTypeAndValueSET> attributes;
    private SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.UnknownSignatureAlgorithm;
    private PublicKeyAlgorithm publicKeyAlgorithm = PublicKeyAlgorithm.Unknown;
    private String friendlyName;
    private KeyType keyType;
    private int keyLength;
    private EllipticCurve keyCurve;
    private byte[] csr;
    private KeyPair keyPair;
    private CsrOriginOption csrOrigin;
    private String pickupId;
    private ChainOption chainOption;
    private String keyPassword;
    private Boolean fetchPrivateKey;
    private String thumbprint;
    private Duration timeout;

    public void generatePrivateKey() throws VCertException {
        if(keyPair != null) {
            return;
        }
        switch(keyType) {
            case ECDSA: {
                keyPair = generateECDSAKeyPair(keyCurve);
                break;
            }
            case RSA: {
                if(keyLength == 0) {
                    keyLength = KeyType.defaultRsaLength();
                }
                keyPair = generateRSAKeyPair(keyLength);
                break;
            }
            default:
                throw new VCertException(format("Unable to generate certificate request, key type %s is not supported", keyType.name()));
        }
    }

    public void generateCSR() throws VCertException {
        try {
            PKCS10CertificationRequest certificationRequest = new PKCS10CertificationRequest(
                    signatureAlgorithm.standardName(),
                    subject.toX500Principal(),
                    keyPair.getPublic(),
                    null,
                    keyPair.getPrivate());

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            BASE64Encoder base64Encoder = new BASE64Encoder();
            outputStream.write("-----BEGIN CERTIFICATE REQUEST-----".getBytes());
            outputStream.write(System.lineSeparator().getBytes());
            base64Encoder.encodeBuffer(certificationRequest.getEncoded(), outputStream);
            outputStream.write("-----END CERTIFICATE REQUEST-----".getBytes());
            csr = outputStream.toByteArray();
        } catch(Exception e) {
            throw new VCertException("Unable to generate CSR", e);
        }
    }

    private KeyPair generateECDSAKeyPair(EllipticCurve keyCurve) throws VCertException {
        throw new UnsupportedOperationException("Yet to implement key generation based on elliptic curves");
    }

    private KeyPair generateRSAKeyPair(Integer keyLength) throws VCertException {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(keyLength);
            return keyPairGenerator.generateKeyPair();
        } catch(NoSuchAlgorithmException e) {
            throw new VCertException("No security provider found for KeyFactory.RSA", e);
        }
    }

    @Data
    public static class PKIXName {
        private String commonName;
        private String serialNumber;
        private List<String> country;
        private List<String> organization;
        private List<String> organizationalUnit;
        private List<String> locality;
        private List<String> province;
        private List<String> streetAddress;
        private List<String> postalCode;

        private Collection<AttributeTypeAndValue> names;
        private Collection<AttributeTypeAndValue> extraNames;

        public X500Principal toX500Principal() {
            X500NameBuilder x500NameBuilder = new X500NameBuilder();
            x500NameBuilder.addRDN(BCStyle.CN, commonName);
            for(String org : organization) {
                x500NameBuilder.addRDN(BCStyle.O, org);
            }
            return new X500Principal(x500NameBuilder.build().toString());
        }
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
