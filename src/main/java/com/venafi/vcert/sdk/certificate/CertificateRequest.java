package com.venafi.vcert.sdk.certificate;

import com.venafi.vcert.sdk.SignatureAlgorithm;
import lombok.Data;

import java.net.InetAddress;
import java.security.PrivateKey;
import java.time.Duration;
import java.util.Collection;
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
    private Collection<Byte> csr; // Todo revist
    private PrivateKey privateKey;
    private CsrOriginOption csrOrigin;
    private String pickupId;
    private ChainOption chainOption;
    private String keyPassword;
    private Boolean fetchPrivateKey;
    private String thumbprint;
    private Duration timeout;

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
