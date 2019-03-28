package com.venafi.vcert.sdk.certificate;

import com.venafi.vcert.sdk.SignatureAlgorithm;
import lombok.Data;

import java.net.InetAddress;
import java.security.PrivateKey;
import java.time.Duration;
import java.util.Collection;

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
    private static class PKIXName {
        private Collection<String> Country;
        private Collection<String> Organization;
        private Collection<String> OrganizationalUnit;
        private Collection<String> Locality;
        private Collection<String> Province;
        private Collection<String> StreetAddress;
        private Collection<String> PostalCode;
        private String SerialNumber;
        private String CommonName;

        private Collection<AttributeTypeAndValue> names;
        private Collection<AttributeTypeAndValue> extraNames;
    }

    // Todo do we need this?
    @Data
    private static class AttributeTypeAndValue {
        private Collection<Integer> type;
        private Object value;
    }

    // Todo do we need this?
    @Data
    private static class AttributeTypeAndValueSET {
        private Collection<Integer> type;
        private Collection<Collection<AttributeTypeAndValue>> value;
    }
}
