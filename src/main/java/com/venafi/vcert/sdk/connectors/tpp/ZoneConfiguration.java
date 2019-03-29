package com.venafi.vcert.sdk.connectors.tpp;

import com.venafi.vcert.sdk.SignatureAlgorithm;
import com.venafi.vcert.sdk.certificate.CertificateRequest;
import com.venafi.vcert.sdk.certificate.EllipticCurve;
import com.venafi.vcert.sdk.certificate.KeyType;
import com.venafi.vcert.sdk.connectors.Policy;
import com.venafi.vcert.sdk.endpoint.AllowedKeyConfiguration;
import com.venafi.vcert.sdk.utils.Is;
import lombok.Data;
import org.apache.logging.log4j.util.PropertySource;
import sun.security.rsa.RSAPublicKeyImpl;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Data
public class ZoneConfiguration {

    private String organization;
    private List<String> organizationalUnit;
    private String country;
    private String province;
    private String locality;
    private Policy policy = new Policy(); // Go merges the policy struct into the ZoneConfiguration one...

    private SignatureAlgorithm hashAlgorithm;

    private Map<String, String> customAttributeValues = new HashMap<>(); // Go SDK factory sets an empty map

    /**
     * UpdateCertificateRequest updates a certificate request based on the zone configurataion retrieved from the remote endpoint
     * @return
     */
    public void updateCertificateRequest(CertificateRequest request) {
        CertificateRequest.PKIXName subject = request.subject();

        subject.organization(Entity.of(subject.organization(), organization).resolve());
        if(Is.blank(subject.organizationalUnit()) && !Is.blank(organizationalUnit)) {
            subject.organizationalUnit(organizationalUnit);
        }
        subject.country(Entity.of(subject.country(), country).resolve());
        subject.province(Entity.of(subject.province(), province).resolve());
        subject.locality(Entity.of(subject.locality(), locality).resolve());
        if(hashAlgorithm != SignatureAlgorithm.UnknownSignatureAlgorithm) {
            request.signatureAlgorithm(hashAlgorithm);
        } else {
            request.signatureAlgorithm(SignatureAlgorithm.SHA256WithRSA);
        }

        if(!Is.blank(policy.allowedKeyConfigurations())) {
            boolean foundMatch = false;
            for(AllowedKeyConfiguration keyConf : policy.allowedKeyConfigurations()) {
                if(keyConf.keytype() == request.keyType()) {
                    foundMatch = true;
                    switch (request.keyType()) {
                        case ECDSA: {
                            if(!Is.blank(keyConf.keyCurves())) {
                                request.keyCurve(keyConf.keyCurves().get(0));
                            } else {
                                request.keyCurve(EllipticCurve.ellipticCurveDefault());
                            }
                            break;
                        }
                        case RSA: {
                            if(!Is.blank(keyConf.keySizes())) {
                                boolean sizeOK = false;
                                for(Integer size : keyConf.keySizes()) {
                                    if(size.equals(request.keyLength())) {
                                        sizeOK = true;
                                    }
                                }
                                if(!sizeOK) {
                                    List<Integer> reversedKeySizes = new ArrayList<>(keyConf.keySizes()); // not reversing the original
                                    reversedKeySizes.sort(Collections.reverseOrder());
                                    request.keyLength(reversedKeySizes.get(0));
                                }
                            } else {
                                request.keyLength(keyConf.keySizes().get(0));
                            }
                            break;
                        }
                    }
                }
            }
            if(!foundMatch) {
                AllowedKeyConfiguration configuration = policy.allowedKeyConfigurations().get(0);
                request.keyType(configuration.keytype());
                switch (request.keyType()) {
                    case ECDSA: {
                        if(!Is.blank(configuration.keyCurves())) {
                            request.keyCurve(configuration.keyCurves().get(0));
                        } else {
                            request.keyCurve(EllipticCurve.ellipticCurveDefault());
                        }
                        break;
                    }
                    case RSA: {
                        if(!Is.blank(configuration.keySizes())) {
                            List<Integer> reversedKeySizes = new ArrayList<>(configuration.keySizes());
                            reversedKeySizes.sort(Comparator.reverseOrder());
                            request.keyLength(reversedKeySizes.get(0));
                        } else {
                            request.keyLength(2048);
                        }
                        break;
                    }
                }
            }
        } else {
            // Zone config has no key length parameters, so we just pass user's -key-size or fall to default 2048
            if(KeyType.RSA.equals(request.keyType()) && (request.keyLength() == null || request.keyLength().equals(0))) {
                request.keyLength(2048);
            }
        }
    }

    private static class Entity {
        private List<String> target;
        private String source;

        private Entity() {

        }
        static Entity of(List<String> target, String source) {
            Entity entity = new Entity();
            entity.target = target;
            entity.source = source;
            return entity;
        }
        List<String> resolve() {
            if(Is.blank(target) && !Is.blank(source)) {
                return Collections.singletonList(source);
            } else if(!Is.blank(target) && !Is.equalsFold(target.get(0), source)) {
                return Collections.singletonList(source);
            }
            return target;
        }
    }
}


