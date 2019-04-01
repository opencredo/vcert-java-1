package com.venafi.vcert.sdk.connectors.cloud;

import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.CertificateRequest;
import com.venafi.vcert.sdk.connectors.Connector;
import com.venafi.vcert.sdk.connectors.cloud.domain.UserDetails;
import com.venafi.vcert.sdk.connectors.tpp.ZoneConfiguration;
import com.venafi.vcert.sdk.endpoint.Authentication;
import lombok.Getter;

import java.util.Arrays;
import java.util.Collection;

import static java.lang.String.format;

public class CloudConnector implements Connector {

    private Cloud cloud;

    @Getter
    private UserDetails user;
    private Authentication auth;
    private String zone;

    CloudConnector(Cloud cloud) {
        this.cloud = cloud;
    }

    @Override
    public void setZone(String zone) {
        this.zone = zone;
    }

    @Override
    public void authenticate(Authentication auth) throws VCertException {
        VCertException.throwIfNull(auth, "failed to authenticate: missing credentials");
        this.auth = auth;
        this.user = cloud.authorize(auth.apiKey());
    }

    @Override
    public ZoneConfiguration readZoneConfiguration(String tag) throws VCertException {
        VCertException.throwIfNull(tag, "empty zone name");
        Zone zone = getZoneByTag(tag);
        CertificatePolicy policy = getPoliciesById(Arrays.asList(zone.defaultCertificateIdentityPolicy(), zone.defaultCertificateUsePolicy()));
        return zone.getZoneConfiguration(user, policy);
    }

    @Override
    public CertificateRequest generateRequest(ZoneConfiguration config, CertificateRequest request) throws VCertException {
        switch(request.csrOrigin()) {
            case LocalGeneratedCSR:
                if(config == null) {
                    config = readZoneConfiguration(zone);
                }
                config.validateCertificateRequest(request);
                config.updateCertificateRequest(request);
                request.generatePrivateKey();
                request.generateCSR();
                break;
            case UserProvidedCSR:
                break;
            case ServiceGeneratedCSR:
                break;
            default:
                throw new VCertException(format("Unreconginised request CSR origin %s", request.csrOrigin()));
        }

        return request;
    }

    private CertificatePolicy getPoliciesById(Collection<String> ids) throws VCertException {
        CertificatePolicy policy = new CertificatePolicy();
        VCertException.throwIfNull(user, "must be authenticated to read the zone configuration");
        for(String id : ids) {
            CertificatePolicy certificatePolicy = cloud.policyById(id, auth.apiKey());
            switch (certificatePolicy.certificatePolicyType()) {
                case "CERTIFICATE_IDENTITY": {
                    policy.subjectCNRegexes(certificatePolicy.subjectCNRegexes());
                    policy.subjectORegexes(certificatePolicy.subjectORegexes());
                    policy.subjectOURegexes(certificatePolicy.subjectOURegexes());
                    policy.subjectSTRegexes(certificatePolicy.subjectSTRegexes());
                    policy.subjectLRegexes(certificatePolicy.subjectLRegexes());
                    policy.subjectCRegexes(certificatePolicy.subjectCRegexes());
                    policy.sanRegexes(certificatePolicy.sanRegexes());
                    break;
                }
                case "CERTIFICATE_USE": {
                    policy.keyTypes(certificatePolicy.keyTypes());
                    policy.keyReuse(certificatePolicy.keyReuse());
                    break;
                }
                default: throw new IllegalArgumentException(format("unknown type %s", certificatePolicy.certificatePolicyType()));
            }
        }
        return policy;
    }

    private Zone getZoneByTag(String zone) throws VCertException {
        VCertException.throwIfNull(user, "must be authenticated to read the zone configuration");
        return cloud.zoneByTag(zone, auth.apiKey());
    }
}
