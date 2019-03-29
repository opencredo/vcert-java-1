package com.venafi.vcert.sdk.connectors.tpp;

import com.venafi.vcert.sdk.SignatureAlgorithm;
import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.CertificateRequest;
import com.venafi.vcert.sdk.connectors.Policy;
import com.venafi.vcert.sdk.endpoint.AllowedKeyConfiguration;
import lombok.Data;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

@Data
// TODO mvoe up one package
public class ZoneConfiguration {

    private String organization;
    private Collection<String> organizationalUnit;
    private String country;
    private String province;
    private String locality;
    private Policy policy;

    private SignatureAlgorithm hashAlgorithm;

    private Map<String, String> customAttributeValues;

    public boolean validateCertificateRequest(CertificateRequest request) throws VCertException {
        if(!isComponentValid(policy.subjectCNRegexes(), Collections.singletonList(request.subject().commonName()))) {
            throw new VCertException("The requested CN does not match any of the allowed CN regular expressions");
        }
        if(!isComponentValid(policy.subjectORegexes(), request.subject().organization())) {
            throw new VCertException("The requested Organization does not match any of the allowed Organization regular expressions");
        }
        if(!isComponentValid(policy.subjectOURegexes(), request.subject().organizationalUnit())) {
            throw new VCertException("The requested Organizational Unit does not match any of the allowed Organization Unit regular expressions");
        }
        if(!isComponentValid(policy.subjectSTRegexes(), request.subject().province())) {
            throw new VCertException("The requested State/Province does not match any of the allowed State/Province regular expressions");
        }
        if(!isComponentValid(policy.subjectLRegexes(), request.subject().locality())) {
            throw new VCertException("The requested Locality does not match any of the allowed Locality regular expressions");
        }
        if(!isComponentValid(policy.subjectCRegexes(), request.subject().country())) {
            throw new VCertException("The requested Country does not match any of the allowed Country regular expressions");
        }
        if(!isComponentValid(policy.dnsSanRegExs(), request.dnsNames())) {
            throw new VCertException("The requested Subject Alternative Name does not match any of the allowed Country regular expressions");
        }
        //todo: add ip, email and over cheking

        List<AllowedKeyConfiguration> allowedKeyConfigurations = policy.allowedKeyConfigurations();
        if(allowedKeyConfigurations != null && allowedKeyConfigurations.size() > 0) {
            boolean match = false;
            for(AllowedKeyConfiguration keyConfiguration : allowedKeyConfigurations) {
                if(keyConfiguration.keyType() == request.keyType()) {
                    if(request.keyLength() > 0) {
                        for(Integer size : keyConfiguration.keySizes()) {
                            if(size.equals(request.keyLength())) {
                                return true;
                            }
                        }
                    }
                    return true;
                }
            }
            throw new VCertException("The requested Key Type and Size do not match any of the allowed Key Types and Sizes");
        }

        return true;
    }

    private boolean isComponentValid(Collection<String> regexes, Collection<String> components) {
        if(regexes.size() == 0 && components.size() == 0) {
            return true;
        }

        for(String regex : regexes) {
            Pattern pattern;
            try {
                pattern = Pattern.compile(regex);
            } catch(PatternSyntaxException e) {
                // TODO log error
                return false;
            }
            for(String component : components) {
                Matcher m = pattern.matcher(component);
                if(m.matches()) {
                    return true;
                }
            }
        }
        return false;
    }
}


