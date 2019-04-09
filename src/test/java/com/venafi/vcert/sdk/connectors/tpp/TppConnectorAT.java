package com.venafi.vcert.sdk.connectors.tpp;

import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.*;
import com.venafi.vcert.sdk.endpoint.Authentication;
import feign.FeignException;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.StringReader;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;

import static com.venafi.vcert.sdk.TestUtils.getTestIps;
import static java.lang.String.format;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TppConnectorAT {

    private TppConnector classUnderTest = new TppConnector(Tpp.connect(System.getenv("VENAFI_TPP_URL")));

    @BeforeEach
    void authenticate() throws VCertException {
        Security.addProvider(new BouncyCastleProvider());
        Authentication authentication = new Authentication(System.getenv("VENAFI_USER"), System.getenv("VENAFI_PASSWORD"), null);
        classUnderTest.authenticate(authentication);
    }

    @Test
    void readZoneConfiguration() throws VCertException {
        try {
            ZoneConfiguration zoneConfig = classUnderTest.readZoneConfiguration(System.getenv("VENAFI_ZONE"));
        } catch (FeignException fe) {
            throw VCertException.fromFeignException(fe);
        }
    }

    @Test
    void ping() throws VCertException {
        assertThatCode(() -> classUnderTest.ping()).doesNotThrowAnyException();
    }

    @Test
    void generateRequest() throws VCertException, IOException {
        String zone = System.getenv("VENAFI_ZONE");
        String commonName = System.getenv("VENAFI_CERT_COMMON_NAME");
        ZoneConfiguration zoneConfiguration = classUnderTest.readZoneConfiguration(zone);
        CertificateRequest certificateRequest = new CertificateRequest().subject(
                new CertificateRequest.PKIXName()
                        .commonName(commonName)
                        .organization(Collections.singletonList("Venafi, Inc."))
                        .organizationalUnit(Arrays.asList("Engineering", "Automated Tests"))
                        .country(Collections.singletonList("US"))
                        .locality(Collections.singletonList("SLC"))
                        .province(Collections.singletonList("Utah")))
                .dnsNames(Collections.singletonList(InetAddress.getLocalHost().getHostName()))
                .ipAddresses(getTestIps())
                .keyType(KeyType.RSA)
                .keyLength(2048);

        certificateRequest = classUnderTest.generateRequest(zoneConfiguration, certificateRequest);

        assertThat(certificateRequest.csr()).isNotEmpty();

        PKCS10CertificationRequest request = (PKCS10CertificationRequest) new PEMParser(new StringReader(new String(certificateRequest.csr()))).readObject();

        // Values overridden by policy which is why they don't match the above values
        String subject = request.getSubject().toString();

        assertThat(subject).contains(format("CN=%s", commonName));
        assertThat(subject).contains("O=Venafi");
        assertThat(subject).contains("OU=Engineering");
        assertThat(subject).contains("OU=Automated Tests");
        assertThat(subject).contains("C=GB");
        assertThat(subject).contains("L=Bracknell");
        assertThat(subject).contains("ST=Berkshire");
    }

    @Test
    void requestCertificate() throws VCertException, SocketException, UnknownHostException {
        String zone = System.getenv("VENAFI_ZONE");
        String commonName = System.getenv("VENAFI_CERT_COMMON_NAME");
        ZoneConfiguration zoneConfiguration = classUnderTest.readZoneConfiguration(zone);
        CertificateRequest certificateRequest = new CertificateRequest().subject(
                new CertificateRequest.PKIXName()
                        .commonName(commonName)
                        .organization(Collections.singletonList("Venafi"))
                        .organizationalUnit(Collections.singletonList("Demo"))
                        .country(Collections.singletonList("GB"))
                        .locality(Collections.singletonList("Bracknell"))
                        .province(Collections.singletonList("Berkshire")))
                .dnsNames(Collections.singletonList(InetAddress.getLocalHost().getHostName()))
                .ipAddresses(getTestIps())
                .keyType(KeyType.RSA)
                .keyLength(2048);

        certificateRequest = classUnderTest.generateRequest(zoneConfiguration, certificateRequest);
        String certificateId = classUnderTest.requestCertificate(certificateRequest, zone);
        assertThat(certificateId).isNotNull();
    }

    @Test
    void retrieveCertificate() throws VCertException, SocketException, UnknownHostException {
        String zone = System.getenv("VENAFI_ZONE");
        String commonName = System.getenv("VENAFI_CERT_COMMON_NAME");
        ZoneConfiguration zoneConfiguration = classUnderTest.readZoneConfiguration(zone);
        CertificateRequest certificateRequest = new CertificateRequest().subject(
                new CertificateRequest.PKIXName()
                        .commonName(commonName)
                        .organization(Collections.singletonList("Venafi"))
                        .organizationalUnit(Collections.singletonList("Demo"))
                        .country(Collections.singletonList("GB"))
                        .locality(Collections.singletonList("Bracknell"))
                        .province(Collections.singletonList("Berkshire")))
                .dnsNames(Collections.singletonList(InetAddress.getLocalHost().getHostName()))
                .ipAddresses(getTestIps())
                .keyType(KeyType.RSA)
                .keyLength(2048);

        certificateRequest = classUnderTest.generateRequest(zoneConfiguration, certificateRequest);
        String certificateId = classUnderTest.requestCertificate(certificateRequest, zone);
        assertThat(certificateId).isNotNull();

        PEMCollection pemCollection = classUnderTest.retrieveCertificate(certificateRequest);

        assertThat(pemCollection.certificate()).isNotNull();
        assertThat(pemCollection.chain()).hasSize(2);
        assertThat(pemCollection.privateKey()).isNull();
    }

    @Test
    void revokeCertificate() throws VCertException {
        assertThrows(UnsupportedOperationException.class, () -> {
            classUnderTest.revokeCertificate(new RevocationRequest());
        });
    }

    @Test
    void renewCertificate() throws VCertException, UnknownHostException, SocketException, CertificateException, NoSuchAlgorithmException {
        String zone = System.getenv("VENAFI_ZONE");
        String commonName = System.getenv("VENAFI_CERT_COMMON_NAME");
        ZoneConfiguration zoneConfiguration = classUnderTest.readZoneConfiguration(zone);
        CertificateRequest certificateRequest = new CertificateRequest().subject(
                new CertificateRequest.PKIXName()
                        .commonName(commonName)
                        .organization(Collections.singletonList("Venafi"))
                        .organizationalUnit(Collections.singletonList("Demo"))
                        .country(Collections.singletonList("GB"))
                        .locality(Collections.singletonList("Bracknell"))
                        .province(Collections.singletonList("Berkshire")))
                .dnsNames(Collections.singletonList(InetAddress.getLocalHost().getHostName()))
                .ipAddresses(getTestIps())
                .keyType(KeyType.RSA)
                .keyLength(2048);

        certificateRequest = classUnderTest.generateRequest(zoneConfiguration, certificateRequest);
        String certificateId = classUnderTest.requestCertificate(certificateRequest, zone);
        assertThat(certificateId).isNotNull();

        PEMCollection pemCollection = classUnderTest.retrieveCertificate(certificateRequest);
        X509Certificate cert = (X509Certificate) pemCollection.certificate();

        String thumbprint = DigestUtils.sha1Hex(cert.getEncoded()).toUpperCase();

        CertificateRequest certificateRequestToRenew = new CertificateRequest().subject(
                new CertificateRequest.PKIXName()
                        .commonName(commonName)
                        .organization(Collections.singletonList("Venafi"))
                        .organizationalUnit(Collections.singletonList("Demo"))
                        .country(Collections.singletonList("GB"))
                        .locality(Collections.singletonList("Bracknell"))
                        .province(Collections.singletonList("Berkshire")))
                .dnsNames(Collections.singletonList(InetAddress.getLocalHost().getHostName()))
                .ipAddresses(getTestIps())
                .keyType(KeyType.RSA)
                .keyLength(2048);
        classUnderTest.generateRequest(zoneConfiguration, certificateRequestToRenew);

        String renewRequestId = classUnderTest.renewCertificate(new RenewalRequest()
                .request(certificateRequestToRenew)
                .thumbprint(thumbprint));

        assertThat(renewRequestId).isNotNull();
    }

    @Test
    void importCertificate() {
        assertThrows(UnsupportedOperationException.class, () -> classUnderTest.importCertificate(new ImportRequest()));
    }

    @Test
    void readPolicyConfiguration() {
        assertThrows(UnsupportedOperationException.class, () -> classUnderTest.readPolicyConfiguration("zone"));
    }
}