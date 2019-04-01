package com.venafi.vcert.sdk.certificate;

import com.venafi.vcert.sdk.SignatureAlgorithm;
import com.venafi.vcert.sdk.VCertException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemReader;
import org.junit.jupiter.api.Test;
import sun.misc.BASE64Decoder;
import sun.security.x509.X509CertImpl;

import java.io.IOException;
import java.io.StringReader;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

class CertificateRequestTest {

    @Test
    void generateCSR() throws IOException, VCertException, CertificateException {
        Security.addProvider(new BouncyCastleProvider());

        Collection<InetAddress> ips = new ArrayList<>();
        for(NetworkInterface networkInterface : Collections.list(NetworkInterface.getNetworkInterfaces())) {
            for(InetAddress inetAddress : Collections.list(networkInterface.getInetAddresses())) {
                if(!inetAddress.isLoopbackAddress()) {
                    ips.add(inetAddress);
                }
            }
        }

        CertificateRequest certificateRequest = new CertificateRequest().subject(
                new CertificateRequest.PKIXName()
                        .commonName("vcert.test.vfidev.com")
                        .organization(Collections.singletonList("Venafi, Inc."))
                        .organizationalUnit(Arrays.asList("Engineering", "Automated Tests"))
                        .country(Collections.singletonList("US"))
                        .locality(Collections.singletonList("SLC"))
                        .province(Collections.singletonList("Utah")))
                .dnsNames(Collections.singletonList(InetAddress.getLocalHost().getHostName()))
                .ipAddresses(ips);

        certificateRequest.keyType(KeyType.RSA);
        certificateRequest.signatureAlgorithm(SignatureAlgorithm.SHA256WithRSA);

        certificateRequest.generatePrivateKey();
        certificateRequest.generateCSR();

        PKCS10CertificationRequest cert = null;
        StringReader reader = new StringReader(new String(certificateRequest.csr()));
        PEMParser pemParser = new PEMParser(reader);
        cert = (PKCS10CertificationRequest)pemParser.readObject();
        pemParser.close();

        assertThat(cert.getSubject().toString()).isEqualTo("O=Venafi\\, Inc.,CN=vcert.test.vfidev.com");
    }

    @Test
    void decodebase64() throws IOException {
        String cert = "MIICUjCCAToCAQAwDzENMAsGA1UEAxMERnJlZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIoagFvcRevza6RjAPkGslFSd4cj5+BoavBs96O/RT0/a76noLXwulsJFo5t0oF+tz3YCqEbOPPSnvh8PN9kBC/lNoBAXQm69hJ0kOcAEqnGKhLOiOH7vTgRTG9SQ7Aan/3FciaFy9fboY0Tq4vB5N4Ts5w64Pg+Xkl3ikBQhYoYhUwId0g2kxKFkU5gUBmIjhm0a8LwJhnPZ6GJNZZBIregrdri2oCF3P0FIBgmALyqLwub8xN8jxzLO5fYQjJ8vorRtBmOvfshzJHDEjndx/HgZxR5YgSxGWsywcGuyBJZJBnoVi4DcfW0xdMH6g9irtz5pEPYxsBxseQv5ZGM27MCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAR9C3rnnhGa2ng9GG1lJjIxMCG4U+BFUb24scymjc0anAo73eII5G6FUgQJS9SQGaAU3U1W5k4Gt1Ashai+IkXd3b3mie6Mm7PjVe9Txc4BAFJ8kw5B7bFrp42/IezTQK9Z8tJn0TI/pE9EmR7wxTDAuSaa9yvsvdiB4Vg+bk/YEzts8phX4wl191Y2LlfpiA6sTgw4+3CyTwUWqwMaMZV4/bg7xJ+XteplT5N8VUIMemNUmFp4qCSSvTqE5tp12eY95iEgpkIKZBmQ/+ju/zcbhANuyvZ5nwPx6iA0W5rubeSubDA8fuF/398U+j2Y+ffRrlIUG6oEiZLJFDb3m2jg==";

        BASE64Decoder base64Decoder = new BASE64Decoder();
        System.out.println(new String(base64Decoder.decodeBuffer(cert)));
    }
}


//    func TestGenerateCertificateRequestWithRSAKey(t *testing.T) {
//        req := getCertificateRequestForTest()
//        var err error
//        req.PrivateKey, err = GenerateRSAPrivateKey(512)
//        if err != nil {
//            t.Fatalf("Error generating RSA Private Key\nError: %s", err)
//        }
//
//        err = req.GenerateCSR()
//        if err != nil {
//            t.Fatalf("Error generating Certificate Request\nError: %s", err)
//        }
//
//        pemBlock, _ := pem.Decode(req.CSR)
//        if pemBlock == nil {
//            t.Fatalf("Failed to decode CSR as PEM")
//        }
//
//        parsedReq, err := x509.ParseCertificateRequest(pemBlock.Bytes)
//        if err != nil {
//            t.Fatalf("Error parsing generated Certificate Request\nError: %s", err)
//        }
//
//        err = parsedReq.CheckSignature()
//        if err != nil {
//            t.Fatalf("Error checking signature of generated Certificate Request\nError: %s", err)
//        }
//    }