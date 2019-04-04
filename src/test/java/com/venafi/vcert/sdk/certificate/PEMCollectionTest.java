package com.venafi.vcert.sdk.certificate;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateException;

import static org.assertj.core.api.Assertions.assertThat;

class PEMCollectionTest {

    @Test
    void fromResponse() throws IOException, CertificateException {
        ClassLoader classLoader = getClass().getClassLoader();
        String body = new String(Files.readAllBytes(Paths.get(classLoader.getResource("certificates/certWithKey.pem").getPath())));
        PEMCollection pemCollection = PEMCollection.fromResponse(body, ChainOption.ChainOptionRootLast);
        assertThat(pemCollection.certificate()).isNotNull();
        assertThat(pemCollection.chain()).hasSize(1);
        assertThat(pemCollection.privateKey()).isNotNull();
    }
}