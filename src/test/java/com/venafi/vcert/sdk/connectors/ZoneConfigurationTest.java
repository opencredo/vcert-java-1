package com.venafi.vcert.sdk.connectors;


import com.venafi.vcert.sdk.VCertException;
import org.junit.jupiter.api.Test;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;


public class ZoneConfigurationTest {

    @Test
    public void algos() {
        for (Provider provider : Security.getProviders()) {
            System.out.println("Provider: " + provider.getName() + " version: " + provider.getVersion());
            for (Provider.Service service : provider.getServices()) {
                System.out.printf("  Type : %-30s  Algorithm: %-30s\n", service.getType(), service.getAlgorithm());
            }
        }
        System.out.println("===");
        Provider[] providers = Security.getProviders(Collections.singletonMap("KeyFactory.RSA", ""));
        Arrays.stream(providers).forEach(System.out::println);
    }

    @Test
    void caseFolding() {
        String test = "Fußball";
        System.out.println(test.toUpperCase());
        System.out.println(test.toUpperCase().toLowerCase());
        String knowledge = "Wissen";
//        assertFalse(knowledge.toUpperCase().equals("Wißen".toUpperCase()));
    }

    @Test
    void test() throws NoSuchAlgorithmException {
        Provider[] providers = Security.getProviders(Collections.singletonMap("KeyFactory.RSA", ""));
        Provider provider = providers[0];
        provider.getService("KeyFactory", "RSA");

        KeyPairGenerator.getInstance("RSA");
    }

    @Test
    void eqNull() {
        System.out.println(null == null);
    }

}