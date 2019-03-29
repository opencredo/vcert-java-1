package com.venafi.vcert.sdk;

public enum SignatureAlgorithm {

    UnknownSignatureAlgorithm(""),
    MD2withRSA("MD2withRSA"),

    MD5WithRSA("MD5withRSA"),
    SHA1WithRSA("SHA1withRSA"),
    SHA256WithRSA("SHA256withRSA"),
    SHA384WithRSA("SHA384withRSA"),
    SHA512WithRSA("SHA512withRSA"),
    DSAWithSHA1("DSAwithSHA1"),
    DSAWithSHA256("DSAwithSHA256"),
    ECDSAWithSHA1("ECDSAwithSHA1"),
    ECDSAWithSHA256("ECDSAwithSHA256"),
    ECDSAWithSHA384("ECDSAwithSHA384"),
    ECDSAWithSHA512("ECDSAwithSHA512"),
    SHA256WithRSAPSS("SHA256withRSAPSS"),
    SHA384WithRSAPSS("SHA384withRSAPSS"),
    SHA512WithRSAPSS("SHA512withRSAPSS");

    /**
     * @param standardName
     * @see <a href="https://docs.oracle.com/javase/9/docs/specs/security/standard-names.html#signature-algorithms">Standard Signature Algorithm Names</a>
     */
    SignatureAlgorithm(String standardName) {
        this.standardName = standardName;
    }

    private String standardName;
}
