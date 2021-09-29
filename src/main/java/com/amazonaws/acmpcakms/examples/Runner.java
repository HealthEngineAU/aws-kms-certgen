package com.amazonaws.acmpcakms.examples;

import com.amazonaws.services.acmpca.model.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public class Runner {
    private static final String ROOT_COMMON_NAME = "Healthengine-SelfSignedRoot";
    private static final String SUBORDINATE_COMMON_NAME = "Healthengine-Subordinate";
    private static final String ENTITY_COMMON_NAME;
    private static final String CMK_ALIAS;

    private static String getEnvWithDefault(String name, String defaultValue) {
        String value = System.getenv(name);
        return value != null ? value : defaultValue;
    }

    static {
        CMK_ALIAS = getEnvWithDefault("KMS_KEY_ID", "cvip-auth");
        ENTITY_COMMON_NAME = getEnvWithDefault("CERT_CN", "Healthengine-CVIP");
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(final String[] args) throws Exception {

        /* Creating a CA hierarcy in ACM Private CA. This CA hiearchy consistant of a Root and subordinate CA */
        // System.out.println("Creating a CA hierarchy\n");

        PrivateCA rootPrivateCA = PrivateCA.builder()
                .withCommonName(ROOT_COMMON_NAME)
                .withType(CertificateAuthorityType.ROOT)
                .getOrCreate();

        PrivateCA subordinatePrivateCA = PrivateCA.builder()
                .withIssuer(rootPrivateCA)
                .withCommonName(SUBORDINATE_COMMON_NAME)
                .withType(CertificateAuthorityType.SUBORDINATE)
                .getOrCreate();

        /* Creating a asymmetric key pair using AWS KMS */
        // System.out.println();
        // System.out.println("Getting or creating a asymmetric key pair using AWS KMS\n");

        AsymmetricCMK codeSigningCMK = AsymmetricCMK.builder()
                .withAlias(CMK_ALIAS)
                .getOrCreate();

        /* Creating a asymmetric key pair using AWS KMS */
        // System.out.println();
        // System.out.println("Creating a CSR(Certificate signing request) for creating a code signing certificate\n");
        String codeSigningCSR = codeSigningCMK.generateCSR(ENTITY_COMMON_NAME);

        /* Issuing the code signing certificate from ACM Private CA */
        // System.out.println();
        // System.out.println("Issuing a code signing certificate from ACM Private CA\n");
        GetCertificateResult codeSigningCertificate = subordinatePrivateCA.issueCodeSigningCertificate(codeSigningCSR);
    }
}
