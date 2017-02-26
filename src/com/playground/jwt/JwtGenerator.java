package com.playground.jwt;

import com.sun.org.apache.xml.internal.security.algorithms.SignatureAlgorithm;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class JwtGenerator {
    private static final long YEAR = 365L * 24 * 60 * 60;
    public static void main(String[] args) throws Exception {
        CertAndKeyGen certGen = new CertAndKeyGen("RSA", "SHA256WithRSA");
        certGen.generate(512);
        Base64.Encoder encoder = Base64.getEncoder();
        X509Certificate cert = certGen.getSelfCertificate(
                new X500Name("CN=SOME CN 1,O=SOME ORG,L=SOME LOCATION,C=SOME CITY"), YEAR * 1000);
        PrivateKey privateKey = certGen.getPrivateKey();
        String privateKeyEncoded = encoder.encodeToString(privateKey.getEncoded());
        String base64PublicCert = encoder.withoutPadding().encodeToString(cert.getEncoded());
        String jwt = Jwts.builder()
                .setSubject("SOME SUBJECT")
                .setIssuer("SOME ISSUER")
                .setClaims(buildPermissionClaims(
                        "cn=SOME_CN,ou=SOME_OU,ou=SOME_OU2,o=SOME_O;"
                ))
                .signWith(SignatureAlgorithm.RS256, privateKey)
                .compact();
        System.out.println("private:\n");
        System.out.println(privateKeyEncoded);
        System.out.println("\npublic cert:\n");
        System.out.println(base64PublicCert);
        System.out.println("\njwt:\n");
        System.out.println(jwt);
    }
    private static Map<String, Object> buildPermissionClaims(String permissions) {
        HashMap<String, Object> claims = new HashMap<>();
        HashMap<String, Object> privateClaims = new HashMap<>();
        privateClaims.put("permissions", permissions);
        claims.put("some_claim", privateClaims);
        return claims;
    }
}