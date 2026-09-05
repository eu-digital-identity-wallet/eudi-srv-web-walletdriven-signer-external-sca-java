/*
 Copyright 2024 European Commission

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

package eu.europa.ec.eudi.signer.r3.sca.model.signature;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import eu.europa.ec.eudi.signer.r3.sca.config.TimestampAuthorityConfig;
import eu.europa.ec.eudi.signer.r3.sca.model.credential.CredentialsService;
import eu.europa.ec.eudi.signer.r3.sca.model.signature.DSSService;
import eu.europa.ec.eudi.signer.r3.sca.model.signature.SignatureService;
import eu.europa.ec.eudi.signer.r3.sca.web.controller.SignaturesController;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class WrprcEndpointsTest {
    @TempDir Path temporary;
    private final ObjectMapper json = new ObjectMapper();
    private MockMvc mvc;
    private KeyPair key;
    private X509Certificate certificate;
    private static final String PAYLOAD = "{\"sub\":\"local-test\"}";

    @BeforeEach
    void setup() throws Exception {
        var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        key = generator.generateKeyPair();
        var name = new X500Name("CN=Local test");
        long now = System.currentTimeMillis();
        certificate = new JcaX509CertificateConverter().getCertificate(
            new JcaX509v3CertificateBuilder(name, BigInteger.ONE, new Date(now - 60000),
                new Date(now + 3600000), name, key.getPublic()).build(
                    new JcaContentSignerBuilder("SHA256withECDSA").build(key.getPrivate())));
        Path certFile = temporary.resolve("certificate.der");
        Files.write(certFile, certificate.getEncoded());
        var config = new TimestampAuthorityConfig();
        config.setCertificatePath(certFile.toString());
        config.setServerUrl("http://127.0.0.1:1/unused-tsa");
        config.setSupportedDigestAlgorithm(List.of("2.16.840.1.101.3.4.2.1"));
        var service = new SignatureService(new DSSService(config), config);
        mvc = MockMvcBuilders.standaloneSetup(new SignaturesController(new CredentialsService(config), service)).build();
    }

    private ObjectNode request(boolean profile) throws Exception {
        var request = json.createObjectNode();
        request.put("endEntityCertificate", Base64.getEncoder().encodeToString(certificate.getEncoded()));
        request.putArray("certificateChain");
        request.put("hashAlgorithmOID", "2.16.840.1.101.3.4.2.1");
        var doc = request.putArray("documents").addObject();
        doc.put("document", Base64.getEncoder().encodeToString(PAYLOAD.getBytes(StandardCharsets.UTF_8)));
        doc.put("signature_format", "J"); doc.put("conformance_level", "Ades-B-B");
        doc.put("signed_envelope_property", "ENVELOPING"); doc.put("container", "No");
        if (profile) doc.put("jades_profile", "WRPRC");
        return request;
    }

    private String roundTrip(boolean profile) throws Exception { return roundTrip(profile, profile); }

    private String roundTrip(boolean profile, boolean assemblyProfile) throws Exception {
        var request = request(profile);
        var response = json.readTree(mvc.perform(post("/signatures/calculate_hash")
            .contentType("application/json").content(request.toString()))
            .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        Signature signer = Signature.getInstance("NONEwithECDSA");
        signer.initSign(key.getPrivate());
        signer.update(Base64.getDecoder().decode(response.get("hashes").get(0).asText()));
        request.put("date", response.get("signature_date").asLong());
        request.putArray("signatures").add(Base64.getEncoder().encodeToString(signer.sign()));
        request.put("returnValidationInfo", false);
        var document = (ObjectNode) request.get("documents").get(0);
        if (assemblyProfile) document.put("jades_profile", "WRPRC");
        else document.remove("jades_profile");
        var signed = json.readTree(mvc.perform(post("/signatures/obtain_signed_doc")
            .contentType("application/json").content(request.toString()))
            .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        return new String(Base64.getDecoder().decode(signed.get("documentWithSignature").get(0).asText()), StandardCharsets.UTF_8);
    }

    @Test void unrelatedCriticalHeadersArePreserved() throws Exception {
        var params = new eu.europa.esig.dss.jades.JAdESSignatureParameters();
        params.setJwsSerializationType(eu.europa.esig.dss.enumerations.JWSSerializationType.COMPACT_SERIALIZATION);
        params.setSignatureLevel(eu.europa.esig.dss.enumerations.SignatureLevel.JAdES_BASELINE_B);
        params.setSignaturePackaging(eu.europa.esig.dss.enumerations.SignaturePackaging.ENVELOPING);
        params.setDigestAlgorithm(eu.europa.esig.dss.enumerations.DigestAlgorithm.SHA256);
        params.setSigningCertificate(new eu.europa.esig.dss.model.x509.CertificateToken(certificate));
        params.bLevel().setSigningDate(new Date());
        params.bLevel().setSignedAssertions(List.of("synthetic assertion"));
        var signer = new WrprcJAdESService(new eu.europa.esig.dss.validation.CommonCertificateVerifier());
        var data = signer.getDataToSign(new eu.europa.esig.dss.model.InMemoryDocument(PAYLOAD.getBytes(StandardCharsets.UTF_8)), params);
        String encodedHeader = new String(data.getBytes(), StandardCharsets.US_ASCII).split("\\.")[0];
        var header = json.readTree(Base64.getUrlDecoder().decode(encodedHeader));
        assertTrue(header.has("srAts"));
        assertTrue(header.get("crit").toString().contains("srAts"));
        assertFalse(header.get("crit").toString().contains("sigT"));
    }

    @Test void profilePassesDefaultNimbusVerification() throws Exception {
        var jwt = SignedJWT.parse(roundTrip(true));
        assertEquals("rc-wrp+jwt", jwt.getHeader().getType().toString());
        assertNull(jwt.getHeader().getCriticalParams());
        assertNull(jwt.getHeader().getCustomParam("sigT"));
        assertNotNull(jwt.getHeader().getCustomParam("iat"));
        assertArrayEquals(certificate.getEncoded(), jwt.getHeader().getX509CertChain().get(0).decode());
        assertEquals(PAYLOAD, jwt.getPayload().toString());
        var verifier = new ECDSAVerifier((ECPublicKey) certificate.getPublicKey());
        assertTrue(jwt.verify(verifier));
        String[] parts = jwt.serialize().split("\\.");
        String changedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"sub\":\"tampered\"}".getBytes(StandardCharsets.UTF_8));
        assertFalse(SignedJWT.parse(parts[0] + "." + changedPayload + "." + parts[2]).verify(verifier));
    }

    @Test void changingProfileBetweenStepsDoesNotProduceValidSignature() throws Exception {
        var jwt = SignedJWT.parse(roundTrip(false, true));
        assertFalse(jwt.verify(new ECDSAVerifier((ECPublicKey) certificate.getPublicKey())));
    }

    @Test void omittedProfileKeepsJsonAndLegacyHeaders() throws Exception {
        var doc = json.readTree(roundTrip(false));
        var header = json.readTree(Base64.getUrlDecoder().decode(doc.get("signatures").get(0).get("protected").asText()));
        assertEquals("jose+json", header.get("typ").asText());
        assertTrue(header.has("sigT"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"jades_profile:UNKNOWN", "signature_format:P", "conformance_level:Ades-B-T", "signed_envelope_property:DETACHED", "container:ASiC-E"})
    void incompatibleOptionsReturn400OnBothEndpoints(String mutation) throws Exception {
        var request = request(true);
        String[] parts = mutation.split(":");
        ((ObjectNode) request.get("documents").get(0)).put(parts[0], parts[1]);
        for (String endpoint : List.of("calculate_hash", "obtain_signed_doc")) {
            mvc.perform(post("/signatures/" + endpoint).contentType("application/json").content(request.toString()))
                .andExpect(status().isBadRequest());
        }
    }
}
