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

import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.signature.JAdESBuilder;
import eu.europa.esig.dss.jades.signature.JAdESCompactBuilder;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.validation.CertificateVerifier;
import java.util.Collection;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/** Opt-in WRPRC headers, applied identically before hashing and signature assembly. */
final class WrprcJAdESService extends JAdESService {
    WrprcJAdESService(CertificateVerifier verifier) { super(verifier); }

    @Override
    protected JAdESBuilder getJAdESBuilder(JAdESSignatureParameters parameters, List<DSSDocument> documents) {
        return new JAdESCompactBuilder(certificateVerifier, parameters, documents) {
            @Override
            protected void incorporateHeader(JWS jws) {
                for (var entry : jadesLevelBaselineB.getSignedProperties().entrySet()) {
                    if ("sigT".equals(entry.getKey())) continue;
                    if ("crit".equals(entry.getKey())) {
                        // Remove only the replaced sigT reference; preserve any other critical headers.
                        Collection<?> original = (Collection<?>) entry.getValue();
                        List<?> remaining = original.stream().filter(value -> !"sigT".equals(value)).toList();
                        if (!remaining.isEmpty()) jws.setHeader("crit", remaining);
                    } else {
                        jws.setHeader(entry.getKey(), entry.getValue());
                    }
                }
                // ETSI TS 119 182-1 V1.2.1, 5.1.11 and 5.2.1: iat replaces sigT.
                jws.setHeader("iat", parameters.bLevel().getSigningDate().getTime() / 1000);
                jws.setHeader("typ", "rc-wrp+jwt");
                // WRPRC consumers need the signing certificate even when DSS regards it as trusted.
                List<String> chain = new ArrayList<>();
                chain.add(Base64.getEncoder().encodeToString(parameters.getSigningCertificate().getEncoded()));
                for (var certificate : parameters.getCertificateChain()) {
                    if (!certificate.equals(parameters.getSigningCertificate())) {
                        chain.add(Base64.getEncoder().encodeToString(certificate.getEncoded()));
                    }
                }
                jws.setHeader("x5c", chain);
            }
        };
    }
}
