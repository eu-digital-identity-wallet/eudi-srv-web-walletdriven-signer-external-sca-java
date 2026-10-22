/*
 Copyright 2026 European Commission

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

package eu.europa.ec.eudi.signer.r3.sca.web.controller;

import java.security.cert.X509Certificate;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import eu.europa.ec.eudi.signer.r3.sca.model.credential.CredentialsService;
import eu.europa.ec.eudi.signer.r3.sca.model.signature.SignatureService;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;

@WebMvcTest(SignaturesController.class)
public class SignatureControllerCalculateHashRequestValidationTest {

	@Autowired
	private MockMvc mockMvc;
	@MockitoBean
	private SignatureService signatureService;
	@MockitoBean
	private CredentialsService credentialsService;

	private final String documents = """
			[
				{
     				"document": "random-string-replacing-a-document",
      				"signature_format": "J",
      				"conformance_level": "Ades-B-B",
      				"signed_envelope_property": "ENVELOPING",
      				"container": "No"
    			}
    		]
		""";

	@BeforeEach
	void setup() throws Exception {
		X509Certificate mockCertificate = mock(X509Certificate.class);
		CommonTrustedCertificateSource mockSource = mock(CommonTrustedCertificateSource.class);

		when(credentialsService.base64DecodeCertificate(any()))
			  .thenReturn(mockCertificate);

		when(credentialsService.getCommonTrustedCertificateSource())
			  .thenReturn(mockSource);

		when(signatureService.calculateHashValue(
			  any(),
			  any(),
			  any(),
			  any(),
			  any(),
			  any()
		)).thenReturn(List.of("dummy-hash"));
	}

	@Test
	void whenValidRequest_thenReturns200() throws Exception {
		String requestBody = String.format("""
			{
  				"documents": %s,
  				"endEntityCertificate": "random-string-not-a-certificate",
  				"hashAlgorithmOID": "2.16.840.1.101.3.4.2.1"
			}
		""", documents);

		mockMvc.perform(post("/signatures/calculate_hash")
					.contentType(MediaType.APPLICATION_JSON)
					.content(requestBody))
			  .andExpect(status().isOk())
			  .andExpect(jsonPath("$.hashes").exists());
	}

	void postMvcExpectBadRequest(String requestBody, String expectedCode, String expectedField) throws Exception{
		mockMvc.perform(post("/signatures/calculate_hash")
					.contentType(MediaType.APPLICATION_JSON)
					.content(requestBody))
			  .andExpect(status().isBadRequest())
			  .andExpect(jsonPath("$.error.code").value(expectedCode))
			  .andExpect(jsonPath("$.error.field").value(expectedField));
	}

	@Test
	void whenBlankEndEntityCertificate_thenReturns400() throws Exception {
		String requestBody = String.format("""
			{
  				"documents": %s,
  				"endEntityCertificate": "",
  				"hashAlgorithmOID": "2.16.840.1.101.3.4.2.1"
			}
		""", documents);
		postMvcExpectBadRequest(requestBody, "MISSING_PARAMETER", "endEntityCertificate");
	}

	@Test
	void whenMissingEndEntityCertificate_thenReturns400() throws Exception {
		String requestBody = String.format("""
			{
  				"documents": %s,
  				"hashAlgorithmOID": "2.16.840.1.101.3.4.2.1"
			}
		""", documents);
		postMvcExpectBadRequest(requestBody, "MISSING_PARAMETER", "endEntityCertificate");
	}

	@Test
	void whenMissingHashAlgorithmOID_thenReturns400() throws Exception {
		String requestBody = String.format("""
			{
  				"documents": %s,
  				"endEntityCertificate": "random-string-not-a-certificate"
			}
		""", documents);
		postMvcExpectBadRequest(requestBody, "MISSING_PARAMETER", "hashAlgorithmOID");
	}

	@Test
	void whenBlankHashAlgorithmOID_thenReturns400() throws Exception {
		String requestBody = String.format("""
			{
  				"documents": %s,
  				"endEntityCertificate": "random-string-not-a-certificate",
  				"hashAlgorithmOID": ""
			}
		""", documents);
		postMvcExpectBadRequest(requestBody, "MISSING_PARAMETER", "hashAlgorithmOID");
	}

	@Test
	void whenMissingDocuments_thenReturns400() throws Exception {
		String requestBody = """
			{
  				"endEntityCertificate": "random-string-not-a-certificate",
  				"hashAlgorithmOID": "2.16.840.1.101.3.4.2.1"
			}
		""";
		mockMvc.perform(post("/signatures/calculate_hash")
					.contentType(MediaType.APPLICATION_JSON)
					.content(requestBody))
			  .andExpect(status().isBadRequest())
			  .andExpect(jsonPath("$.error.field").value("documents"));
	}

	@Test
	void whenEmptyListDocuments_thenReturns200() throws Exception {
		String requestBody = """
			{
  				"documents": [ ],
  				"endEntityCertificate": "random-string-not-a-certificate",
  				"hashAlgorithmOID": "2.16.840.1.101.3.4.2.1"
			}
		""";
		postMvcExpectBadRequest(requestBody, "EMPTY_PARAMETER", "documents");
	}

	@Test
	void whenMissingDocumentsParamDocument_thenReturns400() throws Exception {
		String requestBody = """
			{
  				"documents": [
    				{
      					"signature_format": "J",
      					"conformance_level": "Ades-B-B",
      					"signed_envelope_property": "ENVELOPING",
      					"container": "No"
    				}
  				],
  				"endEntityCertificate": "random-string-not-a-certificate",
  				"hashAlgorithmOID": "2.16.840.1.101.3.4.2.1"
			}
		""";
		postMvcExpectBadRequest(requestBody, "MISSING_PARAMETER", "documents[0].document");
	}

	@Test
	void whenInvalidDocumentsParamSignatureFormat_thenReturns400() throws Exception {
		String requestBody = """
			{
  				"documents": [
    				{
      					"document": "random-string-replacing-a-document",
      					"signature_format": "J.",
      					"conformance_level": "Ades-B-B",
      					"signed_envelope_property": "ENVELOPING",
      					"container": "No"
    				}
  				],
  				"endEntityCertificate": "random-string-not-a-certificate",
  				"hashAlgorithmOID": "2.16.840.1.101.3.4.2.1"
			}
		""";
		postMvcExpectBadRequest(requestBody, "VALIDATION_ERROR", "documents[0].signature_format");
	}

	@Test
	void whenInvalidDocumentsParamConformanceLevel_thenReturns400() throws Exception {
		String requestBody = """
			{
  				"documents": [
    				{
      					"document": "random-string-replacing-a-document",
      					"signature_format": "J",
      					"conformance_level": "Ades-B-B-1",
      					"signed_envelope_property": "ENVELOPING",
      					"container": "No"
    				}
  				],
  				"endEntityCertificate": "random-string-not-a-certificate",
  				"hashAlgorithmOID": "2.16.840.1.101.3.4.2.1"
			}
		""";
		postMvcExpectBadRequest(requestBody, "VALIDATION_ERROR", "documents[0].conformance_level");
	}

	@Test
	void whenInvalidDocumentsParamSignedEnvelopeProperty_thenReturns400() throws Exception {
		String requestBody = """
			{
  				"documents": [
    				{
      					"document": "random-string-replacing-a-document",
      					"signature_format": "J",
      					"conformance_level": "Ades-B-B",
      					"signed_envelope_property": "ENVELOPING-",
      					"container": "No"
    				}
  				],
  				"endEntityCertificate": "random-string-not-a-certificate",
  				"hashAlgorithmOID": "2.16.840.1.101.3.4.2.1"
			}
		""";
		postMvcExpectBadRequest(requestBody, "VALIDATION_ERROR", "documents[0].signed_envelope_property");
	}

	@Test
	void whenInvalidDocumentsParamContainer_thenReturns400() throws Exception {
		String requestBody = """
			{
  				"documents": [
    				{
      					"document": "random-string-replacing-a-document",
      					"signature_format": "J",
      					"conformance_level": "Ades-B-B",
      					"signed_envelope_property": "ENVELOPING",
      					"container": "No."
    				}
  				],
  				"endEntityCertificate": "random-string-not-a-certificate",
  				"hashAlgorithmOID": "2.16.840.1.101.3.4.2.1"
			}
		""";
		postMvcExpectBadRequest(requestBody, "VALIDATION_ERROR", "documents[0].container");
	}
}
