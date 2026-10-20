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

package eu.europa.ec.eudi.signer.r3.sca.web.dto.calculateHash;

import java.util.ArrayList;
import java.util.List;

import eu.europa.ec.eudi.signer.r3.sca.web.dto.qtsp.signDoc.DocumentsSignDocRequest;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

@Schema(description = "JSON Object containing the information to retrieve base64-encoded hashes values to be signed.")
public class CalculateHashRequest {
	@Schema(description = "An array of JSON Objects containing base64-encoded documents and further parameters.", required = true)
	@NotEmpty(message = "At least one document to be signed must be sent in the request.")
	@NotNull(message = "Missing required parameter: documents")
	@Valid
	private List<DocumentsSignDocRequest> documents;
	@Schema(description = "The base64-encoded end entity certificate of the signer of the document.", required = true)
	@NotBlank(message = "Missing required parameter: endEntityCertificate")
	private String endEntityCertificate;
	@Schema(description = "The base64-encoded certificate chain of the end entity certificate.")
	private List<String> certificateChain = new ArrayList<>();
	@Schema(description = "The OID of the algorithm to be used to calculate the hash value(s).", required = true)
	@NotBlank(message = "Missing required parameter: hashAlgorithmOID")
	private String hashAlgorithmOID;

	public List<DocumentsSignDocRequest> getDocuments() {
		return documents;
	}

	public void setDocuments(List<DocumentsSignDocRequest> documents) {
		this.documents = documents;
	}

	public String getEndEntityCertificate() {
		return endEntityCertificate;
	}

	public void setEndEntityCertificate(String endEntityCertificate) {
		this.endEntityCertificate = endEntityCertificate;
	}

	public List<String> getCertificateChain() {
		return certificateChain;
	}

	public void setCertificateChain(List<String> certificateChain) {
		this.certificateChain = certificateChain;
	}

	public String getHashAlgorithmOID() {
		return hashAlgorithmOID;
	}

	public void setHashAlgorithmOID(String hashAlgorithmOID) {
		this.hashAlgorithmOID = hashAlgorithmOID;
	}
}
