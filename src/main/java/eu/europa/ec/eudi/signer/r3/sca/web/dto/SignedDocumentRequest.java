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

package eu.europa.ec.eudi.signer.r3.sca.web.dto;

import java.util.ArrayList;
import java.util.List;

import eu.europa.ec.eudi.signer.r3.sca.web.dto.qtsp.signDoc.DocumentsSignDocRequest;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

@Schema(description = "JSON Object containing the information to retrieve signed documents.")
public class SignedDocumentRequest {
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
	@Schema(description = "The OID of the algorithm used to calculate the hash value(s).", required = true)
	@NotBlank(message = "Missing required parameter: hashAlgorithmOID")
	private String hashAlgorithmOID;
	@Schema(description = "Boolean that indicates if the service will return the validation_info in the response.")
	private boolean returnValidationInfo;
	@Schema(description = "As returned in the calculate_hash endpoint, the number of milliseconds since January 1, 1970, 00:00:00 GMT represented by date of when the hash(es) where obtained.", required = true)
	@NotNull(message = "Missing required parameter: date")
	private Long date;
	@Schema(description = "An array of base64-encoded signatures values of the hash(es) retrieved from the calculate_hash. Each signature corresponds to the document at the same index in the documents list. The order must be preserved.", required = true)
	@NotEmpty(message = "At least one signature must be sent in the request.")
	@NotNull(message = "Missing required parameter: signatures")
	List<String> signatures;

	public List<DocumentsSignDocRequest> getDocuments() {
		return documents;
	}

	public void setDocuments(List<DocumentsSignDocRequest> documents) {
		this.documents = documents;
	}

	public String getHashAlgorithmOID() {
		return hashAlgorithmOID;
	}

	public void setHashAlgorithmOID(String hashAlgorithmOID) {
		this.hashAlgorithmOID = hashAlgorithmOID;
	}

	public boolean isReturnValidationInfo() {
		return returnValidationInfo;
	}

	public void setReturnValidationInfo(boolean returnValidationInfo) {
		this.returnValidationInfo = returnValidationInfo;
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

	public long getDate() {
		return date;
	}

	public void setDate(long date) {
		this.date = date;
	}

	public List<String> getSignatures() {
		return signatures;
	}

	public void setSignatures(List<String> signatures) {
		this.signatures = signatures;
	}
}
