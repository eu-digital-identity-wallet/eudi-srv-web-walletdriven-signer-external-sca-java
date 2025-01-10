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

import eu.europa.ec.eudi.signer.r3.sca.web.dto.qtsp.signDoc.DocumentsSignDocRequest;
import jakarta.validation.constraints.NotBlank;

import java.util.List;

public class SignedDocumentRequest {
	@NotBlank(message = "At least one document must be present in the request.")
	private List<DocumentsSignDocRequest> documents;
	@NotBlank(message = "The hashAlgorithmOID must be present.")
	private String hashAlgorithmOID;
	private boolean returnValidationInfo;
	@NotBlank(message = "The certificate must be present.")
	private String endEntityCertificate;
	private List<String> certificateChain;
	@NotBlank(message = "The 'date' value must be present.")
	private long date;
	@NotBlank(message = "The list of signatures must be present.")
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
