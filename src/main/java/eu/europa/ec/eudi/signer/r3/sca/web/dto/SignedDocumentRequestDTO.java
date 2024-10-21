package eu.europa.ec.eudi.signer.r3.sca.web.dto;

import eu.europa.ec.eudi.signer.r3.sca.web.dto.signDoc.DocumentsSignDocRequest;

import java.util.List;

public class SignedDocumentRequestDTO {
	private List<DocumentsSignDocRequest> documents;
	private String hashAlgorithmOID;
	private boolean returnValidationInfo;
	private String signingCertificate;
	private List<String> certificateChain;
	private long date;
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

	public String getSigningCertificate() {
		return signingCertificate;
	}

	public void setSigningCertificate(String signingCertificate) {
		this.signingCertificate = signingCertificate;
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
