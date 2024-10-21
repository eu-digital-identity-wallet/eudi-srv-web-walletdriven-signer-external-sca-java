package eu.europa.ec.eudi.signer.r3.sca.web.dto.calculateHash;

import eu.europa.ec.eudi.signer.r3.sca.web.dto.signDoc.DocumentsSignDocRequest;

import java.util.List;

public class CalculateHashRequest {

	private List<DocumentsSignDocRequest> documents;
	private String signingCertificate;
	private List<String> certificateChain;
	private String hashAlgorithmOID;

	public List<DocumentsSignDocRequest> getDocuments() {
		return documents;
	}

	public void setDocuments(List<DocumentsSignDocRequest> documents) {
		this.documents = documents;
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

	public String getHashAlgorithmOID() {
		return hashAlgorithmOID;
	}

	public void setHashAlgorithmOID(String hashAlgorithmOID) {
		this.hashAlgorithmOID = hashAlgorithmOID;
	}
}
