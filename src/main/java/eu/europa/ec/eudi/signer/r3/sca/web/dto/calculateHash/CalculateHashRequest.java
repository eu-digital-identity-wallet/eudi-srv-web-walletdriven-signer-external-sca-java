package eu.europa.ec.eudi.signer.r3.sca.web.dto.calculateHash;

import eu.europa.ec.eudi.signer.r3.sca.web.dto.signDoc.DocumentsSignDocRequest;

import java.util.ArrayList;
import java.util.List;

public class CalculateHashRequest {

	private List<DocumentsSignDocRequest> documents;
	private String endEntityCertificate;
	private List<String> certificateChain = new ArrayList<>();
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
