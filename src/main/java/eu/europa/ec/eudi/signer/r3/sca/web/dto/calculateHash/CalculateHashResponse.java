package eu.europa.ec.eudi.signer.r3.sca.web.dto.calculateHash;

import java.util.List;

public class CalculateHashResponse {
	private List<String> hashes;
	private long signature_date;

	public CalculateHashResponse(List<String> hashes, long signature_date) {
		this.hashes = hashes;
		this.signature_date = signature_date;
	}

	public List<String> getHashes() {
		return hashes;
	}

	public void setHashes(List<String> hashes) {
		this.hashes = hashes;
	}

	public long getSignature_date() {
		return signature_date;
	}

	public void setSignature_date(long signature_date) {
		this.signature_date = signature_date;
	}
}
