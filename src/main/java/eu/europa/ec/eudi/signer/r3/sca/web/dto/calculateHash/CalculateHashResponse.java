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
