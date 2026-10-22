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

package eu.europa.ec.eudi.signer.r3.sca;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import eu.europa.ec.eudi.signer.r3.sca.model.credential.CredentialsService;

@SpringBootTest(
	  properties = {
			"timestamp-authority.certificate-path=${TIMESTAMP_AUTHORITY_CERTIFICATE_FILEPATH:/dummy/path}",
			"timestamp-authority.server-url=${TIMESTAMP_AUTHORITY_URL:http://dummy_url}",
			"timestamp-authority.supported-digest-algorithm=${TIMESTAMP_AUTHORITY_SUPPORTED_DIGEST_ALGS:2.16.840.1.101.3.4.2.1}"
	  }
)
class ScaApplicationTests {

	@MockitoBean
	CredentialsService credentialsService;

	@Test
	void contextLoads() {
	}

}
