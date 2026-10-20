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

package eu.europa.ec.eudi.signer.r3.sca.config;

import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;

@Configuration
public class SwaggerConfig {
	@Bean
	GroupedOpenApi publicApi(){
		return GroupedOpenApi.builder()
			  .group("public-apis")
			  .pathsToMatch("/**")
			  .build();
	}

	@Bean
	public OpenAPI customOpenAPI() {
		return new OpenAPI()
			  .info(new Info()
					.title("EUDI Wallet-Driven external SCA")
					.description("REST API Server implementing the **Wallet-driven external SCA** component of the remote Qualified Electronic Signature (rQES) for the EUDI Wallet.")
					.version("0.4.0")
					.license(new License()
						  .name("Apache 2.0")
						  .url("https://www.apache.org/licenses/LICENSE-2.0.html"))
			  );
	}
}
