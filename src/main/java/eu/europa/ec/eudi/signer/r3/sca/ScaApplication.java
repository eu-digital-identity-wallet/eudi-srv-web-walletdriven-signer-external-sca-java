package eu.europa.ec.eudi.signer.r3.sca;

import eu.europa.ec.eudi.signer.r3.sca.config.OAuthClientConfig;
import eu.europa.ec.eudi.signer.r3.sca.config.TrustedCertificateConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties({ OAuthClientConfig.class, TrustedCertificateConfig.class })
public class ScaApplication {
	public static void main(String[] args) {
		//Logger libraryLogger = Logger.getLogger("eu.europa.esig");
		//libraryLogger.setLevel(Level.FINE);
		SpringApplication.run(ScaApplication.class, args);
	}
}
