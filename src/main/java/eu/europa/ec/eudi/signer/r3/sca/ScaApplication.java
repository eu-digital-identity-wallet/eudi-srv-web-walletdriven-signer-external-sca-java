package eu.europa.ec.eudi.signer.r3.sca;

import java.util.logging.Level;
import java.util.logging.Logger;

import eu.europa.ec.eudi.signer.r3.sca.config.OAuthClientConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties({ OAuthClientConfig.class })
public class ScaApplication {
	public static void main(String[] args) {
		Logger libraryLogger = Logger.getLogger("eu.europa.esig");
		libraryLogger.setLevel(Level.FINE);
		SpringApplication.run(ScaApplication.class, args);
	}
}
