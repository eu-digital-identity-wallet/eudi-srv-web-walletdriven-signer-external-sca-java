package eu.europa.ec.eudi.signer.r3.sca;

import java.util.logging.Level;
import java.util.logging.Logger;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class ScaApplication {
	public static void main(String[] args) {
		Logger libraryLogger = Logger.getLogger("eu.europa.esig");
		libraryLogger.setLevel(Level.FINE);
		SpringApplication.run(ScaApplication.class, args);
	}
}
