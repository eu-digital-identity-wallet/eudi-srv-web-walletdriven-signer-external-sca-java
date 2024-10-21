package eu.europa.ec.eudi.signer.r3.sca.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "trusted-certificate")
public class TrustedCertificateConfig {
	private String filename;
	private String timeStampAuthority;

	public String getFilename() {
		return filename;
	}

	public void setFilename(String filename) {
		this.filename = filename;
	}

	public String getTimeStampAuthority() {
		return timeStampAuthority;
	}

	public void setTimeStampAuthority(String timeStampAuthority) {
		this.timeStampAuthority = timeStampAuthority;
	}
}
