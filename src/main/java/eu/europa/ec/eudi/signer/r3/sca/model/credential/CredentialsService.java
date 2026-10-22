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

package eu.europa.ec.eudi.signer.r3.sca.model.credential;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import eu.europa.ec.eudi.signer.r3.sca.config.TimestampAuthorityConfig;
import eu.europa.ec.eudi.signer.r3.sca.exception.ExternalSCAException.CertificateBase64DecodingException;
import eu.europa.ec.eudi.signer.r3.sca.exception.ExternalSCAException.MisconfigurationException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;

@Service
public class CredentialsService {
    private static final Logger logger = LoggerFactory.getLogger(CredentialsService.class);
    private final CertificateToken TSACertificateToken;

    public CredentialsService(@Autowired TimestampAuthorityConfig timestampAuthorityConfig) throws MisconfigurationException {
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            String certificateStringPath = timestampAuthorityConfig.getCertificatePath();
            if (certificateStringPath == null || certificateStringPath.isEmpty()) {
                throw new MisconfigurationException("Timestamp authority certificate path not found in configuration.", "timestamp-authority.certificate-path");
            }
            FileInputStream certInput = new FileInputStream(certificateStringPath);
            X509Certificate TSACertificate = (X509Certificate) certFactory.generateCertificate(certInput);
            this.TSACertificateToken = new CertificateToken(TSACertificate);
            certInput.close();
        }
        catch (CertificateException e){
            String message = "Failed to generate timestamp authority X.509 certificate. Certificate may be invalid or corrupted.";
            logger.error("{} Error: {}", message, e.getMessage(), e);
            throw new MisconfigurationException(message, "timestamp-authority.certificate-path");
        } catch (FileNotFoundException e) {
            String message = "Failed to find the timestamp authority X.509 certificate file.";
            logger.error("{} Error: {}", message, e.getMessage(), e);
			throw new MisconfigurationException(message, "timestamp-authority.certificate-path");
		} catch (IOException e) {
            String message = "Unexpected error when loading the timestamp authority certificate.";
            logger.error("{} Error: {}", message, e.getMessage(), e);
			throw new MisconfigurationException(message, "timestamp-authority.certificate-path");
		}
	}

    public X509Certificate base64DecodeCertificate(String certificate) throws CertificateBase64DecodingException {
        try {
            byte[] certificateBytes = Base64.getDecoder().decode(certificate);
            ByteArrayInputStream inputStream = new ByteArrayInputStream(certificateBytes);
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificateDecoded = (X509Certificate) certFactory.generateCertificate(inputStream);
            logger.info("Successfully decoded X.509 certificate. Subject: {}", certificateDecoded.getSubjectX500Principal());
            return certificateDecoded;
        } catch (IllegalArgumentException e) {
            String message = "Failed to decode the provided certificate. Input is not valid Base64.";
            logger.error("{} Error: {}", message, e.getMessage(), e);
            throw new CertificateBase64DecodingException(message);

        } catch (CertificateException e) {
            String message = "Failed to generate X.509 certificate from decoded bytes. Certificate may be invalid or corrupted.";
			logger.error("{} Error: {}", message, e.getMessage(), e);
            throw new CertificateBase64DecodingException(message);
        }
    }

    public CommonTrustedCertificateSource getCommonTrustedCertificateSource (){
        CommonTrustedCertificateSource certificateSource = new CommonTrustedCertificateSource();
        certificateSource.addCertificate(this.TSACertificateToken);
        return certificateSource;
    }
}
