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

package eu.europa.ec.eudi.signer.r3.sca.model.signature;

import java.awt.Color;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;

import eu.europa.ec.eudi.signer.r3.sca.config.TimestampAuthorityConfig;
import eu.europa.ec.eudi.signer.r3.sca.exception.ExternalSCAException.DocumentSignDocParameterInvalidException;
import eu.europa.ec.eudi.signer.r3.sca.exception.ExternalSCAException.UnsupportedSignatureFormatException;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.qtsp.signDoc.DocumentsSignDocRequest;
import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.cades.signature.CAdESTimestampParameters;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.ImageScaling;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.SignerTextHorizontalAlignment;
import eu.europa.esig.dss.enumerations.SignerTextPosition;
import eu.europa.esig.dss.enumerations.SignerTextVerticalAlignment;
import eu.europa.esig.dss.enumerations.TextWrapping;
import eu.europa.esig.dss.enumerations.VisualSignatureAlignmentHorizontal;
import eu.europa.esig.dss.enumerations.VisualSignatureAlignmentVertical;
import eu.europa.esig.dss.enumerations.VisualSignatureRotation;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.TimestampParameters;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.DSSFont;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxNativeObjectFactory;
import eu.europa.esig.dss.pdf.pdfbox.visible.PdfBoxNativeFont;
import eu.europa.esig.dss.service.SecureRandomNonceSource;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.signature.AbstractSignatureParameters;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.validation.OCSPFirstRevocationDataLoadingStrategyFactory;
import eu.europa.esig.dss.spi.validation.RevocationDataVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

@Service
public class DSSService {
    private final static Logger logger = LoggerFactory.getLogger(DSSService.class);
	private final TimestampAuthorityConfig timestampAuthorityConfig;

	public DSSService(@Autowired TimestampAuthorityConfig timestampAuthorityConfig){
		this.timestampAuthorityConfig = timestampAuthorityConfig;
	}

    private DSSDocument loadDssDocument(String document, String filename){
        byte[] dataDocument = Base64.getDecoder().decode(document);
		return new InMemoryDocument(dataDocument, filename);
    }

	private DSSDocument loadDssDocument(String document){
		byte[] dataDocument = Base64.getDecoder().decode(document);
		return new InMemoryDocument(dataDocument);
	}

	/*
     * Function that returns the digest of the data to be signed from the document and parameters received
     */
	@SuppressWarnings({ "rawtypes", "unchecked" })
    public byte[] getDigestOfDataToBeSigned(DocumentsSignDocRequest document, X509Certificate certificate,
											CommonTrustedCertificateSource certificateSource, List<X509Certificate> certificateChain,
											String hashAlgorithmOID,  Date date) throws DocumentSignDocParameterInvalidException, UnsupportedSignatureFormatException {

		SignatureDocumentForm form = getSignatureDocumentForm(document, hashAlgorithmOID, certificate, date, certificateSource, certificateChain);
		logger.info("Successfully created the DocumentSignatureForm.");

		DocumentSignatureService service = getSignatureService(form.getContainerType(), form.getSignatureForm(), form.getTrustedCertificates());
		logger.info("Successfully created the DocumentSignatureService");

        AbstractSignatureParameters parameters = fillParameters(form);
		logger.info("Successfully set up SignatureParameters");

        ToBeSigned toBeSigned;
		if(form.getSignatureForm().equals(SignatureForm.PAdES)) {
			setImageSignedPDF((PAdESService) service, (PAdESSignatureParameters) parameters, form);
		}
		toBeSigned = service.getDataToSign(form.getDocumentToSign(), parameters);
		logger.info("Successfully retrieved dataToSign.");
		return DSSUtils.digest(parameters.getDigestAlgorithm(), toBeSigned.getBytes());
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    public DSSDocument signDocument(DocumentsSignDocRequest document, String hashAlgorithmOID, X509Certificate certificate, Date date,
									CommonTrustedCertificateSource certificateSource, List<X509Certificate> certificateChain, String signature) throws UnsupportedSignatureFormatException, DocumentSignDocParameterInvalidException {
		SignatureDocumentForm form = getSignatureDocumentForm(document, hashAlgorithmOID, certificate, date, certificateSource, certificateChain);
		form.setSignatureValue(Base64.getDecoder().decode(signature));
		logger.info("Successfully created the DocumentSignatureForm.");

		DocumentSignatureService service = getSignatureService(form.getContainerType(), form.getSignatureForm(), form.getTrustedCertificates());
		logger.info("Successfully created the DocumentSignatureService");

		AbstractSignatureParameters parameters = fillParameters(form);
		logger.info("Successfully set up SignatureParameters");

        SignatureValue signatureValue = new SignatureValue();
        signatureValue.setAlgorithm(SignatureAlgorithm.getAlgorithm(form.getEncryptionAlgorithm(), form.getDigestAlgorithm()));
        signatureValue.setValue(form.getSignatureValue());
		logger.info("Successfully created the SignatureValue");

		if(form.getSignatureForm().equals(SignatureForm.PAdES)) {
			setImageSignedPDF((PAdESService) service, (PAdESSignatureParameters) parameters, form);
		}
		DSSDocument signedDocument = service.signDocument(form.getDocumentToSign(), parameters, signatureValue);
		logger.info("Successfully retrieved signed document.");
		return signedDocument;
    }

	private SignatureDocumentForm getSignatureDocumentForm(DocumentsSignDocRequest document, String hashAlgorithmOID, X509Certificate certificate, Date date,
														  CommonTrustedCertificateSource certificateSource, List<X509Certificate> certificateChain) throws DocumentSignDocParameterInvalidException {

		SignatureDocumentForm signatureDocumentForm = new SignatureDocumentForm();

		DSSDocument dssDocument;
		if(document.getDocument_name() == null)
			dssDocument = loadDssDocument(document.getDocument());
		else
			dssDocument = loadDssDocument(document.getDocument(), document.getDocument_name());
		logger.debug("Loaded Base64-encoded document to sign as DSSDocument");
		signatureDocumentForm.setDocumentToSign(dssDocument);

		SignaturePackaging signaturePackaging = getSignaturePackaging(document.getSigned_envelope_property());
		signatureDocumentForm.setSignaturePackaging(signaturePackaging);
		ASiCContainerType asicContainerType = getASiCContainerType(document.getContainer());
		signatureDocumentForm.setContainerType(asicContainerType);
		SignatureLevel signatureLevel = getSignatureLevel(document.getConformance_level(), document.getSignature_format());
		signatureDocumentForm.setSignatureLevel(signatureLevel);
		SignatureForm signatureFormat = getSignatureForm(document.getSignature_format());
		signatureDocumentForm.setSignatureForm(signatureFormat);

		DigestAlgorithm digestAlgorithm = getDigestAlgorithmFromOID(hashAlgorithmOID);
		signatureDocumentForm.setDigestAlgorithm(digestAlgorithm);

		signatureDocumentForm.setCertificate(certificate);
		signatureDocumentForm.setCertChain(certificateChain);
		EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.forName(certificate.getPublicKey().getAlgorithm());
		signatureDocumentForm.setEncryptionAlgorithm(encryptionAlgorithm);
		signatureDocumentForm.setTrustedCertificates(certificateSource);
		signatureDocumentForm.setDate(date);

		return signatureDocumentForm;
	}

	private static SignatureLevel getSignatureLevel(String conformance_level, String signature_format) throws DocumentSignDocParameterInvalidException {
		String enumValue = getSignatureLevelFromSignatureFormatAndConformanceLevel(conformance_level, signature_format);
		return SignatureLevel.valueByName(enumValue);
	}

	private static String getSignatureLevelFromSignatureFormatAndConformanceLevel(String conformance_level, String signature_format) throws DocumentSignDocParameterInvalidException {
		String prefix = switch (signature_format) {
			case "P" -> "PAdES_BASELINE_";
			case "C" -> "CAdES_BASELINE_";
			case "J" -> "JAdES_BASELINE_";
			case "X" -> "XAdES_BASELINE_";
			default -> {
				logger.error("Signature Format in request is invalid.");
				throw new DocumentSignDocParameterInvalidException("The signature format received is invalid.", "signature_format");
			}
		};

		return switch (conformance_level) {
			case "Ades-B-B" -> prefix + "B";
			case "Ades-B-LT" -> prefix + "LT";
			case "Ades-B-LTA" -> prefix + "LTA";
			case "Ades-B-T" -> prefix + "T";
			default -> {
				logger.error("Conformance Level in request is invalid.");
				throw new DocumentSignDocParameterInvalidException("The conformance level received is invalid.", "conformance_level");
			}
		};
	}

	private static SignatureForm getSignatureForm(String signature_format) throws DocumentSignDocParameterInvalidException {
		return switch (signature_format) {
			case "P" -> SignatureForm.PAdES;
			case "C" -> SignatureForm.CAdES;
			case "J" -> SignatureForm.JAdES;
			case "X" -> SignatureForm.XAdES;
			default -> {
				logger.error("signature_format is an invalid value.");
				throw new DocumentSignDocParameterInvalidException("The signature_format received is invalid", "signature_format");
			}
		};
	}

	static DigestAlgorithm getDigestAlgorithmFromOID(String algorithmOID) throws DocumentSignDocParameterInvalidException{
		try {
			return DigestAlgorithm.forOID(algorithmOID);
		}
		catch (IllegalArgumentException e){
			logger.info("HashAlgorithmOID given doesn't match a DigestAlgorithm. Try to load SignatureAlgorithm.");

			try {
				SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.forOID(algorithmOID);
				return signatureAlgorithm.getDigestAlgorithm();
			}
			catch (IllegalArgumentException e1){
				logger.error("Session_id:{},Signature Digest Algorithm invalid.", RequestContextHolder.currentRequestAttributes().getSessionId());
				throw new DocumentSignDocParameterInvalidException("A valid DigestAlgorithm was not found from the hashAlgorithmOID.", "hashAlgorithmOID");
			}
		}
	}

	private static ASiCContainerType getASiCContainerType(String container) throws DocumentSignDocParameterInvalidException {
		return switch (container) {
			case "No" -> null;
			case "ASiC-E" -> ASiCContainerType.ASiC_E;
			case "ASiC-S" -> ASiCContainerType.ASiC_S;
			default -> {
				logger.error("ASiC Container Type received is invalid.");
				throw new DocumentSignDocParameterInvalidException("The ASiC Container Type is not supported.", "container");
			}
		};
	}

	private static SignaturePackaging getSignaturePackaging(String signedEnvelopeProperty) throws DocumentSignDocParameterInvalidException {
		return switch (signedEnvelopeProperty) {
			case "ENVELOPED" -> SignaturePackaging.ENVELOPED;
			case "ENVELOPING" -> SignaturePackaging.ENVELOPING;
			case "DETACHED" -> SignaturePackaging.DETACHED;
			case "INTERNALLY_DETACHED" -> SignaturePackaging.INTERNALLY_DETACHED;
			default -> {
				logger.error("The signature packaging received is invalid.");
				throw new DocumentSignDocParameterInvalidException("The signedEnvelopeProperty received doesn't match any of the Signature Packaging supported.", "signed_envelope_property");
			}
		};
	}

	@SuppressWarnings("rawtypes")
	private DocumentSignatureService getSignatureService(ASiCContainerType containerType, SignatureForm signatureForm, CommonTrustedCertificateSource trustedCertificates) throws UnsupportedSignatureFormatException {
		CertificateVerifier cv = getCertificateVerifier(trustedCertificates);

		DocumentSignatureService service;
		if (containerType != null) {
			service = (DocumentSignatureService) getASiCSignatureService(signatureForm, cv);
		} else {
			service = switch (signatureForm) {
				case CAdES -> new CAdESService(cv);
				case PAdES -> new PAdESService(cv);
				case XAdES -> new XAdESService(cv);
				case JAdES -> new JAdESService(cv);
				default -> {
					logger.error(String.format("The signature format %s is not supported", signatureForm));
					throw new UnsupportedSignatureFormatException(String.format("The signature format %s is not supported", signatureForm));
				}
			};
		}
		service.setTspSource(getTspSource());
		return service;
	}

	private static CertificateVerifier getCertificateVerifier(CommonTrustedCertificateSource TrustedCertificates) {
		OnlineCRLSource onlineCRLSource = new OnlineCRLSource();
		onlineCRLSource.setDataLoader(new CommonsDataLoader());

		OnlineOCSPSource onlineOCSPSource = new OnlineOCSPSource();
		onlineOCSPSource.setDataLoader(new OCSPDataLoader());
		onlineOCSPSource.setNonceSource(new SecureRandomNonceSource());

		RevocationDataVerifier revocationDataVerifier = RevocationDataVerifier.createDefaultRevocationDataVerifier();

		CertificateVerifier cv = new CommonCertificateVerifier();
		cv.setTrustedCertSources(TrustedCertificates);
		cv.setCheckRevocationForUntrustedChains(false);
		cv.setCrlSource(onlineCRLSource);
		cv.setOcspSource(null);
		cv.setAIASource(null); // Capability to download resources from AIA
		cv.setAlertOnMissingRevocationData(new ExceptionOnStatusAlert());
		cv.setAlertOnUncoveredPOE(new LogOnStatusAlert(Level.WARN));
		cv.setAlertOnRevokedCertificate(new ExceptionOnStatusAlert());
		cv.setAlertOnInvalidTimestamp(new ExceptionOnStatusAlert());
		cv.setAlertOnNoRevocationAfterBestSignatureTime(new LogOnStatusAlert(Level.ERROR));
		cv.setAlertOnExpiredCertificate(new ExceptionOnStatusAlert());
		cv.setRevocationDataLoadingStrategyFactory(new OCSPFirstRevocationDataLoadingStrategyFactory());
		cv.setRevocationDataVerifier(revocationDataVerifier);
		cv.setRevocationFallback(true);
		return cv;
	}

	@SuppressWarnings("rawtypes")
	private MultipleDocumentsSignatureService getASiCSignatureService(SignatureForm signatureForm, CertificateVerifier cv) throws UnsupportedSignatureFormatException {
		return switch (signatureForm) {
			case CAdES -> new ASiCWithCAdESService(cv);
			case XAdES -> new ASiCWithXAdESService(cv);
			default -> {
				logger.error(String.format("Signature form selected for an ASiC container (%s) is not supported", signatureForm));
				throw new UnsupportedSignatureFormatException(
					  String.format("Signature form selected for an ASiC container (%s) is not supported", signatureForm));
			}
		};
	}

	private OnlineTSPSource getTspSource(){
		String tspServer = this.timestampAuthorityConfig.getServerUrl();
		OnlineTSPSource onlineTSPSource = new OnlineTSPSource(tspServer);
		onlineTSPSource.setDataLoader(new TimestampDataLoader());
		return onlineTSPSource;
	}

	@SuppressWarnings({ "rawtypes" })
	private AbstractSignatureParameters fillParameters(SignatureDocumentForm form) throws UnsupportedSignatureFormatException {
		AbstractSignatureParameters parameters = getSignatureParameters(form.getContainerType(),  form.getSignatureForm());
		fillParameters(parameters, form);
		return parameters;
	}

	@SuppressWarnings({ "rawtypes" })
	private AbstractSignatureParameters getSignatureParameters(ASiCContainerType containerType, SignatureForm signatureForm) throws UnsupportedSignatureFormatException {
		AbstractSignatureParameters parameters;
		if (containerType != null)
			return getASiCSignatureParameters(containerType, signatureForm);

		switch (signatureForm) {
			case CAdES -> parameters = new CAdESSignatureParameters();
			case PAdES -> {
                            PAdESSignatureParameters padesParams = new PAdESSignatureParameters();
                            padesParams.setContentSize(9472 * 2); // double reserved space for signature
                            parameters = padesParams;
            }
			case XAdES -> parameters = new XAdESSignatureParameters();
			case JAdES -> {
                            JAdESSignatureParameters jadesParameters = new JAdESSignatureParameters();
                            jadesParameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);
                            jadesParameters.setSigDMechanism(SigDMechanism.OBJECT_ID_BY_URI_HASH); // to use by default
                            parameters = jadesParameters;
            }
			default -> {
                            logger.error("Unknown signature format : {}", signatureForm);
                            throw new UnsupportedSignatureFormatException(String.format("Unknown signature format : %s", signatureForm));
            }
		}

		return parameters;
	}

	@SuppressWarnings({ "rawtypes" })
	private AbstractSignatureParameters getASiCSignatureParameters(ASiCContainerType containerType, SignatureForm signatureForm) throws UnsupportedSignatureFormatException {
		AbstractSignatureParameters parameters;
		switch (signatureForm) {
			case CAdES -> {
                            ASiCWithCAdESSignatureParameters asicCadesParams = new ASiCWithCAdESSignatureParameters();
                            asicCadesParams.aSiC().setContainerType(containerType);
                            parameters = asicCadesParams;
            }
			case XAdES -> {
                            ASiCWithXAdESSignatureParameters asicXadesParams = new ASiCWithXAdESSignatureParameters();
                            asicXadesParams.aSiC().setContainerType(containerType);
                            parameters = asicXadesParams;
            }
			default -> {
                            logger.error(String.format("Signature format selected for an ASiC container (%s) is not supported", signatureForm));
                            throw new UnsupportedSignatureFormatException(
                                    String.format("Signature format selected for an ASiC container (%s) is not supported", signatureForm));
            }
		}
		return parameters;
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	private void fillParameters(AbstractSignatureParameters parameters, SignatureDocumentForm form) throws UnsupportedSignatureFormatException {
		parameters.setSignaturePackaging(form.getSignaturePackaging());
		parameters.setSignatureLevel(form.getSignatureLevel());
		parameters.setDigestAlgorithm(form.getDigestAlgorithm());
		parameters.setEncryptionAlgorithm(form.getEncryptionAlgorithm()); // ToDo
		parameters.bLevel().setSigningDate(form.getDate());

		CertificateToken signingCertificate = new CertificateToken(form.getCertificate());
		parameters.setSigningCertificate(signingCertificate);

		List<X509Certificate> certificateChainBytes = form.getCertChain();
		List<CertificateToken> certChainToken = new LinkedList<>();
		for (X509Certificate cert : certificateChainBytes) {
			certChainToken.add(new CertificateToken(cert));
		}
		parameters.setCertificateChain(certChainToken);

		fillTimestampParameters(parameters, form);
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	private void fillTimestampParameters(AbstractSignatureParameters parameters, SignatureDocumentForm form) throws UnsupportedSignatureFormatException {
		SignatureForm signatureForm = form.getSignatureForm();
		ASiCContainerType containerType = form.getContainerType();

		TimestampParameters timestampParameters = getTimestampParameters(containerType, signatureForm);
		timestampParameters.setDigestAlgorithm(form.getDigestAlgorithm());

		parameters.setContentTimestampParameters(timestampParameters);
		parameters.setSignatureTimestampParameters(timestampParameters);
		parameters.setArchiveTimestampParameters(timestampParameters);
	}

	private TimestampParameters getTimestampParameters(ASiCContainerType containerType, SignatureForm signatureForm) throws UnsupportedSignatureFormatException {
		TimestampParameters parameters;
		if (containerType == null) {
			parameters = switch (signatureForm) {
				case CAdES -> new CAdESTimestampParameters();
				case XAdES -> new XAdESTimestampParameters();
				case PAdES -> new PAdESTimestampParameters();
				case JAdES -> new JAdESTimestampParameters();
				default -> {
					logger.error(String.format("Signature format selected for a time-stamp (%s) is not supported.", signatureForm));
					throw new UnsupportedSignatureFormatException(
						  String.format("Signature format selected for a time-stamp (%s) is not supported.", signatureForm));
				}
			};

		} else {
			switch (signatureForm) {
				case CAdES -> {
                                    ASiCWithCAdESTimestampParameters asicParameters = new ASiCWithCAdESTimestampParameters();
                                    asicParameters.aSiC().setContainerType(containerType);
                                    parameters = asicParameters;
                        }
				case XAdES -> parameters = new XAdESTimestampParameters();
				default -> {
                                    logger.error(String.format("Signature format selected for an ASiC time-stamp (%s) is not supported.", signatureForm));
                                    throw new UnsupportedSignatureFormatException(
                                            String.format("Signature format selected for an ASiC time-stamp (%s) is not supported.", signatureForm));
                        }
			}
		}
		return parameters;
	}

	private void setImageSignedPDF(PAdESService service, PAdESSignatureParameters parameters, SignatureDocumentForm form) throws DocumentSignDocParameterInvalidException {
		SignatureImageParameters imageParameters;
		try {
			imageParameters = setVisualSignature(form.getDocumentToSign(), form.getCertificate(), form.getDate());
		}
		catch (IOException e){
			logger.error("There was an excepted error reading document to sign's content. {}", e.getMessage());
			throw new DocumentSignDocParameterInvalidException("There was an excepted error reading document to sign's content.", "document");
		}
		parameters.setImageParameters(imageParameters);
		service.setPdfObjFactory(new PdfBoxNativeObjectFactory());
	}

	private SignatureImageParameters setVisualSignature(DSSDocument document, X509Certificate certificate, Date date) throws IOException {

		InputStream is = document.openStream();
		PDDocument pdfDocument = Loader.loadPDF(is.readAllBytes());

		// Initialize visual signature and configure
		SignatureImageParameters imageParameters = createImageParameters();

		SignatureImageTextParameters textParameters = createTextParameters(certificate, date);
		imageParameters.setTextParameters(textParameters);

		SignatureFieldParameters fieldParameters = createFieldRectangle(pdfDocument);
		imageParameters.setFieldParameters(fieldParameters);

		return imageParameters;
	}

	private SignatureFieldParameters createFieldRectangle(PDDocument pdfDocument) {
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		// the origin is the left and top corner of the page
		fieldParameters.setOriginX(20);
		fieldParameters.setOriginY(20);
		fieldParameters.setHeight(50);
		fieldParameters.setPage(pdfDocument.getNumberOfPages());
		fieldParameters.setRotation(VisualSignatureRotation.AUTOMATIC);
		return fieldParameters;
	}

	private SignatureImageTextParameters createTextParameters(X509Certificate certificate, Date date){
		X500Name x500Name = new X500Name(certificate.getSubjectX500Principal().getName());
		RDN cn = x500Name.getRDNs(BCStyle.CN)[0];
		String name = IETFUtils.valueToString(cn.getFirst().getValue());

		SimpleDateFormat sdf = new SimpleDateFormat("EEEE dd MMM yyyy, HH:mm:ss z");
		String dateString = sdf.format(date.getTime());

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		DSSFont font = new PdfBoxNativeFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA));
		font.setSize(10);
		textParameters.setFont(font);
		textParameters.setText("Signing documents with EUDI Wallet\nSigner: "+name+"\n"+dateString);
		textParameters.setTextColor(Color.BLACK);
		textParameters.setPadding(10); // Defines a padding between the text and a border of its bounding area
		textParameters.setTextWrapping(TextWrapping.FONT_BASED); // TextWrapping parameter allows defining the text wrapping behavior within  the signature field
		textParameters.setSignerTextPosition(SignerTextPosition.RIGHT); // the text will be placed on the right side and the image on the right
		textParameters.setSignerTextHorizontalAlignment(SignerTextHorizontalAlignment.LEFT); // Specifies a horizontal alignment of a text with respect to its area
		textParameters.setSignerTextVerticalAlignment(SignerTextVerticalAlignment.TOP); // Specifies a vertical alignment of a text block with respect to a signature field area
		return textParameters;
	}

	private SignatureImageParameters createImageParameters() {
		SignatureImageParameters imageParameters = new SignatureImageParameters();

		// Visible signature positioning
		imageParameters.setAlignmentHorizontal(VisualSignatureAlignmentHorizontal.LEFT);
		imageParameters.setAlignmentVertical(VisualSignatureAlignmentVertical.BOTTOM);
		imageParameters.setImageScaling(ImageScaling.ZOOM_AND_CENTER);
		imageParameters.setImage(new InMemoryDocument(Objects.requireNonNull(getClass().getResourceAsStream("/img/symbol.png"))));

		return imageParameters;
	}









}
