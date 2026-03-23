# Changelog

## [0.4.0]

_23 Mar 2026_

### Changed:
- Removed URL-encoding after document digest generation.

## [0.3.0]

_1 Jul 2025_

### Added:
- Visible representation of the PDF signature.
- Docker support for the application:
  - Added Dockerfile to build the application image.
  - Added docker-compose.yml.
  - Instructions for building and running the container added to README.md.

### Fixed:
- Remove unused code.
- Bugs found during Signature Parameter combinations testing.

## [0.2.0]

_29 Nov 2024_

### Added:
- Endpoint to calculate the digest of data to be signed
- Endpoint to obtain the signed document
- Support to obtaining signature types: PAdES, CAdES, XAdES, JAdES
- Support for Baseline signatures: -B, -T, -LT, -LTA

