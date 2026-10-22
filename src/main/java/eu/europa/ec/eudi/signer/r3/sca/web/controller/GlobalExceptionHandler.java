/*
 Copyright 2026 European Commission

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

package eu.europa.ec.eudi.signer.r3.sca.web.controller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import eu.europa.ec.eudi.signer.r3.sca.exception.ExternalSCAException;

@RestControllerAdvice
public class GlobalExceptionHandler {

	public record ErrorDetailWithField(String code, String message, String field) {}

	public record ErrorDetail(String code, String message) {}

	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<Map<String, Object>> handleValidationErrors(MethodArgumentNotValidException ex) {
		FieldError error = ex.getBindingResult().getFieldErrors().get(0);
		String field = error.getField();
		String constraint = error.getCode();

		ErrorDetailWithField detail = switch (constraint) {
			case "NotNull", "NotBlank" -> new ErrorDetailWithField(
				  "MISSING_PARAMETER",
				  error.getDefaultMessage(),
				  field
			);
			case "NotEmpty" -> new ErrorDetailWithField(
				  "EMPTY_PARAMETER",
				  error.getDefaultMessage(),
				  field
			);
			case "Valid" -> new ErrorDetailWithField(
				  "INVALID_PARAMETER",
				  error.getDefaultMessage(),
				  field
			);
			default -> new ErrorDetailWithField(
				  "VALIDATION_ERROR",
				  error.getDefaultMessage(),
				  field
			);
		};

		Map<String, Object> errors = new HashMap<>();
		errors.put("error", detail);
		return ResponseEntity.badRequest().body(errors);
	}

	@ExceptionHandler(ExternalSCAException.class)
	public ResponseEntity<Map<String, Object>> handleExternalSCAExceptions(ExternalSCAException ex) {
		Map<String, Object> errors = new HashMap<>();
		if(ex.hasField()) {
			ErrorDetailWithField detail = new ErrorDetailWithField(ex.getErrorCode(), ex.getMessage(), ex.getField());
			errors.put("error", detail);
		}
		else {
			ErrorDetail detail = new ErrorDetail(ex.getErrorCode(), ex.getMessage());
			errors.put("error", detail);
		}
		return ResponseEntity.badRequest().body(errors);
	}
}
