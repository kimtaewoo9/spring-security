package software.springsecurity.exception;

import javax.security.sasl.AuthenticationException;

public class JwtAuthenticationException extends AuthenticationException {

	private final int httpStatus;
	private final String errorCode;

	public JwtAuthenticationException(String message, int httpStatus, String errorCode) {
		super(message);
		this.httpStatus = httpStatus;
		this.errorCode = errorCode;
	}

	public JwtAuthenticationException(String message, Throwable cause, int httpStatus,
		String errorCode) {
		super(message, cause);
		this.httpStatus = httpStatus;
		this.errorCode = errorCode;
	}

	public int getHttpStatus() {
		return httpStatus;
	}

	public String getErrorCode() {
		return errorCode;
	}
}
