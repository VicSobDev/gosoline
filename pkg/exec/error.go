package exec

import (
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
)

type ErrorType int

const (
	// We don't know yet, let the other error checkers decide about this error. If the error is
	// not marked retryable by another checker, we will not retry it.
	ErrorTypeUnknown ErrorType = iota
	// Stop retrying, the error was actually a "success" and needs to be propagated to the caller
	// ("success" meaning something e.g. was not found, but will not magically appear just because
	// we retry a few more times)
	ErrorTypeOk
	// Immediately stop retrying and return this error to the caller
	ErrorTypePermanent
	// Retry the execution of the action
	ErrorTypeRetryable
)

type ErrorChecker func(result interface{}, err error) ErrorType

func CheckUsedClosedConnectionError(_ interface{}, err error) ErrorType {
	if IsUsedClosedConnectionError(err) {
		return ErrorTypeRetryable
	}

	return ErrorTypeUnknown
}

func IsUsedClosedConnectionError(err error) bool {
	return strings.Contains(err.Error(), "use of closed network connection")
}

func CheckConnectionError(_ interface{}, err error) ErrorType {
	if IsConnectionError(err) {
		return ErrorTypeRetryable
	}

	return ErrorTypeUnknown
}

func IsConnectionError(err error) bool {
	if errors.Is(err, io.EOF) {
		// End of file (EOF) is a common indication of a connection being closed.
		return true
	}

	// Check for errors that implement the net.Error interface for network-related issues.
	var netErr net.Error
	if errors.As(err, &netErr) {
		// Timeout or temporary errors are often indicative of connection issues.
		if netErr.Timeout() {
			return true
		}
	}

	// Check for *net.OpError, which can provide more specific details about network operations failures.
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		// This includes various syscall errors like "connection refused", "connection reset", etc.
		return true
	}
	if strings.Contains(err.Error(), "read: connection reset") {
		return true
	}

	return false
}

func CheckTimeoutError(_ interface{}, err error) ErrorType {
	if IsTimeoutError(err) {
		return ErrorTypeRetryable
	}

	return ErrorTypeUnknown
}

func IsTimeoutError(err error) bool {
	if errors.Is(err, syscall.ETIMEDOUT) {
		// Directly checks for a timeout error.
		return true
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		// net.Error provides a Timeout method to check if the error is a timeout.
		return netErr.Timeout()
	}

	return false
}

func CheckClientAwaitHeaderTimeoutError(_ interface{}, err error) ErrorType {
	if IsClientAwaitHeadersTimeoutError(err) {
		return ErrorTypeRetryable
	}

	return ErrorTypeUnknown
}

func IsClientAwaitHeadersTimeoutError(err error) bool {
	return strings.Contains(err.Error(), "(Client.Timeout exceeded while awaiting headers)")
}

func CheckTlsHandshakeTimeoutError(_ interface{}, err error) ErrorType {
	if IsTlsHandshakeTimeoutError(err) {
		return ErrorTypeRetryable
	}

	return ErrorTypeUnknown
}

func IsTlsHandshakeTimeoutError(err error) bool {
	return strings.Contains(err.Error(), "net/http: TLS handshake timeout")
}
