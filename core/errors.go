package core

import (
	"errors"
	"net"
)

type brokenError struct {
	cause error
}

func (e *brokenError) Error() string {
	return ErrConnBroken.Error() + ": " + e.cause.Error()
}

func (e *brokenError) Unwrap() []error {
	return []error{ErrConnBroken, e.cause}
}

func (e *brokenError) Timeout() bool {
	var netErr net.Error
	return errors.As(e.cause, &netErr) && netErr.Timeout()
}

func (e *brokenError) Temporary() bool {
	return false
}
