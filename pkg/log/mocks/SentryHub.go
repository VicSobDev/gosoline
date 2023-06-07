// Code generated by mockery v2.22.1. DO NOT EDIT.

package mocks

import (
	sentry "github.com/getsentry/sentry-go"
	mock "github.com/stretchr/testify/mock"

	time "time"
)

// SentryHub is an autogenerated mock type for the SentryHub type
type SentryHub struct {
	mock.Mock
}

// CaptureException provides a mock function with given fields: exception
func (_m *SentryHub) CaptureException(exception error) *sentry.EventID {
	ret := _m.Called(exception)

	var r0 *sentry.EventID
	if rf, ok := ret.Get(0).(func(error) *sentry.EventID); ok {
		r0 = rf(exception)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*sentry.EventID)
		}
	}

	return r0
}

// ConfigureScope provides a mock function with given fields: f
func (_m *SentryHub) ConfigureScope(f func(*sentry.Scope)) {
	_m.Called(f)
}

// Flush provides a mock function with given fields: timeout
func (_m *SentryHub) Flush(timeout time.Duration) bool {
	ret := _m.Called(timeout)

	var r0 bool
	if rf, ok := ret.Get(0).(func(time.Duration) bool); ok {
		r0 = rf(timeout)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// WithScope provides a mock function with given fields: f
func (_m *SentryHub) WithScope(f func(*sentry.Scope)) {
	_m.Called(f)
}

type mockConstructorTestingTNewSentryHub interface {
	mock.TestingT
	Cleanup(func())
}

// NewSentryHub creates a new instance of SentryHub. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewSentryHub(t mockConstructorTestingTNewSentryHub) *SentryHub {
	mock := &SentryHub{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
