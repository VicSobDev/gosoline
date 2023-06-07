// Code generated by mockery v2.22.1. DO NOT EDIT.

package mocks

import (
	tracing "github.com/justtrackio/gosoline/pkg/tracing"
	mock "github.com/stretchr/testify/mock"
)

// TraceAble is an autogenerated mock type for the TraceAble type
type TraceAble struct {
	mock.Mock
}

// GetTrace provides a mock function with given fields:
func (_m *TraceAble) GetTrace() *tracing.Trace {
	ret := _m.Called()

	var r0 *tracing.Trace
	if rf, ok := ret.Get(0).(func() *tracing.Trace); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*tracing.Trace)
		}
	}

	return r0
}

type mockConstructorTestingTNewTraceAble interface {
	mock.TestingT
	Cleanup(func())
}

// NewTraceAble creates a new instance of TraceAble. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewTraceAble(t mockConstructorTestingTNewTraceAble) *TraceAble {
	mock := &TraceAble{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
