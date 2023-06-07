// Code generated by mockery v2.22.1. DO NOT EDIT.

package mocks

import (
	context "context"

	mock "github.com/stretchr/testify/mock"
)

// RunnableCallback is an autogenerated mock type for the RunnableCallback type
type RunnableCallback struct {
	mock.Mock
}

// Run provides a mock function with given fields: ctx
func (_m *RunnableCallback) Run(ctx context.Context) error {
	ret := _m.Called(ctx)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context) error); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

type mockConstructorTestingTNewRunnableCallback interface {
	mock.TestingT
	Cleanup(func())
}

// NewRunnableCallback creates a new instance of RunnableCallback. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewRunnableCallback(t mockConstructorTestingTNewRunnableCallback) *RunnableCallback {
	mock := &RunnableCallback{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
