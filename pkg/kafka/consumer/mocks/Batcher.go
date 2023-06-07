// Code generated by mockery v2.22.1. DO NOT EDIT.

package mocks

import (
	context "context"

	kafka "github.com/segmentio/kafka-go"
	mock "github.com/stretchr/testify/mock"
)

// Batcher is an autogenerated mock type for the Batcher type
type Batcher struct {
	mock.Mock
}

// Get provides a mock function with given fields: ctx
func (_m *Batcher) Get(ctx context.Context) []kafka.Message {
	ret := _m.Called(ctx)

	var r0 []kafka.Message
	if rf, ok := ret.Get(0).(func(context.Context) []kafka.Message); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]kafka.Message)
		}
	}

	return r0
}

type mockConstructorTestingTNewBatcher interface {
	mock.TestingT
	Cleanup(func())
}

// NewBatcher creates a new instance of Batcher. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewBatcher(t mockConstructorTestingTNewBatcher) *Batcher {
	mock := &Batcher{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
