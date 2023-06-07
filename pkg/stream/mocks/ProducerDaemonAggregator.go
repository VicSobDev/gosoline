// Code generated by mockery v2.22.1. DO NOT EDIT.

package mocks

import (
	context "context"

	stream "github.com/justtrackio/gosoline/pkg/stream"
	mock "github.com/stretchr/testify/mock"
)

// ProducerDaemonAggregator is an autogenerated mock type for the ProducerDaemonAggregator type
type ProducerDaemonAggregator struct {
	mock.Mock
}

// Flush provides a mock function with given fields:
func (_m *ProducerDaemonAggregator) Flush() ([]stream.AggregateFlush, error) {
	ret := _m.Called()

	var r0 []stream.AggregateFlush
	var r1 error
	if rf, ok := ret.Get(0).(func() ([]stream.AggregateFlush, error)); ok {
		return rf()
	}
	if rf, ok := ret.Get(0).(func() []stream.AggregateFlush); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]stream.AggregateFlush)
		}
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Write provides a mock function with given fields: ctx, msg
func (_m *ProducerDaemonAggregator) Write(ctx context.Context, msg *stream.Message) ([]stream.AggregateFlush, error) {
	ret := _m.Called(ctx, msg)

	var r0 []stream.AggregateFlush
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *stream.Message) ([]stream.AggregateFlush, error)); ok {
		return rf(ctx, msg)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *stream.Message) []stream.AggregateFlush); ok {
		r0 = rf(ctx, msg)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]stream.AggregateFlush)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *stream.Message) error); ok {
		r1 = rf(ctx, msg)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

type mockConstructorTestingTNewProducerDaemonAggregator interface {
	mock.TestingT
	Cleanup(func())
}

// NewProducerDaemonAggregator creates a new instance of ProducerDaemonAggregator. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewProducerDaemonAggregator(t mockConstructorTestingTNewProducerDaemonAggregator) *ProducerDaemonAggregator {
	mock := &ProducerDaemonAggregator{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
