// Code generated by mockery v2.22.1. DO NOT EDIT.

package mocks

import (
	context "context"

	mock "github.com/stretchr/testify/mock"
)

// BatchConsumerCallback is an autogenerated mock type for the BatchConsumerCallback type
type BatchConsumerCallback struct {
	mock.Mock
}

// Consume provides a mock function with given fields: ctx, models, attributes
func (_m *BatchConsumerCallback) Consume(ctx context.Context, models []interface{}, attributes []map[string]interface{}) ([]bool, error) {
	ret := _m.Called(ctx, models, attributes)

	var r0 []bool
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, []interface{}, []map[string]interface{}) ([]bool, error)); ok {
		return rf(ctx, models, attributes)
	}
	if rf, ok := ret.Get(0).(func(context.Context, []interface{}, []map[string]interface{}) []bool); ok {
		r0 = rf(ctx, models, attributes)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]bool)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, []interface{}, []map[string]interface{}) error); ok {
		r1 = rf(ctx, models, attributes)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetModel provides a mock function with given fields: attributes
func (_m *BatchConsumerCallback) GetModel(attributes map[string]interface{}) interface{} {
	ret := _m.Called(attributes)

	var r0 interface{}
	if rf, ok := ret.Get(0).(func(map[string]interface{}) interface{}); ok {
		r0 = rf(attributes)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(interface{})
		}
	}

	return r0
}

type mockConstructorTestingTNewBatchConsumerCallback interface {
	mock.TestingT
	Cleanup(func())
}

// NewBatchConsumerCallback creates a new instance of BatchConsumerCallback. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewBatchConsumerCallback(t mockConstructorTestingTNewBatchConsumerCallback) *BatchConsumerCallback {
	mock := &BatchConsumerCallback{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
