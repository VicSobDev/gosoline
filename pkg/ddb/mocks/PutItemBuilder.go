// Code generated by mockery v2.22.1. DO NOT EDIT.

package mocks

import (
	dynamodb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddb "github.com/justtrackio/gosoline/pkg/ddb"

	expression "github.com/aws/aws-sdk-go-v2/feature/dynamodb/expression"

	mock "github.com/stretchr/testify/mock"
)

// PutItemBuilder is an autogenerated mock type for the PutItemBuilder type
type PutItemBuilder struct {
	mock.Mock
}

// Build provides a mock function with given fields: item
func (_m *PutItemBuilder) Build(item interface{}) (*dynamodb.PutItemInput, error) {
	ret := _m.Called(item)

	var r0 *dynamodb.PutItemInput
	var r1 error
	if rf, ok := ret.Get(0).(func(interface{}) (*dynamodb.PutItemInput, error)); ok {
		return rf(item)
	}
	if rf, ok := ret.Get(0).(func(interface{}) *dynamodb.PutItemInput); ok {
		r0 = rf(item)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*dynamodb.PutItemInput)
		}
	}

	if rf, ok := ret.Get(1).(func(interface{}) error); ok {
		r1 = rf(item)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ReturnAllOld provides a mock function with given fields:
func (_m *PutItemBuilder) ReturnAllOld() ddb.PutItemBuilder {
	ret := _m.Called()

	var r0 ddb.PutItemBuilder
	if rf, ok := ret.Get(0).(func() ddb.PutItemBuilder); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(ddb.PutItemBuilder)
		}
	}

	return r0
}

// ReturnNone provides a mock function with given fields:
func (_m *PutItemBuilder) ReturnNone() ddb.PutItemBuilder {
	ret := _m.Called()

	var r0 ddb.PutItemBuilder
	if rf, ok := ret.Get(0).(func() ddb.PutItemBuilder); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(ddb.PutItemBuilder)
		}
	}

	return r0
}

// WithCondition provides a mock function with given fields: cond
func (_m *PutItemBuilder) WithCondition(cond expression.ConditionBuilder) ddb.PutItemBuilder {
	ret := _m.Called(cond)

	var r0 ddb.PutItemBuilder
	if rf, ok := ret.Get(0).(func(expression.ConditionBuilder) ddb.PutItemBuilder); ok {
		r0 = rf(cond)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(ddb.PutItemBuilder)
		}
	}

	return r0
}

type mockConstructorTestingTNewPutItemBuilder interface {
	mock.TestingT
	Cleanup(func())
}

// NewPutItemBuilder creates a new instance of PutItemBuilder. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewPutItemBuilder(t mockConstructorTestingTNewPutItemBuilder) *PutItemBuilder {
	mock := &PutItemBuilder{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
