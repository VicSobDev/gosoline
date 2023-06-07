// Code generated by mockery v2.22.1. DO NOT EDIT.

package mocks

import (
	context "context"

	db_repo "github.com/justtrackio/gosoline/pkg/db-repo"

	mock "github.com/stretchr/testify/mock"
)

// BaseCreateHandler is an autogenerated mock type for the BaseCreateHandler type
type BaseCreateHandler struct {
	mock.Mock
}

// GetCreateInput provides a mock function with given fields:
func (_m *BaseCreateHandler) GetCreateInput() interface{} {
	ret := _m.Called()

	var r0 interface{}
	if rf, ok := ret.Get(0).(func() interface{}); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(interface{})
		}
	}

	return r0
}

// TransformCreate provides a mock function with given fields: ctx, input, model
func (_m *BaseCreateHandler) TransformCreate(ctx context.Context, input interface{}, model db_repo.ModelBased) error {
	ret := _m.Called(ctx, input, model)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, interface{}, db_repo.ModelBased) error); ok {
		r0 = rf(ctx, input, model)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

type mockConstructorTestingTNewBaseCreateHandler interface {
	mock.TestingT
	Cleanup(func())
}

// NewBaseCreateHandler creates a new instance of BaseCreateHandler. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewBaseCreateHandler(t mockConstructorTestingTNewBaseCreateHandler) *BaseCreateHandler {
	mock := &BaseCreateHandler{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
