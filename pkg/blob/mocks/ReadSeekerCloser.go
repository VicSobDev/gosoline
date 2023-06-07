// Code generated by mockery v2.22.1. DO NOT EDIT.

package mocks

import mock "github.com/stretchr/testify/mock"

// ReadSeekerCloser is an autogenerated mock type for the ReadSeekerCloser type
type ReadSeekerCloser struct {
	mock.Mock
}

// Close provides a mock function with given fields:
func (_m *ReadSeekerCloser) Close() error {
	ret := _m.Called()

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Read provides a mock function with given fields: p
func (_m *ReadSeekerCloser) Read(p []byte) (int, error) {
	ret := _m.Called(p)

	var r0 int
	var r1 error
	if rf, ok := ret.Get(0).(func([]byte) (int, error)); ok {
		return rf(p)
	}
	if rf, ok := ret.Get(0).(func([]byte) int); ok {
		r0 = rf(p)
	} else {
		r0 = ret.Get(0).(int)
	}

	if rf, ok := ret.Get(1).(func([]byte) error); ok {
		r1 = rf(p)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Seek provides a mock function with given fields: offset, whence
func (_m *ReadSeekerCloser) Seek(offset int64, whence int) (int64, error) {
	ret := _m.Called(offset, whence)

	var r0 int64
	var r1 error
	if rf, ok := ret.Get(0).(func(int64, int) (int64, error)); ok {
		return rf(offset, whence)
	}
	if rf, ok := ret.Get(0).(func(int64, int) int64); ok {
		r0 = rf(offset, whence)
	} else {
		r0 = ret.Get(0).(int64)
	}

	if rf, ok := ret.Get(1).(func(int64, int) error); ok {
		r1 = rf(offset, whence)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

type mockConstructorTestingTNewReadSeekerCloser interface {
	mock.TestingT
	Cleanup(func())
}

// NewReadSeekerCloser creates a new instance of ReadSeekerCloser. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewReadSeekerCloser(t mockConstructorTestingTNewReadSeekerCloser) *ReadSeekerCloser {
	mock := &ReadSeekerCloser{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
