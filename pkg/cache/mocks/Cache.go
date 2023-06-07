// Code generated by mockery v2.22.1. DO NOT EDIT.

package mocks

import (
	time "time"

	mock "github.com/stretchr/testify/mock"
)

// Cache is an autogenerated mock type for the Cache type
type Cache[T interface{}] struct {
	mock.Mock
}

// Contains provides a mock function with given fields: key
func (_m *Cache[T]) Contains(key string) bool {
	ret := _m.Called(key)

	var r0 bool
	if rf, ok := ret.Get(0).(func(string) bool); ok {
		r0 = rf(key)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// Expire provides a mock function with given fields: key
func (_m *Cache[T]) Expire(key string) bool {
	ret := _m.Called(key)

	var r0 bool
	if rf, ok := ret.Get(0).(func(string) bool); ok {
		r0 = rf(key)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// Get provides a mock function with given fields: key
func (_m *Cache[T]) Get(key string) (T, bool) {
	ret := _m.Called(key)

	var r0 T
	var r1 bool
	if rf, ok := ret.Get(0).(func(string) (T, bool)); ok {
		return rf(key)
	}
	if rf, ok := ret.Get(0).(func(string) T); ok {
		r0 = rf(key)
	} else {
		r0 = ret.Get(0).(T)
	}

	if rf, ok := ret.Get(1).(func(string) bool); ok {
		r1 = rf(key)
	} else {
		r1 = ret.Get(1).(bool)
	}

	return r0, r1
}

// Provide provides a mock function with given fields: key, provider
func (_m *Cache[T]) Provide(key string, provider func() T) T {
	ret := _m.Called(key, provider)

	var r0 T
	if rf, ok := ret.Get(0).(func(string, func() T) T); ok {
		r0 = rf(key, provider)
	} else {
		r0 = ret.Get(0).(T)
	}

	return r0
}

// ProvideWithError provides a mock function with given fields: key, provider
func (_m *Cache[T]) ProvideWithError(key string, provider func() (T, error)) (T, error) {
	ret := _m.Called(key, provider)

	var r0 T
	var r1 error
	if rf, ok := ret.Get(0).(func(string, func() (T, error)) (T, error)); ok {
		return rf(key, provider)
	}
	if rf, ok := ret.Get(0).(func(string, func() (T, error)) T); ok {
		r0 = rf(key, provider)
	} else {
		r0 = ret.Get(0).(T)
	}

	if rf, ok := ret.Get(1).(func(string, func() (T, error)) error); ok {
		r1 = rf(key, provider)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Set provides a mock function with given fields: key, value
func (_m *Cache[T]) Set(key string, value T) {
	_m.Called(key, value)
}

// SetX provides a mock function with given fields: key, value, ttl
func (_m *Cache[T]) SetX(key string, value T, ttl time.Duration) {
	_m.Called(key, value, ttl)
}

type mockConstructorTestingTNewCache interface {
	mock.TestingT
	Cleanup(func())
}

// NewCache creates a new instance of Cache. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewCache[T interface{}](t mockConstructorTestingTNewCache) *Cache[T] {
	mock := &Cache[T]{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
