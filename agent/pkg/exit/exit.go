package exit

import (
	"errors"
	"fmt"
)

// ExitCoder 描述可携带退出码的错误
type ExitCoder interface {
	error
	ExitCode() int
}

// Error 实现带退出码的错误对象
type Error struct {
	Code int
	Err  error
}

// Error 实现 error 接口
func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Err == nil {
		return fmt.Sprintf("exit code %d", e.Code)
	}
	return e.Err.Error()
}

// Unwrap 允许 errors.Unwrap
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// ExitCode 返回退出码
func (e *Error) ExitCode() int {
	if e == nil {
		return 0
	}
	return e.Code
}

// New 构造带退出码的错误
func New(code int, err error) error {
	if err == nil {
		return nil
	}
	var exitErr *Error
	if errors.As(err, &exitErr) {
		return err
	}
	return &Error{
		Code: code,
		Err:  err,
	}
}
