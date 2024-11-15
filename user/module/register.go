package module

import (
	"fmt"
)

var newModule = make(map[string]func(name string) IModule)

// RegisteFunc register module init function
func RegisteFunc(name string, f func(name string) IModule) {
	p := f(name)
	if p == nil {
		panic("function register probe is nil")
	}
	if _, dup := newModule[name]; dup {
		panic(fmt.Sprintf("function register called twice for probe %s", name))
	}
	newModule[name] = f
}

// GetModuleFunc get module init function by name
func GetModuleFunc(name string) func(name string) IModule {
	f, ok := newModule[name]
	if !ok {
		return nil
	}
	return f
}
