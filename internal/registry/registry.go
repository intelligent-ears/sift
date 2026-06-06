package registry

import (
	"github.com/sift-scanner/sift/pkg/module"
)

var modules []module.Module

// Register registers a new module in the central registry.
// Usually called from module package init() functions.
func Register(m module.Module) {
	modules = append(modules, m)
}

// All returns all registered modules.
func All() []module.Module {
	return modules
}
