package conftest

import (
	. "github.com/khulnasoft/starboard/itest/starboard-operator/behavior"
	. "github.com/onsi/ginkgo"
)

var _ = Describe("Conftest", ConfigurationCheckerBehavior(&inputs))
