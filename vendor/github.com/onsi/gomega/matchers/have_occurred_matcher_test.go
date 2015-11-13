package matchers_test

import (
	"errors"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/matchers"
)

type CustomErr struct {
	msg string
}

func (e *CustomErr) Error() string {
	return e.msg
}

var _ = Describe("HaveOccurred", func() {
	It("should succeed if matching an error", func() {
		Ω(errors.New("Foo")).Should(HaveOccurred())
	})

	It("should not succeed with nil", func() {
		Ω(nil).ShouldNot(HaveOccurred())
	})

	It("should only support errors and nil", func() {
		success, err := (&HaveOccurredMatcher{}).Match("foo")
		Ω(success).Should(BeFalse())
		Ω(err).Should(HaveOccurred())

		success, err = (&HaveOccurredMatcher{}).Match("")
		Ω(success).Should(BeFalse())
		Ω(err).Should(HaveOccurred())
	})

	It("should succeed with pointer types that conform to error interface", func() {
		err := &CustomErr{"ohai"}
		Ω(err).Should(HaveOccurred())
	})

	It("should not succeed with nil pointers to types that conform to error interface", func() {
		var err *CustomErr = nil
		Ω(err).ShouldNot(HaveOccurred())
	})
})
