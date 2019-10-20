package authorization

import (
	"fmt"
	"github.com/zeebo/errs"
	"testing"
)

func TestSanity(t *testing.T) {
	testErr := errs.New("testing 123")
	errrrrrrs := []error {
		Error.Wrap(ErrDB.New("don't show me!")),
		Error.Wrap(ErrDB.Wrap(testErr)),
		Error.Wrap(testErr),
	}

	for _, e := range errrrrrrs {
		if ErrDB.Has(e) {
			e = Error.New("internal error")
		}

		fmt.Printf("internal: %v\n", ErrDB.Has(e))
		fmt.Printf("err: %s\n", e)
		fmt.Printf("unwrapped: %s\n", errs.Unwrap(e))
	}
}
