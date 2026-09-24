package transport

import (
	"reflect"
	"testing"
)

func TestNetstackLayoutMatchesCurrentVersion(t *testing.T) {
	if err := checkNetstackLayout(); err != nil {
		t.Fatal(err)
	}
}

func TestCompareStructPrefixRejectsMismatch(t *testing.T) {
	type renamed struct {
		endpoint any
		stack    any
	}
	type view struct {
		ep    any
		stack any
	}
	type retyped struct {
		ep    int
		stack any
	}
	type short struct {
		ep any
	}
	for _, actual := range []any{renamed{}, retyped{}, short{}, 0} {
		if err := compareStructPrefix(reflect.TypeOf(actual), reflect.TypeOf(view{})); err == nil {
			t.Fatalf("layout %T accepted", actual)
		}
	}
	type matching struct {
		ep    any
		stack any
		extra int
	}
	if err := compareStructPrefix(reflect.TypeOf(matching{}), reflect.TypeOf(view{})); err != nil {
		t.Fatal(err)
	}
}
