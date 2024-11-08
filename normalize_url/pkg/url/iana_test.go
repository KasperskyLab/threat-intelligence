package url

import "testing"

func TestIANA(t *testing.T) {
	expected := 379
	if len(IANASchemes) != expected {
		t.Fatalf("Amount of IANA Schemes must be %d", expected)
	}
}
