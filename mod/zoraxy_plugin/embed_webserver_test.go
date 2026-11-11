package zoraxy_plugin

import "testing"

func TestSanitizeCSRFToken(t *testing.T) {
	ok := []string{"abc123", "dGVzdC10b2tlbg==", "A-b_c.d+e/f=", "x"}
	for _, v := range ok {
		if got := sanitizeCSRFToken(v); got != v {
			t.Errorf("%q is a plain token and must be kept, got %q", v, got)
		}
	}
	bad := []string{
		"", `"; alert(1); "`, "</script><script>alert(1)</script>", `x" onload="alert(1)`, "a b", "a\nb", "a'b", "<b>", "a;b",
		"\u2028", string(make([]byte, 600)), "aaaa" + string(rune(0)),
	}
	for _, v := range bad {
		if got := sanitizeCSRFToken(v); got != "missing-csrf-token" {
			t.Errorf("%q must be replaced by the placeholder, got %q", v, got)
		}
	}
	long := make([]byte, 513)
	for i := range long {
		long[i] = 'a'
	}
	if got := sanitizeCSRFToken(string(long)); got != "missing-csrf-token" {
		t.Errorf("a 513-character token must be refused")
	}
}
