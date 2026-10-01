package profile

import "testing"

func TestTokenRoundTrip(t *testing.T) {
	chrome, _ := Lookup("chrome")
	c := *chrome
	h2 := *chrome.H2
	h2.HeaderPriority = nil // as a capture would arrive
	c.H2 = &h2
	c.Name = "captured-app"
	tok, err := c.Token()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("token is %d chars", len(tok))
	p, err := FromToken(tok)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "captured-app" || len(p.TLS.RawClientHello) != len(chrome.TLS.RawClientHello) {
		t.Fatal("round trip lost data")
	}
	if p.H2.HeaderPriority == nil || *p.H2.HeaderPriority != *chrome.H2.HeaderPriority {
		t.Fatalf("priority not inherited from matching settings: %+v", p.H2.HeaderPriority)
	}
}
