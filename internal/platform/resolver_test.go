package platform

import "testing"

func TestParseResolverConfigIsReadOnlyModel(t *testing.T) {
	snapshot, err := ParseResolverConfig("nameserver 223.5.5.5\nsearch office.example corp.example\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Upstreams) != 1 || snapshot.Upstreams[0].Address != "223.5.5.5" {
		t.Fatalf("unexpected upstreams: %+v", snapshot.Upstreams)
	}
	if len(snapshot.SearchDomains) != 2 {
		t.Fatalf("unexpected search domains: %+v", snapshot.SearchDomains)
	}
}

func TestRejectsUnexpandedLocalProxy(t *testing.T) {
	if _, err := ParseResolverConfig("nameserver 127.0.0.53\n"); err == nil {
		t.Fatal("expected local-only proxy to require native expansion")
	}
}
