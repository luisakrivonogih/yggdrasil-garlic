package garlic

import "testing"

func TestServicePortTable(t *testing.T) {
	table, err := ServiceConfig{LocalAddr: "127.0.0.1:8080", TLSLocalAddr: "127.0.0.1:8443", Ports: map[uint16]string{22: "127.0.0.1:22", 9000: "[::1]:9000"}}.PortTable()
	if err != nil || len(table) != 4 || table[80] != "127.0.0.1:8080" || table[443] != "127.0.0.1:8443" || table[22] != "127.0.0.1:22" {
		t.Fatalf("table = %v, %v", table, err)
	}
	// A synonym that repeats the same address is fine.
	if _, err := (ServiceConfig{LocalAddr: "127.0.0.1:8080", Ports: map[uint16]string{80: "127.0.0.1:8080"}}).PortTable(); err != nil {
		t.Fatal(err)
	}
	for name, cfg := range map[string]ServiceConfig{
		"conflict":     {LocalAddr: "127.0.0.1:1", Ports: map[uint16]string{80: "127.0.0.1:2"}},
		"tls conflict": {TLSLocalAddr: "127.0.0.1:1", Ports: map[uint16]string{443: "127.0.0.1:2"}},
		"port zero":    {Ports: map[uint16]string{0: "127.0.0.1:2"}},
		"bad address":  {Ports: map[uint16]string{7000: "nonsense"}},
		"empty":        {},
	} {
		if _, err := cfg.PortTable(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
