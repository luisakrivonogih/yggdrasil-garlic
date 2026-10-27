package garlic_test

import (
	"encoding/hex"
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/yggdrasil-network/yggdrasil-go/src/garlic"
)

func expectDomainAdminError(t *testing.T, socket, request string, args map[string]interface{}, want string) {
	t.Helper()
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(map[string]interface{}{"request": request, "arguments": args}); err != nil {
		t.Fatal(err)
	}
	var resp struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Status != "error" || !strings.Contains(resp.Error, want) {
		t.Fatalf("%s: status=%q, error=%q; want %q", request, resp.Status, resp.Error, want)
	}
}

func TestDomainAdminPublicationAndResolution(t *testing.T) {
	g, c := newTestGarlicWithCore(t)
	socket := newTestAdminSocket(t, c, g)
	identity := callAdmin(t, socket, "getGarlicIdentity")
	for _, serviceID := range []string{"", "737663"} {
		t.Run("service="+serviceID, func(t *testing.T) {
			args := map[string]interface{}{}
			if serviceID != "" {
				args["serviceId"] = serviceID
			}
			resp := callAdminWithArgs(t, socket, "getGarlicDomain", args)
			domain := resp["domain"].(string)
			gid, err := garlic.ParseDomain(domain)
			if err != nil || resp["gid"] != gid.String() || resp["serviceId"] != serviceID {
				t.Fatalf("getGarlicDomain: %v, %v", resp, err)
			}
			if serviceID == "" && identity["domain"] != domain {
				t.Fatalf("default domain disagrees with identity: %v", identity)
			}
			expectDomainAdminError(t, socket, "resolveGarlicDomain", map[string]interface{}{"domain": domain}, garlic.ErrGIDNotFound.Error())
			introKey := hex.EncodeToString(c.PublicKey())
			args["introPoints"] = introKey
			published := callAdminWithArgs(t, socket, "publishGarlicService", args)
			if published["domain"] != domain || published["gid"] != gid.String() {
				t.Fatalf("publish disagrees with get: %v vs %v", published, resp)
			}
			resolved := callAdminWithArgs(t, socket, "resolveGarlicDomain", map[string]interface{}{"domain": strings.ToUpper(domain) + "."})
			points, ok := resolved["introPoints"].([]interface{})
			if !ok || len(points) != 1 || points[0] != introKey || resolved["domain"] != domain || resolved["gid"] != gid.String() {
				t.Fatalf("resolve: %v", resolved)
			}
			legacy := callAdminWithArgs(t, socket, "lookupGarlicService", map[string]interface{}{"gid": gid.String()})
			if got := legacy["introPoints"].([]interface{}); len(got) != 1 || got[0] != introKey {
				t.Fatalf("legacy lookup: %v", legacy)
			}
		})
	}
}

func TestDomainAdminRejectsInvalidRequests(t *testing.T) {
	g, c := newTestGarlicWithCore(t)
	socket := newTestAdminSocket(t, c, g)
	expectDomainAdminError(t, socket, "getGarlicDomain", map[string]interface{}{"serviceId": "xyz"}, "invalid serviceId")
	expectDomainAdminError(t, socket, "getGarlicDomain", map[string]interface{}{"serviceId": strings.Repeat("ab", 65)}, garlic.ErrServiceIDTooLarge.Error())
	expectDomainAdminError(t, socket, "resolveGarlicDomain", map[string]interface{}{"domain": "example.yggg"}, garlic.ErrInvalidDomain.Error())
	expectDomainAdminError(t, socket, "resolveGarlicDomain", map[string]interface{}{}, "domain")
}
