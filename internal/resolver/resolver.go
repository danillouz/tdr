package resolver

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/danillouz/tdr/internal/dns"
)

// Resolve resolves a domain name to a resource record value.
func Resolve(name string, qt dns.QType) (string, error) {
	// Make sure `name` is a Fully Qualified Domain Name (FQDN).
	if !strings.HasSuffix(name, ".") {
		name += "."
	}

	server := getRootNameServer()
	for {
		msg, err := lookup(server, name, qt)
		if err != nil {
			return "", fmt.Errorf("failed to lookup name: %v", err)
		}

		// When an answer can be retrieved, resolving is done.
		if an := getAnswer(msg); an != "" {
			return an, nil
		}

		// When there's no answer, check the additional records for a name server's
		// IP address, and use that as the name server to lookup the domain name.
		if ip := getAdditional(msg); ip != nil {
			server = ip
			continue
		}

		// When there are no additional records, use the domain name of an
		// authoritative name server to _recursively_ get an answer.
		if name := getAuthority(msg); name != "" {
			an, err := Resolve(name, dns.TypeA)
			if err != nil {
				return "", fmt.Errorf(
					"failed to recursively resolve authority %s during lookup: %v",
					name, err,
				)
			}

			// Use the authoritative name server's IP address as the name server to
			// lookup the domain name.
			server = net.ParseIP(an)
			continue
		}

		return "", fmt.Errorf("no answer found")
	}
}

// getRootNameServer returns the IP address of a root name server.
func getRootNameServer() net.IP {
	// TODO: use root hint file
	// See: https://www.iana.org/domains/root/files

	// Root name server: "a.root-servers.net".
	return net.ParseIP("198.41.0.4")
}

// lookup looks up the resource record(s) for the domain name.
func lookup(server net.IP, name string, qt dns.QType) (*dns.Msg, error) {
	fmt.Printf("looking up %q using name server %q\n", name, server)

	addr := fmt.Sprintf("%s:53", server)
	d := net.Dialer{
		Timeout: time.Second * 5,
	}
	conn, err := d.DialContext(context.Background(), "udp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial address %s: %v", addr, err)
	}
	defer conn.Close()

	query := new(dns.Msg)
	if err := query.SetQuery(name, qt); err != nil {
		return nil, fmt.Errorf("failed to set dns query: %v", err)
	}

	queryb, err := query.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack dns query: %v", err)
	}
	if _, err := conn.Write(queryb); err != nil {
		return nil, fmt.Errorf("failed to write dns query: %v", err)
	}

	// Max UDP message size is 512 bytes.
	// See: https://datatracker.ietf.org/doc/html/rfc1035#section-2.3.4
	buff := make([]byte, 512)
	if _, err := conn.Read(buff); err != nil {
		return nil, fmt.Errorf("failed to read dns response: %v", err)
	}
	resp := new(dns.Msg)
	if _, err := resp.Unpack(buff); err != nil {
		return nil, fmt.Errorf("failed to unpack dns response: %v", err)
	}

	return resp, nil
}

// getAnswer retrieves the first unpacked answer resource record.
func getAnswer(m *dns.Msg) string {
	for _, an := range m.Answer {
		return an.RDataUnpacked
	}

	return ""
}

// getAuthority retrieves the first unpacked authority resource record.
func getAuthority(m *dns.Msg) string {
	for _, ns := range m.Authority {
		return ns.RDataUnpacked
	}

	return ""
}

// getAdditional retrieves the first unpacked additional resource record.
func getAdditional(m *dns.Msg) net.IP {
	for _, ar := range m.Additional {
		return net.ParseIP(ar.RDataUnpacked)
	}

	return nil
}
