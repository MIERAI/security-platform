package exposure

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strconv"
)

// nmap -oX output, the parts the probe reads.
type nmapRun struct {
	Hosts []nmapHost `xml:"host"`
}

type nmapHost struct {
	TimedOut  string `xml:"timedout,attr"`
	Addresses []struct {
		Addr string `xml:"addr,attr"`
	} `xml:"address"`
	Ports []nmapPort `xml:"ports>port"`
}

type nmapPort struct {
	PortID string `xml:"portid,attr"`
	State  *struct {
		State string `xml:"state,attr"`
	} `xml:"state"`
	Service *struct {
		Name *string `xml:"name,attr"`
	} `xml:"service"`
}

// Scan is what one nmap run found: per address, the open ports and nmap's service name for each (nil when nmap
// gave a <service> without a name, "" when it gave none), and the addresses nmap gave up on (host timeout).
type Scan struct {
	Open     map[string]map[int]any
	TimedOut map[string]bool
}

// ParseNmapXML reads nmap's XML report. Only ports in state "open" count (filtered, closed and the rest are not
// exposure); a host without an address or a port without a numeric id is skipped.
func ParseNmapXML(data []byte) (Scan, error) {
	var run nmapRun
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true
	if err := dec.Decode(&run); err != nil {
		return Scan{}, fmt.Errorf("nmap XML: %w", err)
	}
	s := Scan{Open: map[string]map[int]any{}, TimedOut: map[string]bool{}}
	for i := range run.Hosts {
		s.addHost(&run.Hosts[i])
	}
	return s, nil
}

func (s *Scan) addHost(h *nmapHost) {
	if len(h.Addresses) == 0 {
		return
	}
	ip := h.Addresses[0].Addr
	if h.TimedOut == "true" {
		s.TimedOut[ip] = true
	}
	for _, p := range h.Ports {
		n, ok := openPort(&p)
		if !ok {
			continue
		}
		if s.Open[ip] == nil {
			s.Open[ip] = map[int]any{}
		}
		s.Open[ip][n] = p.service()
	}
}

// openPort is the number of a port in state "open" (false for any other state or a malformed id).
func openPort(p *nmapPort) (int, bool) {
	n, err := strconv.Atoi(p.PortID)
	if err != nil || n < 0 || n > 65535 || p.State == nil || p.State.State != "open" {
		return 0, false
	}
	return n, true
}

// service is nmap's service name: "" without a <service>, nil for a <service> without a name.
func (p *nmapPort) service() any {
	if p.Service == nil {
		return ""
	}
	if p.Service.Name == nil {
		return nil
	}
	return *p.Service.Name
}
