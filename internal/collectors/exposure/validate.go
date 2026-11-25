package exposure

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// Patterns of scan inputs. Never written after initialisation.
var (
	// a host name: labels of letters, digits and inner hyphens; it can never start with "-" (an nmap option)
	hostName = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$`)
	portList = regexp.MustCompile(`^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$`)
)

const maxHostName = 253

// ValidTarget reports whether s may be given to nmap as a target: an IP address or a host name. Anything else
// (an option such as "-iL file", a range, a glob, white space) is refused: a scan target is never an argument
// nmap could read as something else.
func ValidTarget(s string) bool {
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Zone() == "" || hostName.MatchString(a.Zone())
	}
	return len(s) <= maxHostName && hostName.MatchString(s)
}

// ValidPorts reports whether s is a port list for nmap -p: ports and ranges (1-65535), comma-separated.
func ValidPorts(s string) bool {
	if !portList.MatchString(s) {
		return false
	}
	for _, part := range strings.Split(s, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		if !validPort(lo) || isRange && (!validPort(hi) || atoi(hi) < atoi(lo)) {
			return false
		}
	}
	return true
}

func validPort(s string) bool {
	n := atoi(s)
	return n >= 1 && n <= 65535
}

func atoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return -1
	}
	return n
}
