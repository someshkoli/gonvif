package onvif

import (
	"net"
	"regexp"
)

func interfaceToString(src interface{}) string {
	data, _ := src.(string)
	return data
}

func getInterfaceAddrs() ([]string, error) {
	infAddrs, err := net.InterfaceAddrs()
	if err != nil {
		return []string{}, err
	}

	addrs := []string{}
	for _, ip := range infAddrs {
		ipAddr, ok := ip.(*net.IPNet)
		if ok && !ipAddr.IP.IsLoopback() && ipAddr.IP.To4() != nil {
			addrs = append(addrs, ipAddr.IP.String())
		}
	}

	return addrs, nil
}

func cleanSOAPMessage(message string) string {
	message = regexp.MustCompile(`\>\s+\<`).ReplaceAllString(message, "><")
	message = regexp.MustCompile(`\s+`).ReplaceAllString(message, " ")
	return message
}
