package onvif

import (
	"errors"
	"net"
	"strings"
	"time"

	"github.com/clbanning/mxj"
	uuid "github.com/satori/go.uuid"
)

var errWrongDiscoveryResponse = errors.New("Response is not related to discovery request")

func getDiscoveryProbeMessage(requestID string) string {
	request := `
	<?xml version="1.0" encoding="UTF-8"?>
	<e:Envelope
		xmlns:e="http://www.w3.org/2003/05/soap-envelope"
		xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
		xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
		xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
		<e:Header>
			<w:MessageID>` + requestID + `</w:MessageID>
			<w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
			<w:Action a:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe
			</w:Action>
		</e:Header>
		<e:Body>
			<d:Probe>
				<d:Types>dn:NetworkVideoTransmitter</d:Types>
			</d:Probe>
		</e:Body>
	</e:Envelope>`

	return cleanSOAPMessage(request)
}

func StartDiscovery(timeout time.Duration) ([]Device, error) {
	ipAddrs, err := getInterfaceAddrs()
	if err != nil {
		return []Device{}, err
	}

	discoveryResult := []Device{}

	for _, ipAddr := range ipAddrs {
		devices, err := DiscoverDevices(ipAddr, timeout)
		if err != nil {
			return []Device{}, err
		}

		discoveryResult = append(discoveryResult, devices...)
	}

	return discoveryResult, nil
}

func DiscoverDevices(ip string, timeout time.Duration) ([]Device, error) {
	requestID := uuid.NewV4()
	probeMessage := getDiscoveryProbeMessage(requestID.String())

	localAddr, err := net.ResolveUDPAddr("udp4", ip+":0")
	if err != nil {
		return []Device{}, err
	}

	multicastAddr, err := net.ResolveUDPAddr("udp4", "239.225.225.250:3702")
	if err != nil {
		return []Device{}, err
	}

	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return []Device{}, err
	}
	defer conn.Close()

	err = conn.SetDeadline(time.Now().Add(timeout))
	if err != nil {
		return []Device{}, err
	}

	_, err = conn.WriteToUDP([]byte(probeMessage), multicastAddr)
	if err != nil {
		return []Device{}, err
	}

	discoveryResults := []Device{}

	for {
		buffer := make([]byte, 10*1024)
		_, _, err := conn.ReadFromUDP(buffer)

		// check connection timeout
		if err != nil {
			if connErr, ok := err.(net.Error); ok && connErr.Timeout() {
				break
			} else {
				return discoveryResults, err
			}
		}

		device, err := GetDeviceFromDiscoverProbeResponse(requestID.String(), buffer)
		if err != nil && err != errWrongDiscoveryResponse {
			return []Device{}, err
		}

		discoveryResults = append(discoveryResults, device)
	}

	return discoveryResults, nil
}

func GetDeviceFromDiscoverProbeResponse(messageID string, response []byte) (Device, error) {
	result := Device{}

	mapXML, err := mxj.NewMapXml(response)
	if err != nil {
		return result, err
	}

	responseID, err := mapXML.ValueForPathString("Envolope.Header.RelatesTo")
	if err != nil {
		if messageID != responseID {
			return result, errWrongDiscoveryResponse
		} else {
			return result, err
		}
	}

	deviceID, _ := mapXML.ValueForPathString("Envelope.Body.ProbeMatches.ProbeMatch.EndpointReference.Address")
	deviceID = strings.Replace(deviceID, "urn:uuid:", "", 1)

	deviceName := ""
	scopes, _ := mapXML.ValueForPathString("Envelope.Body.ProbeMatches.ProbeMatch.Scopes")
	for _, scope := range strings.Split(scopes, " ") {
		if strings.HasPrefix(scope, "onvif://www.onvif.org/name/") {
			deviceName = strings.Replace(scope, "onvif://www.onvif.org/name/", "", 1)
			deviceName = strings.Replace(deviceName, "_", " ", -1)
			break
		}
	}

	// Get device's xAddrs
	xAddrs, _ := mapXML.ValueForPathString("Envelope.Body.ProbeMatches.ProbeMatch.XAddrs")
	listXAddr := strings.Split(xAddrs, " ")
	if len(listXAddr) == 0 {
		return result, errors.New("Device does not have any xAddr")
	}

	// Finalize result
	result.ID = deviceID
	result.Name = deviceName
	result.XAddr = listXAddr[0]

	return result, nil
}
