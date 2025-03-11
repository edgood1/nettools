package nettools

import (
	"errors"
	"fmt"
	"github.com/go-ping/ping"
	"net"
	"strings"
	"time"
)

type IPInfo struct {
	IP        string
	Netmask   string
	Interface string
}

// GetPrimaryIP returns the primary IP address of the local machine.
func GetPrimaryIP() (net.IP, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP, nil
}

// GetPrimaryInterface returns the primary network interface of the local machine.
func GetPrimaryInterface() (net.Interface, error) {
	primaryIP, err := GetPrimaryIP()
	if err != nil {
		return net.Interface{}, fmt.Errorf("Failed to get primary IP: %w", err)
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return net.Interface{}, fmt.Errorf("Couldn't get network interfaces: %w", err)
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			return net.Interface{}, fmt.Errorf("Couldn't get addresses for interface %s: %w", iface.Name, err)
		}

		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}

			// Match the primary IP to one of the interface's addresses
			if ip.Equal(primaryIP) {
				return iface, nil
			}
		}
	}

	return net.Interface{}, fmt.Errorf("Couldn't find primary IP %s on any interface", primaryIP)
}

// GetLocalInterface returns the net.interface with the specified name.
func GetLocalInterface(name string) (net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return net.Interface{}, fmt.Errorf("Couldn't get network interfaces: %w", err)
	}

	for _, iface := range interfaces {
		if iface.Name == name {
			return iface, nil
		}
	}

	return net.Interface{}, fmt.Errorf("Couldn't find interface with name %s", name)
}

// GetLocalIPsAndNetmasks returns a list of IP addresses and netmasks assigned to the local machine.
func GetLocalIPsAndNetmasks() ([]IPInfo, error) {
	var ipInfos []IPInfo

	// Get all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("error fetching interfaces: %w", err)
	}

	for _, iface := range interfaces {
		// Skip interfaces that are down or have no flags
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		// Get addresses for the interface
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("error fetching addresses for interface %s: %w", iface.Name, err)
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.IsLoopback() {
				continue
			}

			// Consider only IPv4 addresses
			ip := ipNet.IP.To4()
			if ip == nil {
				continue
			}

			// Retrieve the netmask in dotted decimal format
			netmask := ConvertNetMaskToDottedDecimal(ipNet.Mask)

			ipInfos = append(ipInfos, IPInfo{
				Interface: iface.Name,
				IP:        ip.String(),
				Netmask:   netmask,
			})
		}
	}

	return ipInfos, nil
}

// GetNetMaskForIP takes an IP address assigned to the local machine and returns its netmask.
func GetNetMaskForIP(ipAddress string) (net.IPMask, error) {
	// Parse the input IP address
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return nil, errors.New("invalid IP address")
	}

	// Get the list of interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list interfaces: %w", err)
	}

	// Loop through each interface
	for _, iface := range interfaces {
		// Get the addresses for the current interface
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("failed to get addresses for interface %s: %w", iface.Name, err)
		}

		// Check each address for a match
		for _, addr := range addrs {
			var ipNet *net.IPNet
			switch v := addr.(type) {
			case *net.IPNet:
				ipNet = v
			case *net.IPAddr:
				ipNet = &net.IPNet{IP: v.IP, Mask: v.IP.DefaultMask()}
			}

			// If the IP matches, return the netmask
			if ipNet != nil && ipNet.IP.Equal(ip) {
				return ipNet.Mask, nil
			}
		}
	}

	return nil, errors.New("IP address %s not found on any local interface " + ipAddress)
}

// GetPrimaryAddressAndPrefix returns the primary IP address and prefix size for the local machine.
func GetPrimaryAddressAndPrefix() (string, int, error) {
	primaryIP, err := GetPrimaryIP()
	if err != nil {
		return "", 0, fmt.Errorf("Failed to get primary IP: %w", err)
	}

	primaryInterface, err := GetPrimaryInterface()
	if err != nil {
		return "", 0, fmt.Errorf("Failed to get primary interface: %w", err)
	}

	interfaceAddrs, err := primaryInterface.Addrs()
	if err != nil {
		return "", 0, fmt.Errorf("Failed to get addresses for primary interface: %w", err)
	}

	for _, interfaceAddr := range interfaceAddrs {
		ip, ipNet, err := net.ParseCIDR(interfaceAddr.String())
		if err != nil {
			continue
		}

		if ip.Equal(primaryIP) {
			prefixSize, _ := ipNet.Mask.Size()
			return primaryIP.String(), prefixSize, nil
		}
	}

	return "", 0, fmt.Errorf("Couldn't find determine primary interface with IP %s", primaryIP)
}

// GetPrimaryAddressAndNetmask returns the primary IP address and netmask for the local machine.
func ConvertPrefixToMask(prefix int) net.IPMask {
	mask := net.CIDRMask(prefix, 32)
	return mask
}

// ConvertPrefixToDottedDecimal converts a prefix size to a dotted decimal netmask.
func ConvertPrefixToDottedDecimal(prefix int) string {
	mask := ConvertPrefixToMask(prefix)
	dd := net.IP(mask).To4()
	if dd == nil {
		return ""
	}
	return dd.String()
}

// ConvertNetMaskToPrefix converts a netmask to a prefix size.
func ConvertNetMaskToDottedDecimal(mask net.IPMask) string {
	if mask == nil {
		return ""
	}
	return net.IP(mask).To4().String()
}

// ConvertDottedDecimalToPrefix converts a dotted decimal netmask to a prefix size.
func ConvertHexToDottedDecimal(hex string) string {
	mask := net.IP(net.ParseIP(hex)).To4()
	if mask == nil {
		return ""
	}
	return mask.String()
}

// ConvertDottedDecimalToPrefix converts a dotted decimal netmask to a prefix size.
func ConvertMaskToPrefix(mask net.IPMask) int {
	prefix, _ := mask.Size()
	return prefix
}

// ConvertDottedDecimalToPrefix converts a dotted decimal netmask to a prefix size.
func StringMaskToPrefix(maskStr string) (int, error) {
	// Parse the string as an IP
	ip := net.ParseIP(maskStr)
	if ip == nil {
		return 0, fmt.Errorf("invalid subnet mask: %s", maskStr)
	}

	// Extract the 4-byte IPv4 representation
	ip = ip.To4()
	if ip == nil {
		return 0, fmt.Errorf("invalid IPv4 subnet mask: %s", maskStr)
	}

	// Count the number of 1 bits in the mask
	prefix := 0
	for _, b := range ip {
		prefix += strings.Count(fmt.Sprintf("%08b", b), "1")
	}
	return prefix, nil
}

// return the next successive mac address
func NextMACAddress(mac string) (string, error) {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return "", err
	}

	// Convert MAC address to an integer
	macInt := uint64(0)
	for _, b := range hw {
		macInt = (macInt << 8) | uint64(b)
	}

	// Add one to the integer
	macInt++

	// Convert the integer back to a MAC address
	newMAC := make(net.HardwareAddr, 6)
	for i := 5; i >= 0; i-- {
		newMAC[i] = byte(macInt & 0xFF)
		macInt >>= 8
	}

	return newMAC.String(), nil
}

// return the previous successive mac address
func PrevMACAddress(mac string) (string, error) {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return "", err
	}

	// Convert MAC address to an integer
	macInt := uint64(0)
	for _, b := range hw {
		macInt = (macInt << 8) | uint64(b)
	}

	// Subtract one from the integer
	macInt--

	// Convert the integer back to a MAC address
	newMAC := make(net.HardwareAddr, 6)
	for i := 5; i >= 0; i-- {
		newMAC[i] = byte(macInt & 0xFF)
		macInt >>= 8
	}

	return newMAC.String(), nil
}

// IsReachable checks if an IP address is reachable.
func IsReachable(ip string) bool {
	pinger, err := ping.NewPinger(ip)
	if err != nil {
		return false
	}
	pinger.Count = 1
	pinger.Timeout = time.Second * 2
	err = pinger.Run()
	if err != nil {
		return false
	}

	stats := pinger.Statistics()
	return stats.PacketsRecv > 0
}
