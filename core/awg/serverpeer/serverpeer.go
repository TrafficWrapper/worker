package serverpeer

import "strconv"

// PeerUAPILines returns one complete server-side peer block in device UAPI order.
func PeerUAPILines(pubHex, pskHex, allowedIP string, keepaliveSec int) []string {
	return []string{
		"public_key=" + pubHex,
		"preshared_key=" + pskHex,
		"persistent_keepalive_interval=" + strconv.Itoa(keepaliveSec),
		"replace_allowed_ips=true",
		"allowed_ip=" + allowedIP,
	}
}
