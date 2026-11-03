package attack

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// A2AGRPCTarget is an operator-approved gRPC address.
type A2AGRPCTarget struct {
	Address string
	Secure  bool
}

func ParseA2AGRPCTarget(raw string) (A2AGRPCTarget, error) {
	var target A2AGRPCTarget
	if raw == "" || strings.TrimSpace(raw) != raw {
		return target, errors.New("A2A gRPC target must be an absolute grpc:// or grpcs:// URL")
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil || (u.Scheme != "grpc" && u.Scheme != "grpcs") ||
		u.Opaque != "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return target, errors.New("A2A gRPC target must be grpc://host:port or grpcs://host:port without a path or credentials")
	}
	host, port := u.Hostname(), u.Port()
	portNumber, err := strconv.Atoi(port)
	if host == "" || err != nil || portNumber < 1 || portNumber > 65535 ||
		strings.ContainsAny(host, " \t\r\n/%") {
		return target, errors.New("A2A gRPC target requires a hostname and numeric port")
	}
	if u.Scheme == "grpc" && !strings.EqualFold(host, "localhost") {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return target, fmt.Errorf("plaintext A2A gRPC is limited to loopback: %q", host)
		}
	}
	return A2AGRPCTarget{Address: net.JoinHostPort(strings.ToLower(host), port), Secure: u.Scheme == "grpcs"}, nil
}
