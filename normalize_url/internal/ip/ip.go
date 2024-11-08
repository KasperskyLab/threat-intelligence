package ip

import (
	"errors"
	"net"
	"strconv"
	"strings"
)

var (
	ErrEmptyValue  = errors.New("value is empty")
	ErrInvalidIPv4 = errors.New("invalid IPv4 format")
)

// NormalizeIPv4 normalizes IPv4.
func NormalizeIPv4(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ErrEmptyValue
	}

	octets := strings.Split(s, ".")
	if len(octets) > 4 {
		return "", ErrInvalidIPv4
	}

	resultRow := ""
	for i := 0; i < len(octets)-1; i++ {
		num, err := parseNumber(octets[i], 1)
		if err != nil {
			return "", err
		}
		resultRow += strconv.Itoa(int(num)) + "."
	}

	num, err := parseNumber(octets[len(octets)-1], 5-len(octets))
	if err != nil {
		return "", err
	}

	resultRow += uint32ToIPv4(num, len(octets)-1)
	return resultRow, nil
}

// NormalizeIPv6 normalizes IPv6.
func NormalizeIPv6(ip string) (string, error) {
	hasLBracket := strings.HasPrefix(ip, "[")
	hasRBracket := strings.HasSuffix(ip, "]")

	ip = strings.Trim(ip, "[]")
	if ip == "" {
		return "", ErrEmptyValue
	}

	pip := net.ParseIP(ip)
	if pip == nil {
		return "", errors.New("not IPv6")
	}
	ip = pip.String()
	if hasLBracket {
		ip = "[" + ip
	}
	if hasRBracket {
		ip += "]"
	}
	return ip, nil
}

func parseNumber(str string, blocksCount int) (uint32, error) {
	var (
		num  uint64
		err  error
		base = getBase(str)
	)

	switch base {
	case 16:
		num, err = strconv.ParseUint(str[2:], base, 32)
	case 8:
		num, err = strconv.ParseUint(str[1:], base, 32)
	default:
		num, err = strconv.ParseUint(str, base, 32)
	}
	if err != nil {
		return 0, err
	}

	var maxNum uint64 = 0xFF
	for i := 1; i < blocksCount; i++ {
		maxNum *= 0xFF
	}
	if num > maxNum {
		return 0, errors.New("num too big for ip")
	}
	return uint32(num), nil
}

func getBase(str string) int {
	switch {
	case strings.HasPrefix(str, "0x"):
		return 16
	case strings.HasPrefix(str, "0") && len(str) != 1:
		return 8
	default:
		return 10
	}
}

func uint32ToIPv4(ip uint32, needBlocks int) string {
	result := net.IP{
		byte(ip >> 24),
		byte(ip >> 16),
		byte(ip >> 8),
		byte(ip),
	}
	parts := strings.Split(result.String(), ".")
	return strings.Join(parts[needBlocks:], ".")
}
