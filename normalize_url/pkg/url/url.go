package url

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"un/internal/ip"
)

const (
	rSep = '/'
	sSep = string(rSep)
)

var (
	ErrInvalidHost = errors.New("invalid url host")
	ErrInvalidPath = errors.New("invalid url path")
)

type HostPort struct {
	Host string
	Port string
	IsIP bool
}

func NormalizeURL(raw string) (string, error) {
	raw = prepare(raw)

	u, err := parseUrl(raw)
	if err != nil {
		return "", err
	}

	hp, err := normalizeHost(u.Host)
	if err != nil {
		return "", err
	}

	path, err := normalizePath(u.EscapedPath())
	if err != nil {
		return "", err
	}

	query, err := normalizeQuery(u.RawQuery)
	if err != nil {
		return "", err
	}

	var buf strings.Builder
	buf.WriteString(hp.Host)

	if hp.Host != "" {
		if path != "" && !strings.HasPrefix(path, sSep) {
			buf.WriteRune(rSep)
		}
	}
	buf.WriteString(path)

	needSuffixSlash := (u.RawQuery != "" || strings.HasSuffix(raw, "?")) &&
		(strings.HasSuffix(u.Path, sSep) || strings.HasSuffix(u.Path, "."))

	if needSuffixSlash {
		if !strings.HasSuffix(path, sSep) {
			buf.WriteRune(rSep)
		}
	}

	if query != "" {
		buf.WriteRune('?')
		buf.WriteString(query)
	} else if u.ForceQuery {
		buf.WriteRune('?')
	}
	res := buf.String()

	// Post-normalization
	res = collapse(res, rSep, false)

	if strings.HasSuffix(res, "/?") && len(query) < 2 {
		if u.Fragment != "" || u.Scheme != "" {
			res = res[:len(res)-2]
		}
	}

	res = strings.TrimSuffix(res, "/.")

	return res, nil
}

// prepare prepares string before URL parsing.
// Removes leading spaces and returns URL with scheme.
func prepare(raw string) string {
	raw = strings.TrimLeft(raw, " ")
	return withScheme(raw)
}

// withScheme tries to detect scheme and if found returns it with ://
// else appends default scheme to url.
func withScheme(raw string) string {
	scheme, rest, _ := strings.Cut(raw, ":")
	scheme = strings.ToLower(scheme)

	if IANASchemes.IsValid(scheme) {
		rest = strings.TrimLeft(rest, sSep)
		return fmt.Sprintf("%s://%s", scheme, rest)
	}

	raw = strings.TrimLeft(raw, sSep)
	return fmt.Sprintf("%s://%s", DefaultScheme, raw)
}

func normalizeHost(raw string) (HostPort, error) {
	if raw == "" {
		return HostPort{}, nil
	}

	parts := strings.Split(strings.ToLower(raw), ":")

	if len(parts) > 2 {
		nip, err := ip.NormalizeIPv6(raw)
		if err != nil {
			return HostPort{}, errors.Join(ErrInvalidHost, err)
		}
		return HostPort{
			Host: nip,
			IsIP: true,
		}, nil
	}

	host := parts[0]
	port := ""
	if len(parts) == 2 {
		port = parts[1]
	}

	hp := HostPort{
		Port: port,
	}

	host = collapse(host, '.', true)
	host = strings.TrimPrefix(host, ".")
	host = strings.TrimPrefix(host, "www.")
	hp.Host = host

	if nip, err := ip.NormalizeIPv4(host); err == nil {
		hp.Host = nip
		hp.IsIP = true
	}

	return hp, nil
}

func normalizePath(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}

	p := filepath.Clean(raw)
	p = strings.TrimPrefix(p, sSep)
	p = strings.ReplaceAll(p, "\\", sSep)
	p = collapse(p, rSep, true)
	parts := strings.Split(p, sSep)
	for i := 0; i < len(parts); i++ {
		unescaped, err := url.PathUnescape(parts[i])
		if err != nil {
			return "", errors.Join(ErrInvalidPath, err)
		}

		parts[i] = strings.ToLower(unescaped)
	}
	p = strings.Join(parts, sSep)

	if p == "*" {
		return "", nil
	}

	return p, nil
}

func normalizeQuery(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}

	q := strings.ReplaceAll(raw, "+", "%2B")
	q = strings.ReplaceAll(q, "%00", "")

	uq, err := url.QueryUnescape(q)
	if err == nil && uq != "" {
		q = uq
	}
	q = collapse(q, rSep, false)

	return strings.ToLower(q), nil
}

// collapse replaces repeated consecutive characters with one.
func collapse(str string, symbol rune, trim bool) string {
	runes := make([]rune, 0, len(str))
	marked := false

	for _, r := range str {
		if r == symbol {
			marked = true
		} else {
			if marked {
				runes = append(runes, symbol)
			}
			runes = append(runes, r)
			marked = false
		}
	}

	if marked && !trim {
		runes = append(runes, symbol)
	}

	return string(runes)
}

// parseUrl parses string and returns [*url.URL] if string is valid url.
func parseUrl(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		if strings.Contains(err.Error(), "invalid URL escape") {
			raw = strings.ReplaceAll(raw, "%", "%25")
			return url.Parse(raw)
		}
		return nil, err
	}
	return u, err
}
