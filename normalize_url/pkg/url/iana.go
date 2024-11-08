package url

import (
	"bufio"
	"embed"
	"log"
)

const DefaultScheme = "http"

//go:embed iana.txt
var fs embed.FS

type ianaSchemes map[string]struct{}

func (s ianaSchemes) IsValid(scheme string) bool {
	_, valid := s[scheme]
	return valid
}

var IANASchemes ianaSchemes

func init() {
	f, err := fs.Open("iana.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	IANASchemes = make(map[string]struct{})

	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		scheme := scanner.Text()
		IANASchemes[scheme] = struct{}{}
	}
}
