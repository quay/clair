package xstrings

import (
	"encoding/json"
	"strings"
)

//Substr extract string of length in s starting at pos
func Substr(s string, pos, length int) string {
	runes := []rune(s)
	l := pos + length
	if l > len(runes) {
		l = len(runes)
	}
	return string(runes[pos:l])
}

//TrimPrefixSuffix combine TrimPrefix and TrimSuffix
func TrimPrefixSuffix(s string, prefix string, suffix string) string {
	return strings.TrimSuffix(strings.TrimPrefix(s, prefix), suffix)
}

func ToIndentJSON(v interface{}) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "\t")
	if err != nil {
		return nil, err
	}
	return b, nil
}
