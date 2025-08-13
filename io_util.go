package main

import "strings"

func joinStrings(ss []string, sep string) string {
	if len(ss) == 0 {
		return ""
	}
	return strings.Join(ss, sep)
}
