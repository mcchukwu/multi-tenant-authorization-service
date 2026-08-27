package normalize

import "strings"

func Email(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
