package normalize

import (
	"strings"

	"github.com/nyaruka/phonenumbers"
)

// NigerianPhone normalizes Nigerian phone numbers to E.164 format.
func NigerianPhone(phone string) string {
	phone = strings.TrimSpace(phone)
	phone = strings.ReplaceAll(phone, " ", "")
	phone = strings.ReplaceAll(phone, "-", "")

	switch {
	case strings.HasPrefix(phone, "0"):
		return "+234" + phone[1:]
	case strings.HasPrefix(phone, "234"):
		return "+" + phone
	default:
		return phone
	}
}

// Phone normalizes any international phone number to E.164 format.
func Phone(phone, defaultRegion string) (string, error) {
	phone = strings.TrimSpace(phone)
	phone = strings.ReplaceAll(phone, " ", "")
	phone = strings.ReplaceAll(phone, "-", "")

	parsed, err := phonenumbers.Parse(phone, defaultRegion)
	if err != nil {
		return "", err
	}
	return phonenumbers.Format(parsed, phonenumbers.E164), nil
}
