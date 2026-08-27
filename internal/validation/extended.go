package validation

import (
	"regexp"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/nyaruka/phonenumbers"
)

var ngPhoneRegex = regexp.MustCompile(`^\+234[7-9]\d{9}$`)
var emailRegex = regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$`)

func registerCustomValidations() {
	Validate.RegisterValidation("ngphone", validateNGPhone)
	Validate.RegisterValidation("phone", validatePhone)
	Validate.RegisterValidation("identifier", validateIdentifier)
	Validate.RegisterValidation("ngidentifier", validateNGIdentifier)
}

// validateNGPhone validates a Nigerian E.164 phone number.
func validateNGPhone(fl validator.FieldLevel) bool {
	return ngPhoneRegex.MatchString(fl.Field().String())
}

// validatePhone validates any international E.164 phone number.
func validatePhone(fl validator.FieldLevel) bool {
	_, err := phonenumbers.Parse(fl.Field().String(), "")
	return err == nil
}

// validateNGIdentifier validates a Nigerian phone number or email.
func validateNGIdentifier(fl validator.FieldLevel) bool {
	val := strings.TrimSpace(fl.Field().String())
	if emailRegex.MatchString(val) {
		return true
	}
	return ngPhoneRegex.MatchString(val)
}

// validateIdentifier validates any international phone number or email.
func validateIdentifier(fl validator.FieldLevel) bool {
	val := strings.TrimSpace(fl.Field().String())
	if emailRegex.MatchString(val) {
		return true
	}
	_, err := phonenumbers.Parse(val, "")
	return err == nil
}
