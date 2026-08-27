package validation

import "github.com/go-playground/validator/v10"

var Validate *validator.Validate

func Init() {
	Validate = validator.New()
	registerCustomValidations()
}

func ValidateStruct(data any) map[string]string {
	err := Validate.Struct(data)
	if err == nil {
		return nil
	}

	validationErrors := err.(validator.ValidationErrors)

	fields := map[string]string{}

	for _, e := range validationErrors {
		fields[e.Field()] = mapValidationMessage(e)
	}

	return fields
}

// mapValidationMessage maps the validation error tag to a human readable message
func mapValidationMessage(e validator.FieldError) string {
	switch e.Tag() {
	case "required":
		return "field is required"
	case "email":
		return "must be a valid email"
	case "min":
		return "value is too short"
	case "max":
		return "value is too long"
	case "ngphone":
		return "must be a valid Nigerian phone number"
	case "phone":
		return "must be a valid phone number"
	case "ngidentifier":
		return "must be a valid Nigerian phone number or email"
	case "identifier":
		return "must be a valid phone number or email"
	case "uuid":
		return "must be a valid UUID"
	case "url":
		return "must be a valid URL"

	default:
		return "invalid value"
	}
}
