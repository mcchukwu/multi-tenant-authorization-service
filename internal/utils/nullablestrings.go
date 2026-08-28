package utils

// nullableString returns a pointer to the string if it's not empty
func NullableString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
