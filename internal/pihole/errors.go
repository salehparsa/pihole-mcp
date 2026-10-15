package pihole

import "fmt"

// APIError is an error response from Pi-hole ({"error":{"key","message","hint"}}).
type APIError struct {
	Status  int
	Key     string
	Message string
	Hint    string
}

func (e *APIError) Error() string {
	s := fmt.Sprintf("pihole: HTTP %d", e.Status)
	if e.Key != "" {
		s += " " + e.Key
	}
	if e.Message != "" {
		s += ": " + e.Message
	}
	if e.Hint != "" {
		s += " (" + e.Hint + ")"
	}
	return s
}
