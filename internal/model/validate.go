package model

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	MaxNameLength        = 256
	MaxDescriptionLength = 2000
)

var md5Regex = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)

func NormalizeMD5(md5 string) string {
	return strings.ToLower(md5)
}

func ValidateMD5(md5 string) error {
	if !md5Regex.MatchString(md5) {
		return fmt.Errorf("md5 must be 32 hexadecimal characters, got %q", md5)
	}
	return nil
}

func (s Severity) IsValid() bool {
	switch s {
	case SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	}
	return false
}

func (t Threat) Validate() error {
	if err := ValidateMD5(t.MD5); err != nil {
		return err
	}
	if strings.TrimSpace(t.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if len(t.Name) > MaxNameLength {
		return fmt.Errorf("name must be at most %d bytes", MaxNameLength)
	}
	if t.Severity == "" {
		return fmt.Errorf("severity is required")
	}
	if !t.Severity.IsValid() {
		return fmt.Errorf("severity must be one of: low, medium, high, critical; got %q", t.Severity)
	}
	if len(t.Description) > MaxDescriptionLength {
		return fmt.Errorf("description must be at most %d bytes", MaxDescriptionLength)
	}
	return nil
}
