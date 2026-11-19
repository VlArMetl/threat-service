package model

import "time"

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Threat struct {
	MD5         string
	Name        string
	Severity    Severity
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
