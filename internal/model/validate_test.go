package model

import (
	"strings"
	"testing"
)

func validThreat() Threat {
	return Threat{
		MD5:      "d41d8cd98f00b204e9800998ecf8427e",
		Name:     "Trojan.Win32.Generic",
		Severity: SeverityHigh,
	}
}

func TestThreatValidate(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*Threat)
		wantErr string
	}{
		{name: "valid", modify: func(*Threat) {}},
		{name: "uppercase md5 is valid", modify: func(t *Threat) { t.MD5 = "D41D8CD98F00B204E9800998ECF8427E" }},
		{name: "md5 too short", modify: func(t *Threat) { t.MD5 = "abc" }, wantErr: "md5"},
		{name: "md5 not hex", modify: func(t *Threat) { t.MD5 = strings.Repeat("z", 32) }, wantErr: "md5"},
		{name: "empty name", modify: func(t *Threat) { t.Name = "" }, wantErr: "name is required"},
		{name: "whitespace name", modify: func(t *Threat) { t.Name = "   " }, wantErr: "name is required"},
		{name: "name too long", modify: func(t *Threat) { t.Name = strings.Repeat("a", MaxNameLength+1) }, wantErr: "name must be at most"},
		{name: "name at limit", modify: func(t *Threat) { t.Name = strings.Repeat("a", MaxNameLength) }},
		{name: "missing severity", modify: func(t *Threat) { t.Severity = "" }, wantErr: "severity is required"},
		{name: "unknown severity", modify: func(t *Threat) { t.Severity = "extreme" }, wantErr: "severity must be one of"},
		{name: "description too long", modify: func(t *Threat) { t.Description = strings.Repeat("a", MaxDescriptionLength+1) }, wantErr: "description"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			th := validThreat()
			tt.modify(&th)
			err := th.Validate()

			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tt.wantErr, err)
			}
		})
	}
}

func TestSeverityIsValid(t *testing.T) {
	for _, s := range []Severity{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical} {
		if !s.IsValid() {
			t.Errorf("%q should be valid", s)
		}
	}
	for _, s := range []Severity{"", "HIGH", "unknown"} {
		if s.IsValid() {
			t.Errorf("%q should be invalid", s)
		}
	}
}
