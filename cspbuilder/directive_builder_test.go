package cspbuilder

import (
	"strings"
	"testing"
)

func TestBuildDirectiveSandbox(t *testing.T) {
	tests := []struct {
		name    string
		values  []string
		wantErr bool
		want    string
	}{
		{
			name:   "empty",
			values: nil,
			want:   "sandbox",
		},
		{
			name:   "allowed value",
			values: []string{"allow-scripts"},
			want:   "sandbox allow-scripts",
		},
		{
			name:    "unallowed value",
			values:  []string{"invalid-sandbox-value"},
			wantErr: true,
		},
		{
			name:    "too many values",
			values:  []string{"allow-forms", "allow-modals"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sb := &strings.Builder{}

			err := buildDirectiveSandbox(sb, tt.values)
			if tt.wantErr && err != nil {
				return
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("buildDirectiveSandbox() error = %v, wantErr %v", err, tt.wantErr)
			}

			if got := sb.String(); got != tt.want {
				t.Errorf("buildDirectiveSandbox() result = '%v', want '%v'", got, tt.want)
			}
		})
	}
}

func TestBuildDirectiveFrameAncestors(t *testing.T) {
	tests := []struct {
		name    string
		values  []string
		wantErr bool
		want    string
	}{
		{
			name:    "empty",
			values:  nil,
			wantErr: true,
		},
		{
			name:   "allowed value",
			values: []string{"'self'"},
			want:   "frame-ancestors 'self'",
		},
		{
			name:    "unallowed value",
			values:  []string{"'invalid-frame-ancestors-value'"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sb := &strings.Builder{}
			err := buildDirectiveFrameAncestors(sb, tt.values)
			if tt.wantErr && err != nil {
				return
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("buildDirectiveFrameAncestors() error = %v, wantErr %v", err, tt.wantErr)
			}

			if got := sb.String(); got != tt.want {
				t.Errorf("buildDirectiveFrameAncestors() result = '%v', want '%v'", got, tt.want)
			}
		})
	}
}

func TestBuildDirectiveReportTo(t *testing.T) {
	tests := []struct {
		name    string
		values  []string
		wantErr bool
		want    string
	}{
		{
			name:    "empty",
			values:  nil,
			wantErr: true,
		},
		{
			name:   "single value",
			values: []string{"group1"},
			want:   "report-to group1",
		},
		{
			name:    "too many values",
			values:  []string{"group1", "group2"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sb := &strings.Builder{}

			err := buildDirectiveReportTo(sb, tt.values)
			if tt.wantErr && err != nil {
				return
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("buildDirectiveReportTo() error = %v, wantErr %v", err, tt.wantErr)
			}

			if got := sb.String(); got != tt.want {
				t.Errorf("buildDirectiveReportTo() result = '%v', want '%v'", got, tt.want)
			}
		})
	}
}

func TestBuildDirectiveRequireTrustedTypesFor(t *testing.T) {
	tests := []struct {
		name    string
		values  []string
		wantErr bool
		want    string
	}{
		{
			name:    "empty",
			values:  nil,
			wantErr: true,
		},
		{
			name:   "allowed value",
			values: []string{"'script'"},
			want:   "require-trusted-types-for 'script'",
		},
		{
			name:    "unallowed value",
			values:  []string{"*"},
			wantErr: true,
		},
		{
			name:    "too many values",
			values:  []string{"'script'", "*"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sb := &strings.Builder{}

			err := buildDirectiveRequireTrustedTypesFor(sb, tt.values)
			if tt.wantErr && err != nil {
				return
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("buildDirectiveRequireTrustedTypesFor() error = %v, wantErr %v", err, tt.wantErr)
			}

			if got := sb.String(); got != tt.want {
				t.Errorf("buildDirectiveRequireTrustedTypesFor() result = '%v', want '%v'", got, tt.want)
			}
		})
	}
}

func TestBuildDirectiveTrustedTypes(t *testing.T) {
	tests := []struct {
		name    string
		values  []string
		wantErr bool
		want    string
	}{
		{
			name:   "empty",
			values: nil,
			want:   "trusted-types",
		},
		{
			name:   "none",
			values: []string{"'none'"},
			want:   "trusted-types 'none'",
		},
		{
			name:   "allowed value",
			values: []string{"policy-#=_/@.%"},
			want:   "trusted-types policy-#=_/@.%",
		},
		{
			name:    "unallowed value",
			values:  []string{"unallowed-char-!"},
			wantErr: true,
		},
		{
			name:   "multiple values",
			values: []string{"policy-1", "policy-#=_/@.%", "'allow-duplicates'"},
			want:   "trusted-types policy-1 policy-#=_/@.% 'allow-duplicates'",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sb := &strings.Builder{}
			err := buildDirectiveTrustedTypes(sb, tt.values)
			if tt.wantErr && err != nil {
				return
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("buildDirectiveTrustedTypes() error = %v, wantErr %v", err, tt.wantErr)
			}

			if got := sb.String(); got != tt.want {
				t.Errorf("buildDirectiveTrustedTypes() result = '%v', want '%v'", got, tt.want)
			}
		})
	}
}

func TestBuildDirectiveUpgradeInsecureRequests(t *testing.T) {
	tests := []struct {
		name    string
		values  []string
		wantErr bool
		want    string
	}{
		{
			name:   "empty",
			values: nil,
			want:   "upgrade-insecure-requests",
		},
		{
			name:    "value",
			values:  []string{"upgrade-insecure-requests"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sb := &strings.Builder{}

			err := buildDirectiveUpgradeInsecureRequests(sb, tt.values)
			if tt.wantErr && err != nil {
				return
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("buildDirectiveUpgradeInsecureRequests() error = %v, wantErr %v", err, tt.wantErr)
			}

			if got := sb.String(); got != tt.want {
				t.Errorf("buildDirectiveUpgradeInsecureRequests() result = '%v', want '%v'", got, tt.want)
			}
		})
	}
}

func TestBuildDirectiveDefault(t *testing.T) {
	tests := []struct {
		name      string
		directive string
		values    []string
		want      string
		wantErr   bool
	}{
		{
			name:      "empty",
			directive: DefaultSrc,
			values:    nil,
			wantErr:   true,
		},
		{
			name:      "single value",
			directive: DefaultSrc,
			values:    []string{"value1"},
			want:      "default-src value1",
		},
		{
			name:      "multiple values",
			directive: DefaultSrc,
			values:    []string{"value1", "value2"},
			want:      "default-src value1 value2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sb := &strings.Builder{}

			err := buildDirectiveDefault(sb, tt.directive, tt.values)
			if tt.wantErr && err != nil {
				return
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("buildDirectiveDefault() error = %v, wantErr %v", err, tt.wantErr)
			}

			if got := sb.String(); got != tt.want {
				t.Errorf("buildDirectiveDefault() result = '%v', want '%v'", got, tt.want)
			}
		})
	}
}
