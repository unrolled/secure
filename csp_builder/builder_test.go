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

			err := BuildDirectiveSandbox(sb, tt.values)
			if tt.wantErr && err != nil {
				return
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("BuildDirectiveSandbox() error = %v, wantErr %v", err, tt.wantErr)
			}

			if got := sb.String(); got != tt.want {
				t.Errorf("BuildDirectiveSandbox() result = '%v', want '%v'", got, tt.want)
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
			err := BuildDirectiveFrameAncestors(sb, tt.values)
			if tt.wantErr && err != nil {
				return
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("BuildDirectiveFrameAncestors() error = %v, wantErr %v", err, tt.wantErr)
			}

			if got := sb.String(); got != tt.want {
				t.Errorf("BuildDirectiveFrameAncestors() result = '%v', want '%v'", got, tt.want)
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

			err := BuildDirectiveReportTo(sb, tt.values)
			if tt.wantErr && err != nil {
				return
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("BuildDirectiveReportTo() error = %v, wantErr %v", err, tt.wantErr)
			}

			if got := sb.String(); got != tt.want {
				t.Errorf("BuildDirectiveReportTo() result = '%v', want '%v'", got, tt.want)
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

			err := BuildDirectiveRequireTrustedTypesFor(sb, tt.values)
			if tt.wantErr && err != nil {
				return
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("BuildDirectiveRequireTrustedTypesFor() error = %v, wantErr %v", err, tt.wantErr)
			}

			if got := sb.String(); got != tt.want {
				t.Errorf("BuildDirectiveRequireTrustedTypesFor() result = '%v', want '%v'", got, tt.want)
			}
		})
	}
}

func TestContentSecurityPolicyBuilder_Build_SingleDirective(t *testing.T) {

	tests := []struct {
		name            string
		directiveName   string
		directiveValues []string
		want            string
		wantErr         bool
	}{
		{
			name:            "empty default-src",
			directiveName:   DefaultSrc,
			directiveValues: nil,
			want:            "",
			wantErr:         true,
		},
		{
			name:            "single default-src",
			directiveName:   DefaultSrc,
			directiveValues: []string{"'self'"},
			want:            "default-src 'self'",
		},
		{
			name:            "multiple default-src",
			directiveName:   DefaultSrc,
			directiveValues: []string{"'self'", "example.com", "*.example.com"},
			want:            "default-src 'self' example.com *.example.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := &ContentSecurityPolicyBuilder{
				Directives: map[string][]string{
					tt.directiveName: tt.directiveValues,
				},
			}
			got, err := builder.Build()
			if (err != nil) != tt.wantErr {
				t.Errorf("ContentSecurityPolicyBuilder.Build() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if got != tt.want {
				t.Errorf("ContentSecurityPolicyBuilder.Build() = '%v', want '%v'", got, tt.want)
			}
		})
	}
}

// TODO test with multiple directives, but iteration over map does not guarantee order...
// TODO: check output begins with any of directive names
// TODO: check output does not end on space or semi-colon
// TODO: check output contains all expected parts
