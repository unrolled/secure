package cspbuilder

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

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
			builder := &Builder{
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

func TestContentSecurityPolicyBuilder_Build_MultipleDirectives(t *testing.T) {
	tests := []struct {
		name       string
		directives map[string]([]string)
		builder    Builder
		wantParts  []string
		wantErr    bool
	}{
		{
			name: "multiple valid directives",
			directives: map[string]([]string){
				"default-src":               {"'self'", "example.com", "*.example.com"},
				"sandbox":                   {"allow-scripts"},
				"frame-ancestors":           {"'self'", "http://*.example.com"},
				"report-to":                 {"group1"},
				"require-trusted-types-for": {"'script'"},
				"trusted-types":             {"policy-1", "policy-#=_/@.%", "'allow-duplicates'"},
				"upgrade-insecure-requests": nil,
			},

			wantParts: []string{
				"default-src 'self' example.com *.example.com",
				"sandbox allow-scripts",
				"frame-ancestors 'self' http://*.example.com",
				"report-to group1",
				"require-trusted-types-for 'script'",
				"trusted-types policy-1 policy-#=_/@.% 'allow-duplicates'",
				"upgrade-insecure-requests",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := &Builder{
				Directives: tt.directives,
			}
			got, err := builder.Build()
			if (err != nil) != tt.wantErr {
				t.Errorf("ContentSecurityPolicyBuilder.Build() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			{
				startsWithDirective := false
				for directive := range tt.directives {
					if strings.HasPrefix(got, directive) {
						startsWithDirective = true
						break
					}
				}
				if !startsWithDirective {
					t.Errorf("ContentSecurityPolicyBuilder.Build() = '%v', does not start with directive name", got)
				}
			}

			if strings.HasSuffix(got, " ") {
				t.Errorf("ContentSecurityPolicyBuilder.Build() = '%v', ends on whitespace", got)
			}
			if strings.HasSuffix(got, ";") {
				t.Errorf("ContentSecurityPolicyBuilder.Build() = '%v', ends on semi-colon", got)
			}

			// order of directives in created string is not guaranteed
			// check output contains all expected parts
			{
				gotParts := strings.Split(got, "; ")
				if len(gotParts) != len(tt.wantParts) {
					t.Errorf("Got %d parts, want %d", len(gotParts), len(tt.wantParts))
				}

				sort.Slice(gotParts, func(i, j int) bool {
					return gotParts[i] < gotParts[j]
				})
				sort.Slice(tt.wantParts, func(i, j int) bool {
					return tt.wantParts[i] < tt.wantParts[j]
				})

				if !reflect.DeepEqual(gotParts, tt.wantParts) {
					t.Errorf("ContentSecurityPolicyBuilder.Build() = '%v', expected following parts %v", got, gotParts)
				}
			}
		})
	}
}
