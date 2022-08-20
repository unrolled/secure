package cspbuilder

import (
	"fmt"
	"strings"
)

const (
	// Fetch Directives
	ChildSrc      = "child-src"
	ConnectSrc    = "connect-src"
	DefaultSrc    = "default-src"
	FontSrc       = "font-src"
	FrameSrc      = "frame-src"
	ImgSrc        = "img-src"
	ManifestSrc   = "manifest-src"
	MediaSrc      = "media-src"
	ObjectSrc     = "object-src"
	PrefetchSrc   = "prefetch-src"
	ScriptSrc     = "script-src"
	ScriptSrcAttr = "script-src-attr"
	ScriptSrcElem = "script-src-elem"
	StyleSrc      = "style-src"
	StyleSrcAttr  = "style-src-attr"
	StyleSrcElem  = "style-src-elem"
	WorkerSrc     = "worker-src"

	// Document Directives
	BaseUri = "base-uri"
	Sandbox = "sandbox"

	// 	Navigation directives
	FormAction     = "form-action"
	FrameAncestors = "frame-ancestors"
	NavigateTo     = "navigate-to"

	// Reporting directives
	ReportUri = "report-uri"
	ReportTo  = "report-to"

	// Other directives
	RequireTrustedTypesFor  = "require-trusted-types-for"
	TrustedTypes            = "trusted-types"
	UpgradeInsecureRequests = "upgrade-insecure-requests"
)

type ContentSecurityPolicyBuilder struct {
	Directives map[string]([]string)
}

func (builder *ContentSecurityPolicyBuilder) Build() (string, error) {

	var sb strings.Builder

	for directive := range builder.Directives {

		if sb.Len() > 0 {
			sb.WriteString("; ")
		}

		switch directive {
		case Sandbox:
			if err := BuildDirectiveSandbox(&sb, builder.Directives[directive]); err != nil {
				return "", err
			}
		case FrameAncestors:
			if err := BuildDirectiveFrameAncestors(&sb, builder.Directives[directive]); err != nil {
				return "", err
			}
		case ReportTo:
			if err := BuildDirectiveReportTo(&sb, builder.Directives[directive]); err != nil {
				return "", err
			}
		case RequireTrustedTypesFor:
			if err := BuildDirectiveRequireTrustedTypesFor(&sb, builder.Directives[directive]); err != nil {
				return "", err
			}
		case TrustedTypes:
			// TODO https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/trusted-types
		case UpgradeInsecureRequests:
			// TODOhttps://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/upgrade-insecure-requests
		default:
			if err := BuildDirectiveDefault(&sb, directive, builder.Directives[directive]); err != nil {
				return "", err
			}
		}
	}

	return sb.String(), nil
}

func BuildDirectiveSandbox(sb *strings.Builder, values []string) error {
	if len(values) == 0 {
		sb.WriteString(Sandbox)
		return nil
	}
	if len(values) > 1 {
		return fmt.Errorf("too many values set for directive %s", Sandbox)
	}

	sandboxVal := values[0]

	switch sandboxVal {
	case "allow-downloads-without-user-activation":
	case "allow-downloads":
	case "allow-forms":
	case "allow-modals":
	case "allow-orientation-lock":
	case "allow-pointer-lock":
	case "allow-popups-to-escape-sandbox":
	case "allow-popups":
	case "allow-presentation":
	case "allow-same-origin":
	case "allow-scripts":
	case "allow-storage-access-by-user-activation":
	case "allow-top-navigation-by-user-activation":
	case "allow-top-navigation-to-custom-protocols":
	case "allow-top-navigation":
	default:
		return fmt.Errorf("unallowed value %s for directive %s", sandboxVal, Sandbox)
	}

	sb.WriteString(Sandbox)
	sb.WriteString(" ")
	sb.WriteString(sandboxVal)

	return nil
}

func BuildDirectiveFrameAncestors(
	sb *strings.Builder,
	values []string,
) error {
	if len(values) == 0 {
		return fmt.Errorf("no values set for directive %s", FrameAncestors)
	}

	sb.WriteString(FrameAncestors)
	for _, val := range values {
		if strings.HasPrefix(val, "'") && strings.HasSuffix(val, "'") {
			switch val {
			case "'self'":
			case "'none'":
			default:
				return fmt.Errorf("unallowed value %s for directive %s", val, FrameAncestors)
			}
		}
		sb.WriteString(" ")
		sb.WriteString(val)
	}
	return nil
}

func BuildDirectiveReportTo(
	sb *strings.Builder,
	values []string,
) error {
	if len(values) == 0 {
		return fmt.Errorf("no values set for directive %s", ReportTo)
	}
	if len(values) > 1 {
		return fmt.Errorf("too many values set for directive %s", ReportTo)
	}

	sb.WriteString(ReportTo)
	sb.WriteString(" ")
	sb.WriteString(values[0])

	return nil
}

func BuildDirectiveRequireTrustedTypesFor(
	sb *strings.Builder,
	values []string,
) error {
	const allowedValue = "'script'"
	if len(values) != 1 || values[0] != allowedValue {
		return fmt.Errorf("value for directive %s must be %s", RequireTrustedTypesFor, allowedValue)
	}

	sb.WriteString(RequireTrustedTypesFor)
	sb.WriteString(" ")
	sb.WriteString(values[0])

	return nil
}

func BuildDirectiveDefault(
	sb *strings.Builder,
	directive string,
	values []string,
) error {
	if len(values) == 0 {
		return fmt.Errorf("no values set for directive %s", directive)
	}

	sb.WriteString(directive)
	for i := range values {

		// TODO: if value is single-quoted should we check for these?
		// 'none'
		// 'report-sample'
		// 'self'
		// 'strict-dynamic'
		// 'unsafe-eval'
		// 'unsafe-hashes'
		// 'unsafe-inline'
		// 'sha256-<base64-value>'
		// 'sha384-<base64-value>'
		// 'sha512-<base64-value>'
		// 'nonce-<base64-value>'

		sb.WriteString(" ")
		sb.WriteString(values[i])
	}
	return nil
}
