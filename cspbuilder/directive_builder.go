package cspbuilder

import (
	"fmt"
	"regexp"
	"strings"
)

func buildDirectiveSandbox(sb *strings.Builder, values []string) error {
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

func buildDirectiveFrameAncestors(
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

func buildDirectiveReportTo(
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

func buildDirectiveRequireTrustedTypesFor(
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

func buildDirectiveTrustedTypes(
	sb *strings.Builder,
	values []string,
) error {
	sb.WriteString(TrustedTypes)

	for _, val := range values {
		sb.WriteString(" ")
		switch val {
		case "'none'":
			if len(values) != 1 {
				return fmt.Errorf("'none' must be only value for directive %s", TrustedTypes)
			}
		case "'allow-duplicates'":
			// nothing to do
		case "*":
			// nothing to do
		default:
			// value is policyname
			regex := regexp.MustCompile(`^[A-Za-z0-9\-#=_/@\.%]*$`)
			if !regex.MatchString(val) {
				return fmt.Errorf("unallowed value %s for directive %s", val, TrustedTypes)
			}
		}
		sb.WriteString(val)
	}

	return nil
}

func buildDirectiveUpgradeInsecureRequests(
	sb *strings.Builder,
	values []string,
) error {
	if len(values) != 0 {
		return fmt.Errorf("directive %s must not contain values", UpgradeInsecureRequests)
	}

	sb.WriteString(UpgradeInsecureRequests)
	return nil
}

func buildDirectiveDefault(
	sb *strings.Builder,
	directive string,
	values []string,
) error {
	if len(values) == 0 {
		return fmt.Errorf("no values set for directive %s", directive)
	}

	sb.WriteString(directive)
	for i := range values {
		sb.WriteString(" ")
		sb.WriteString(values[i])
	}
	return nil
}
