package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// diagnosticList aliases the framework's diagnostic slice for brevity.
type diagnosticList = diag.Diagnostics

// optionalString maps a nullable API string onto a Terraform value.
func optionalString(value *string) types.String {
	if value == nil {
		return types.StringNull()
	}
	return types.StringValue(*value)
}

// stringsFromList reads a Terraform list into a Go slice, leaving the target
// untouched when the list is null or unknown.
func stringsFromList(ctx context.Context, list types.List, target *[]string) diagnosticList {
	if list.IsNull() || list.IsUnknown() {
		return nil
	}
	return list.ElementsAs(ctx, target, false)
}

// stringsFromSet reads a Terraform set into a Go slice.
func stringsFromSet(ctx context.Context, set types.Set, target *[]string) diagnosticList {
	if set.IsNull() || set.IsUnknown() {
		return nil
	}
	return set.ElementsAs(ctx, target, false)
}

// setFromStrings converts an API slice into a Terraform set.
//
// prior is the value currently in configuration or state. When the API returns
// nothing and the practitioner never configured the attribute, the result stays
// null rather than becoming an empty set — Terraform treats null and [] as
// different values and would otherwise report a diff on every plan.
func setFromStrings(ctx context.Context, values []string, prior types.Set) (types.Set, diagnosticList) {
	if len(values) == 0 {
		if prior.IsNull() || prior.IsUnknown() {
			return types.SetNull(types.StringType), nil
		}
		// The practitioner configured an explicit empty set. SetValueFrom on a
		// nil slice would produce a *null* set here, flipping [] to null and
		// producing a perpetual diff, so build the empty set directly.
		return types.SetValue(types.StringType, []attr.Value{})
	}
	return types.SetValueFrom(ctx, types.StringType, values)
}
