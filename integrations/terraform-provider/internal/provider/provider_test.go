package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	dsschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	fwprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	himitsu "github.com/sirsjg/himitsu-enterprise/integrations/client"
)

func newProvider(t *testing.T) fwprovider.Provider {
	t.Helper()
	return New("test")()
}

func TestProviderMetadata(t *testing.T) {
	var resp fwprovider.MetadataResponse
	newProvider(t).Metadata(context.Background(), fwprovider.MetadataRequest{}, &resp)
	if resp.TypeName != "himitsu" {
		t.Fatalf("TypeName = %q", resp.TypeName)
	}
	if resp.Version != "test" {
		t.Fatalf("Version = %q", resp.Version)
	}
}

func TestProviderSchemaMarksTokenSensitive(t *testing.T) {
	var resp fwprovider.SchemaResponse
	newProvider(t).Schema(context.Background(), fwprovider.SchemaRequest{}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: %v", resp.Diagnostics)
	}
	token, ok := resp.Schema.Attributes["token"]
	if !ok {
		t.Fatal("token attribute missing")
	}
	if !token.IsSensitive() {
		t.Fatal("provider token must be marked sensitive")
	}
}

// resourceSchemas builds every registered resource's schema once.
func resourceSchemas(t *testing.T) map[string]rschema.Schema {
	t.Helper()
	schemas := map[string]rschema.Schema{}
	for _, factory := range newProvider(t).(*himitsuProvider).Resources(context.Background()) {
		res := factory()

		var meta resource.MetadataResponse
		res.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "himitsu"}, &meta)

		var schemaResp resource.SchemaResponse
		res.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)
		if schemaResp.Diagnostics.HasError() {
			t.Fatalf("%s schema diagnostics: %v", meta.TypeName, schemaResp.Diagnostics)
		}
		schemas[meta.TypeName] = schemaResp.Schema
	}
	return schemas
}

func TestAllResourcesAreRegisteredAndValid(t *testing.T) {
	schemas := resourceSchemas(t)
	want := []string{
		"himitsu_project", "himitsu_environment", "himitsu_secret",
		"himitsu_tag", "himitsu_api_key",
	}
	for _, name := range want {
		schema, ok := schemas[name]
		if !ok {
			t.Fatalf("resource %s is not registered", name)
		}
		if len(schema.Attributes) == 0 {
			t.Fatalf("resource %s has no attributes", name)
		}
		// Every resource must expose an id for import and addressing.
		if _, ok := schema.Attributes["id"]; !ok {
			t.Errorf("resource %s has no id attribute", name)
		}
	}
	if len(schemas) != len(want) {
		t.Fatalf("registered %d resources, want %d", len(schemas), len(want))
	}
}

// The whole point of this provider is handling secrets; anything carrying
// plaintext must be flagged so Terraform redacts it in plan output.
func TestSecretBearingAttributesAreSensitive(t *testing.T) {
	schemas := resourceSchemas(t)

	value, ok := schemas["himitsu_secret"].Attributes["value"]
	if !ok || !value.IsSensitive() {
		t.Error("himitsu_secret.value must be sensitive")
	}
	token, ok := schemas["himitsu_api_key"].Attributes["token"]
	if !ok || !token.IsSensitive() {
		t.Error("himitsu_api_key.token must be sensitive")
	}
	// Metadata must NOT be sensitive, or plans become unreadable.
	for _, name := range []string{"key", "current_version"} {
		attribute, ok := schemas["himitsu_secret"].Attributes[name]
		if !ok {
			t.Fatalf("himitsu_secret.%s missing", name)
		}
		if attribute.IsSensitive() {
			t.Errorf("himitsu_secret.%s should not be sensitive", name)
		}
	}
}

func TestSecretsDataSourceMarksValuesSensitiveButNotKeys(t *testing.T) {
	var meta datasource.MetadataResponse
	source := NewSecretsDataSource()
	source.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "himitsu"}, &meta)
	if meta.TypeName != "himitsu_secrets" {
		t.Fatalf("TypeName = %q", meta.TypeName)
	}

	var resp datasource.SchemaResponse
	source.Schema(context.Background(), datasource.SchemaRequest{}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: %v", resp.Diagnostics)
	}

	secrets, ok := resp.Schema.Attributes["secrets"]
	if !ok || !secrets.IsSensitive() {
		t.Error("himitsu_secrets.secrets must be sensitive")
	}
	// keys is the non-sensitive escape hatch the docs point people at, so it
	// must stay readable in plan output.
	keys, ok := resp.Schema.Attributes["keys"]
	if !ok {
		t.Fatal("himitsu_secrets.keys missing")
	}
	if keys.IsSensitive() {
		t.Error("himitsu_secrets.keys should not be sensitive")
	}
}

func TestAllDataSourcesAreRegisteredAndValid(t *testing.T) {
	factories := newProvider(t).(*himitsuProvider).DataSources(context.Background())
	names := map[string]bool{}
	for _, factory := range factories {
		source := factory()
		var meta datasource.MetadataResponse
		source.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "himitsu"}, &meta)

		var resp datasource.SchemaResponse
		source.Schema(context.Background(), datasource.SchemaRequest{}, &resp)
		if resp.Diagnostics.HasError() {
			t.Fatalf("%s schema diagnostics: %v", meta.TypeName, resp.Diagnostics)
		}
		if len(resp.Schema.Attributes) == 0 {
			t.Fatalf("%s has no attributes", meta.TypeName)
		}
		names[meta.TypeName] = true
	}
	for _, want := range []string{"himitsu_project", "himitsu_environment", "himitsu_secrets"} {
		if !names[want] {
			t.Errorf("data source %s is not registered", want)
		}
	}
}

// Identity-defining fields have no API-side move operation, so changing them
// must recreate rather than silently diverge from configuration.
func TestIdentityChangesForceReplacement(t *testing.T) {
	schemas := resourceSchemas(t)
	cases := map[string][]string{
		"himitsu_secret":      {"project_id", "environment_id", "key"},
		"himitsu_environment": {"project_id"},
	}
	for resourceName, attributes := range cases {
		for _, name := range attributes {
			attribute, ok := schemas[resourceName].Attributes[name].(rschema.StringAttribute)
			if !ok {
				t.Fatalf("%s.%s is not a string attribute", resourceName, name)
			}
			if len(attribute.PlanModifiers) == 0 {
				t.Errorf("%s.%s has no RequiresReplace plan modifier", resourceName, name)
			}
		}
	}
}

func TestAPIKeyIsImmutable(t *testing.T) {
	// Tokens are minted once and never updatable, so every configurable
	// attribute has to force replacement.
	schema := resourceSchemas(t)["himitsu_api_key"]
	for _, name := range []string{"name", "access", "project_id", "environment_id", "expires_at"} {
		attribute, ok := schema.Attributes[name].(rschema.StringAttribute)
		if !ok {
			t.Fatalf("himitsu_api_key.%s is not a string attribute", name)
		}
		if len(attribute.PlanModifiers) == 0 {
			t.Errorf("himitsu_api_key.%s must force replacement", name)
		}
	}
}

func TestStateWarningsAreDocumented(t *testing.T) {
	// State-in-plaintext is the sharpest edge of this provider. If the warning
	// is ever dropped from the docs, fail here rather than in someone's repo.
	schemas := resourceSchemas(t)
	if !strings.Contains(schemas["himitsu_secret"].MarkdownDescription, "state") {
		t.Error("himitsu_secret must document that values land in Terraform state")
	}
	if !strings.Contains(schemas["himitsu_api_key"].MarkdownDescription, "state") {
		t.Error("himitsu_api_key must document that the token lands in Terraform state")
	}
}

func TestClientFromRejectsWrongType(t *testing.T) {
	var target *himitsu.Client
	var gotSummary string
	ok := clientFrom("not-a-client", &target, func(summary, _ string) { gotSummary = summary })
	if ok {
		t.Fatal("clientFrom accepted a wrong-typed provider data value")
	}
	if !strings.Contains(gotSummary, "Unexpected provider data type") {
		t.Fatalf("summary = %q", gotSummary)
	}
}

func TestClientFromIgnoresNilProviderData(t *testing.T) {
	// Terraform calls Configure before the provider is configured during
	// validation. That must not surface as an error to the practitioner.
	var target *himitsu.Client
	called := false
	if clientFrom(nil, &target, func(string, string) { called = true }) {
		t.Fatal("clientFrom reported success for nil provider data")
	}
	if called {
		t.Fatal("clientFrom raised an error for nil provider data")
	}
}

func TestOptionalStringMapsNil(t *testing.T) {
	if got := optionalString(nil); !got.IsNull() {
		t.Fatalf("optionalString(nil) = %v, want null", got)
	}
	value := "present"
	if got := optionalString(&value); got.ValueString() != "present" {
		t.Fatalf("optionalString = %v", got)
	}
}

func TestSetFromStringsKeepsNullWhenUnconfigured(t *testing.T) {
	ctx := context.Background()
	// An API that returns no tags for an attribute the practitioner never set
	// must stay null, or every plan shows a null -> [] diff forever.
	got, diags := setFromStrings(ctx, nil, types.SetNull(types.StringType))
	if diags.HasError() {
		t.Fatalf("diagnostics: %v", diags)
	}
	if !got.IsNull() {
		t.Fatalf("got %v, want null", got)
	}

	// But a configured empty set stays an empty set.
	configured, _ := types.SetValueFrom(ctx, types.StringType, []string{})
	got, diags = setFromStrings(ctx, nil, configured)
	if diags.HasError() {
		t.Fatalf("diagnostics: %v", diags)
	}
	if got.IsNull() {
		t.Fatal("a configured empty set became null")
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "second", "third"); got != "second" {
		t.Fatalf("firstNonEmpty = %q", got)
	}
	if got := firstNonEmpty("", ""); got != "" {
		t.Fatalf("firstNonEmpty = %q", got)
	}
}

// Ensure data source schemas do not accidentally require both selectors.
func TestLookupSelectorsAreOptional(t *testing.T) {
	source := NewProjectDataSource()
	var resp datasource.SchemaResponse
	source.Schema(context.Background(), datasource.SchemaRequest{}, &resp)

	for _, name := range []string{"id", "slug"} {
		attribute, ok := resp.Schema.Attributes[name].(dsschema.StringAttribute)
		if !ok {
			t.Fatalf("himitsu_project.%s is not a string attribute", name)
		}
		if attribute.Required {
			t.Errorf("himitsu_project.%s must be optional so either selector works", name)
		}
	}
}
