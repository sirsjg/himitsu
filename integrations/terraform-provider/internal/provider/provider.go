// Package provider implements the Terraform provider for Himitsu.
package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	himitsu "github.com/sirsjg/himitsu/integrations/client"
)

// Ensure the provider satisfies the framework interfaces.
var _ provider.Provider = (*himitsuProvider)(nil)

type himitsuProvider struct {
	version string
}

// New returns a provider factory for the given build version.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &himitsuProvider{version: version}
	}
}

type providerModel struct {
	APIURL types.String `tfsdk:"api_url"`
	Token  types.String `tfsdk:"token"`
}

func (p *himitsuProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "himitsu"
	resp.Version = p.version
}

func (p *himitsuProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages projects, environments, secrets, tags, and API keys in a Himitsu instance.",
		Attributes: map[string]schema.Attribute{
			"api_url": schema.StringAttribute{
				MarkdownDescription: "Base URL of the Himitsu API. May also be set with the `HIMITSU_API_URL` environment variable.",
				Optional:            true,
			},
			"token": schema.StringAttribute{
				MarkdownDescription: "Himitsu API token. May also be set with the `HIMITSU_TOKEN` environment variable, which is strongly preferred: a token written into configuration ends up in state and in version control.",
				Optional:            true,
				Sensitive:           true,
			},
		},
	}
}

func (p *himitsuProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// An unknown value here means it depends on another resource that has not
	// been applied yet. Terraform will call Configure again once it is known.
	if config.APIURL.IsUnknown() {
		resp.Diagnostics.AddAttributeError(path.Root("api_url"),
			"Unknown Himitsu API URL",
			"The provider cannot be configured while api_url is unknown. Set it statically or with the HIMITSU_API_URL environment variable.")
	}
	if config.Token.IsUnknown() {
		resp.Diagnostics.AddAttributeError(path.Root("token"),
			"Unknown Himitsu API token",
			"The provider cannot be configured while token is unknown. Set it with the HIMITSU_TOKEN environment variable.")
	}
	if resp.Diagnostics.HasError() {
		return
	}

	apiURL := firstNonEmpty(config.APIURL.ValueString(), os.Getenv("HIMITSU_API_URL"))
	token := firstNonEmpty(config.Token.ValueString(), os.Getenv("HIMITSU_TOKEN"))

	if apiURL == "" {
		resp.Diagnostics.AddAttributeError(path.Root("api_url"),
			"Missing Himitsu API URL",
			"Set the api_url provider attribute or the HIMITSU_API_URL environment variable.")
	}
	if token == "" {
		resp.Diagnostics.AddAttributeError(path.Root("token"),
			"Missing Himitsu API token",
			"Set the HIMITSU_TOKEN environment variable, or the token provider attribute.")
	}
	if resp.Diagnostics.HasError() {
		return
	}

	client, err := himitsu.New(apiURL, token, himitsu.WithUserAgent("terraform-provider-himitsu/"+p.version))
	if err != nil {
		resp.Diagnostics.AddError("Unable to create Himitsu client", err.Error())
		return
	}

	resp.DataSourceData = client
	resp.ResourceData = client
}

func (p *himitsuProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewProjectResource,
		NewEnvironmentResource,
		NewSecretResource,
		NewTagResource,
		NewAPIKeyResource,
	}
}

func (p *himitsuProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewProjectDataSource,
		NewEnvironmentDataSource,
		NewSecretsDataSource,
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// clientFrom extracts the configured API client from provider data. It is
// shared by every resource and data source.
func clientFrom(providerData any, target **himitsu.Client, addError func(string, string)) bool {
	if providerData == nil {
		// Terraform calls Configure on resources before the provider is
		// configured during validation; this is expected, not an error.
		return false
	}
	client, ok := providerData.(*himitsu.Client)
	if !ok {
		addError("Unexpected provider data type",
			"The Himitsu provider was configured with an unexpected client type. This is a bug in the provider.")
		return false
	}
	*target = client
	return true
}
