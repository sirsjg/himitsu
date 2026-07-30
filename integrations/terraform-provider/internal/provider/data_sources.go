package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	himitsu "github.com/sirsjg/himitsu/integrations/client"
)

// ---- himitsu_project ----

var (
	_ datasource.DataSource              = (*projectDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*projectDataSource)(nil)
)

type projectDataSource struct{ client *himitsu.Client }

// NewProjectDataSource returns the himitsu_project data source.
func NewProjectDataSource() datasource.DataSource { return &projectDataSource{} }

type projectDataModel struct {
	ID          types.String `tfsdk:"id"`
	Slug        types.String `tfsdk:"slug"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	OrgID       types.String `tfsdk:"org_id"`
	TagIDs      types.Set    `tfsdk:"tag_ids"`
}

func (d *projectDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_project"
}

func (d *projectDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Looks up an existing Himitsu project by id or slug.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "Project UUID. Provide this or `slug`.",
				Optional:            true,
				Computed:            true,
			},
			"slug": schema.StringAttribute{
				MarkdownDescription: "Project slug. Provide this or `id`.",
				Optional:            true,
				Computed:            true,
			},
			"name":        schema.StringAttribute{MarkdownDescription: "Project name.", Computed: true},
			"description": schema.StringAttribute{MarkdownDescription: "Project description.", Computed: true},
			"org_id":      schema.StringAttribute{MarkdownDescription: "Organization UUID.", Computed: true},
			"tag_ids": schema.SetAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "Tag UUIDs attached to the project.",
				Computed:            true,
			},
		},
	}
}

func (d *projectDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	clientFrom(req.ProviderData, &d.client, resp.Diagnostics.AddError)
}

func (d *projectDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config projectDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if config.ID.IsNull() && config.Slug.IsNull() {
		resp.Diagnostics.AddError("Missing project selector", "Set either id or slug.")
		return
	}

	var project *himitsu.Project
	if !config.ID.IsNull() {
		found, err := d.client.GetProject(ctx, config.ID.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Unable to read project", err.Error())
			return
		}
		project = found
	} else {
		// No lookup-by-slug endpoint exists, so filter the listing.
		projects, err := d.client.ListProjects(ctx)
		if err != nil {
			resp.Diagnostics.AddError("Unable to list projects", err.Error())
			return
		}
		slug := config.Slug.ValueString()
		for i := range projects {
			if projects[i].Slug == slug && projects[i].DeletedAt == nil {
				project = &projects[i]
				break
			}
		}
		if project == nil {
			resp.Diagnostics.AddError("Project not found", fmt.Sprintf("No project with slug %q is visible to this token.", slug))
			return
		}
	}

	config.ID = types.StringValue(project.ID)
	config.Slug = types.StringValue(project.Slug)
	config.Name = types.StringValue(project.Name)
	config.Description = optionalString(project.Description)
	config.OrgID = types.StringValue(project.OrgID)
	tagIDs, diags := types.SetValueFrom(ctx, types.StringType, project.TagIDs)
	resp.Diagnostics.Append(diags...)
	config.TagIDs = tagIDs
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}

// ---- himitsu_environment ----

var (
	_ datasource.DataSource              = (*environmentDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*environmentDataSource)(nil)
)

type environmentDataSource struct{ client *himitsu.Client }

// NewEnvironmentDataSource returns the himitsu_environment data source.
func NewEnvironmentDataSource() datasource.DataSource { return &environmentDataSource{} }

type environmentDataModel struct {
	ID        types.String `tfsdk:"id"`
	ProjectID types.String `tfsdk:"project_id"`
	Slug      types.String `tfsdk:"slug"`
	Name      types.String `tfsdk:"name"`
	Protected types.Bool   `tfsdk:"protected"`
}

func (d *environmentDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_environment"
}

func (d *environmentDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Looks up an environment within a project by id or slug.",
		Attributes: map[string]schema.Attribute{
			"project_id": schema.StringAttribute{
				MarkdownDescription: "Project UUID.",
				Required:            true,
			},
			"id": schema.StringAttribute{
				MarkdownDescription: "Environment UUID. Provide this or `slug`.",
				Optional:            true,
				Computed:            true,
			},
			"slug": schema.StringAttribute{
				MarkdownDescription: "Environment slug, e.g. `production`. Provide this or `id`.",
				Optional:            true,
				Computed:            true,
			},
			"name":      schema.StringAttribute{MarkdownDescription: "Environment name.", Computed: true},
			"protected": schema.BoolAttribute{MarkdownDescription: "Whether the environment is protected.", Computed: true},
		},
	}
}

func (d *environmentDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	clientFrom(req.ProviderData, &d.client, resp.Diagnostics.AddError)
}

func (d *environmentDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config environmentDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if config.ID.IsNull() && config.Slug.IsNull() {
		resp.Diagnostics.AddError("Missing environment selector", "Set either id or slug.")
		return
	}

	projectID := config.ProjectID.ValueString()
	var environment *himitsu.Environment
	if !config.ID.IsNull() {
		found, err := d.client.GetEnvironment(ctx, projectID, config.ID.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Unable to read environment", err.Error())
			return
		}
		environment = found
	} else {
		environments, err := d.client.ListEnvironments(ctx, projectID)
		if err != nil {
			resp.Diagnostics.AddError("Unable to list environments", err.Error())
			return
		}
		slug := config.Slug.ValueString()
		for i := range environments {
			if environments[i].Slug == slug && environments[i].DeletedAt == nil {
				environment = &environments[i]
				break
			}
		}
		if environment == nil {
			resp.Diagnostics.AddError("Environment not found",
				fmt.Sprintf("No environment with slug %q exists in project %s.", slug, projectID))
			return
		}
	}

	config.ID = types.StringValue(environment.ID)
	config.ProjectID = types.StringValue(environment.ProjectID)
	config.Slug = types.StringValue(environment.Slug)
	config.Name = types.StringValue(environment.Name)
	config.Protected = types.BoolValue(environment.Protected)
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}

// ---- himitsu_secrets ----

var (
	_ datasource.DataSource              = (*secretsDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*secretsDataSource)(nil)
)

type secretsDataSource struct{ client *himitsu.Client }

// NewSecretsDataSource returns the himitsu_secrets data source.
func NewSecretsDataSource() datasource.DataSource { return &secretsDataSource{} }

type secretsDataModel struct {
	ProjectID     types.String `tfsdk:"project_id"`
	EnvironmentID types.String `tfsdk:"environment_id"`
	Secrets       types.Map    `tfsdk:"secrets"`
	Keys          types.Set    `tfsdk:"keys"`
	ConfigVersion types.Int64  `tfsdk:"config_version"`
}

func (d *secretsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secrets"
}

func (d *secretsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads every secret in a Himitsu environment as a map.\n\n" +
			"~> The returned values are written to Terraform state in plaintext. Use an encrypted " +
			"state backend. If you only need key names, use the `keys` attribute, which is not sensitive.",
		Attributes: map[string]schema.Attribute{
			"project_id": schema.StringAttribute{
				MarkdownDescription: "Project UUID.",
				Required:            true,
			},
			"environment_id": schema.StringAttribute{
				MarkdownDescription: "Environment UUID.",
				Required:            true,
			},
			"secrets": schema.MapAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "Secret keys mapped to their plaintext values.",
				Computed:            true,
				Sensitive:           true,
			},
			"keys": schema.SetAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "Secret key names, without values.",
				Computed:            true,
			},
			"config_version": schema.Int64Attribute{
				MarkdownDescription: "Environment config version at read time. Increments on every secret change.",
				Computed:            true,
			},
		},
	}
}

func (d *secretsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	clientFrom(req.ProviderData, &d.client, resp.Diagnostics.AddError)
}

func (d *secretsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config secretsDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// knownVersion 0 forces a full read: a data source must always return
	// values, so the 304 path is not useful here.
	runtime, err := d.client.RuntimeConfig(ctx,
		config.ProjectID.ValueString(), config.EnvironmentID.ValueString(), 0)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read secrets", err.Error())
		return
	}

	secrets, diags := types.MapValueFrom(ctx, types.StringType, runtime.Secrets)
	resp.Diagnostics.Append(diags...)

	keyNames := make([]string, 0, len(runtime.Secrets))
	for key := range runtime.Secrets {
		keyNames = append(keyNames, key)
	}
	keys, diags := types.SetValueFrom(ctx, types.StringType, keyNames)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	config.Secrets = secrets
	config.Keys = keys
	config.ConfigVersion = types.Int64Value(runtime.ConfigVersion)
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
