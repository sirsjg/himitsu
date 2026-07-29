package provider

import (
	"context"
	"regexp"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	himitsu "github.com/sirsjg/himitsu-enterprise/integrations/client"
)

// hexColor validates a six-digit hex colour. Shared with the tag resource.
var hexColor = regexp.MustCompile(`^#[0-9A-Fa-f]{6}$`)

var (
	_ resource.Resource              = (*apiKeyResource)(nil)
	_ resource.ResourceWithConfigure = (*apiKeyResource)(nil)
)

type apiKeyResource struct {
	client *himitsu.Client
}

// NewAPIKeyResource returns the himitsu_api_key resource.
func NewAPIKeyResource() resource.Resource { return &apiKeyResource{} }

type apiKeyModel struct {
	ID            types.String `tfsdk:"id"`
	Name          types.String `tfsdk:"name"`
	Access        types.String `tfsdk:"access"`
	ProjectID     types.String `tfsdk:"project_id"`
	EnvironmentID types.String `tfsdk:"environment_id"`
	ExpiresAt     types.String `tfsdk:"expires_at"`
	Prefix        types.String `tfsdk:"prefix"`
	Token         types.String `tfsdk:"token"`
	CreatedAt     types.String `tfsdk:"created_at"`
}

func (r *apiKeyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_api_key"
}

func (r *apiKeyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	// Every attribute forces replacement: the API mints a token once and offers
	// no update operation, so any change means a new key.
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}

	resp.Schema = schema.Schema{
		MarkdownDescription: "A Himitsu API token for machine access.\n\n" +
			"~> The generated token is stored in Terraform state and can only be read at creation. " +
			"Treat state as a secret, and prefer narrow scopes: set `project_id` and `environment_id`, " +
			"and use `read_only` access unless writes are genuinely required.\n\n" +
			"~> A token's effective permissions follow the Himitsu membership of the user whose " +
			"credentials created it. If that user is removed or demoted, this token's access changes with them.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "API key UUID.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Descriptive name shown in the Himitsu UI.",
				Required:            true,
				PlanModifiers:       replace,
			},
			"access": schema.StringAttribute{
				MarkdownDescription: "Either `read_only` or `read_write`.",
				Required:            true,
				PlanModifiers:       replace,
				Validators: []validator.String{
					stringvalidator.OneOf(string(himitsu.AccessReadOnly), string(himitsu.AccessReadWrite)),
				},
			},
			"project_id": schema.StringAttribute{
				MarkdownDescription: "Restrict the key to one project. Omit for an organization-wide key.",
				Optional:            true,
				PlanModifiers:       replace,
			},
			"environment_id": schema.StringAttribute{
				MarkdownDescription: "Restrict the key to one environment. Requires `project_id`.",
				Optional:            true,
				PlanModifiers:       replace,
			},
			"expires_at": schema.StringAttribute{
				MarkdownDescription: "RFC 3339 expiry timestamp. Omit for a non-expiring key.",
				Optional:            true,
				PlanModifiers:       replace,
			},
			"prefix": schema.StringAttribute{
				MarkdownDescription: "Non-secret token prefix, used to identify the key in audit events.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"token": schema.StringAttribute{
				MarkdownDescription: "The generated token. Returned only at creation.",
				Computed:            true,
				Sensitive:           true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"created_at": schema.StringAttribute{
				MarkdownDescription: "RFC 3339 creation timestamp.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

func (r *apiKeyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	clientFrom(req.ProviderData, &r.client, resp.Diagnostics.AddError)
}

func (r *apiKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan apiKeyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !plan.EnvironmentID.IsNull() && plan.ProjectID.IsNull() {
		resp.Diagnostics.AddAttributeError(path.Root("environment_id"),
			"environment_id requires project_id",
			"An environment-scoped API key must also specify the project that owns the environment.")
		return
	}

	input := himitsu.CreateAPIKeyInput{
		Name:   plan.Name.ValueString(),
		Access: himitsu.APIKeyAccess(plan.Access.ValueString()),
	}
	if !plan.ProjectID.IsNull() {
		input.ProjectID = himitsu.Ptr(plan.ProjectID.ValueString())
	}
	if !plan.EnvironmentID.IsNull() {
		input.EnvironmentID = himitsu.Ptr(plan.EnvironmentID.ValueString())
	}
	if !plan.ExpiresAt.IsNull() {
		expiry, err := time.Parse(time.RFC3339, plan.ExpiresAt.ValueString())
		if err != nil {
			resp.Diagnostics.AddAttributeError(path.Root("expires_at"),
				"Invalid expiry timestamp",
				"expires_at must be an RFC 3339 timestamp such as 2027-01-31T00:00:00Z.\n\n"+err.Error())
			return
		}
		input.ExpiresAt = himitsu.Ptr(expiry)
	}

	created, err := r.client.CreateAPIKey(ctx, input)
	if err != nil {
		resp.Diagnostics.AddError("Unable to create API key", err.Error())
		return
	}

	plan.ID = types.StringValue(created.APIKey.ID)
	plan.Prefix = types.StringValue(created.APIKey.Prefix)
	plan.Token = types.StringValue(created.Token)
	plan.CreatedAt = types.StringValue(created.APIKey.CreatedAt.Format(time.RFC3339))
	applyAPIKeyScope(&created.APIKey, &plan)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *apiKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state apiKeyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	key, err := r.client.GetAPIKey(ctx, state.ID.ValueString())
	if err != nil {
		if himitsu.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Unable to read API key", err.Error())
		return
	}
	// A revoked key is dead; treat it as absent so the next apply mints a
	// replacement rather than leaving a token that authenticates nothing.
	if key.RevokedAt != nil {
		resp.State.RemoveResource(ctx)
		return
	}

	state.Name = types.StringValue(key.Name)
	state.Access = types.StringValue(string(key.Access))
	state.Prefix = types.StringValue(key.Prefix)
	state.CreatedAt = types.StringValue(key.CreatedAt.Format(time.RFC3339))
	applyAPIKeyScope(key, &state)
	// token is intentionally left as-is: the API never returns it again, and
	// overwriting it with null would destroy the only copy.
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update is unreachable because every attribute forces replacement, but the
// interface requires it.
func (r *apiKeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("API keys cannot be updated",
		"Every attribute of himitsu_api_key forces replacement. This is a bug in the provider if you see it.")
}

func (r *apiKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state apiKeyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.RevokeAPIKey(ctx, state.ID.ValueString()); err != nil {
		if himitsu.IsNotFound(err) {
			return
		}
		resp.Diagnostics.AddError("Unable to revoke API key", err.Error())
	}
}

func applyAPIKeyScope(key *himitsu.APIKey, model *apiKeyModel) {
	model.ProjectID = optionalString(key.ProjectID)
	model.EnvironmentID = optionalString(key.EnvironmentID)
	if key.ExpiresAt == nil {
		model.ExpiresAt = types.StringNull()
		return
	}
	model.ExpiresAt = types.StringValue(key.ExpiresAt.Format(time.RFC3339))
}
