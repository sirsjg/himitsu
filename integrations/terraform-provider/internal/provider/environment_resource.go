package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	himitsu "github.com/sirsjg/himitsu-enterprise/integrations/client"
)

var (
	_ resource.Resource                = (*environmentResource)(nil)
	_ resource.ResourceWithConfigure   = (*environmentResource)(nil)
	_ resource.ResourceWithImportState = (*environmentResource)(nil)
)

type environmentResource struct {
	client *himitsu.Client
}

// NewEnvironmentResource returns the himitsu_environment resource.
func NewEnvironmentResource() resource.Resource { return &environmentResource{} }

type environmentModel struct {
	ID             types.String `tfsdk:"id"`
	ProjectID      types.String `tfsdk:"project_id"`
	OrgID          types.String `tfsdk:"org_id"`
	Name           types.String `tfsdk:"name"`
	Slug           types.String `tfsdk:"slug"`
	Protected      types.Bool   `tfsdk:"protected"`
	DisplayOrder   types.Int64  `tfsdk:"display_order"`
	ConfirmSecrets types.Bool   `tfsdk:"confirm_secrets_on_destroy"`
}

func (r *environmentResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_environment"
}

func (r *environmentResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A deployment environment within a Himitsu project.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "Environment UUID.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"project_id": schema.StringAttribute{
				MarkdownDescription: "Project UUID that owns the environment.",
				Required:            true,
				// The API has no move operation, so changing the project means
				// building a new environment.
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"org_id": schema.StringAttribute{
				MarkdownDescription: "Organization UUID.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Human-readable environment name.",
				Required:            true,
			},
			"slug": schema.StringAttribute{
				MarkdownDescription: "URL-safe identifier, unique within the project.",
				Required:            true,
			},
			"protected": schema.BoolAttribute{
				MarkdownDescription: "When true, only owners and admins may write secrets or change the environment.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"display_order": schema.Int64Attribute{
				MarkdownDescription: "Ordering position in the UI. Managed by the API.",
				Computed:            true,
			},
			"confirm_secrets_on_destroy": schema.BoolAttribute{
				MarkdownDescription: "Allow destroying this environment while it still holds secrets. " +
					"Defaults to false, which makes the API refuse the delete rather than silently discarding secrets.",
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
			},
		},
	}
}

func (r *environmentResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	clientFrom(req.ProviderData, &r.client, resp.Diagnostics.AddError)
}

func (r *environmentResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan environmentModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	environment, err := r.client.CreateEnvironment(ctx, plan.ProjectID.ValueString(), himitsu.CreateEnvironmentInput{
		Name:      plan.Name.ValueString(),
		Slug:      plan.Slug.ValueString(),
		Protected: himitsu.Ptr(plan.Protected.ValueBool()),
	})
	if err != nil {
		resp.Diagnostics.AddError("Unable to create environment", err.Error())
		return
	}

	applyEnvironment(environment, &plan)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *environmentResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state environmentModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	environment, err := r.client.GetEnvironment(ctx, state.ProjectID.ValueString(), state.ID.ValueString())
	if err != nil {
		if himitsu.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Unable to read environment", err.Error())
		return
	}
	if environment.DeletedAt != nil {
		resp.State.RemoveResource(ctx)
		return
	}

	applyEnvironment(environment, &state)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *environmentResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state environmentModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	environment, err := r.client.UpdateEnvironment(ctx,
		state.ProjectID.ValueString(), state.ID.ValueString(),
		himitsu.UpdateEnvironmentInput{
			Name:      himitsu.Ptr(plan.Name.ValueString()),
			Slug:      himitsu.Ptr(plan.Slug.ValueString()),
			Protected: himitsu.Ptr(plan.Protected.ValueBool()),
		})
	if err != nil {
		resp.Diagnostics.AddError("Unable to update environment", err.Error())
		return
	}

	applyEnvironment(environment, &plan)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *environmentResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state environmentModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.client.DeleteEnvironment(ctx,
		state.ProjectID.ValueString(), state.ID.ValueString(), state.ConfirmSecrets.ValueBool())
	if err != nil {
		if himitsu.IsNotFound(err) {
			return
		}
		// Translate the API's refusal into advice, since the fix is a config
		// change the practitioner has to make deliberately.
		if himitsu.ErrorCode(err) == "ENVIRONMENT_NOT_EMPTY" || strings.Contains(err.Error(), "confirmSecrets") {
			resp.Diagnostics.AddError("Environment still contains secrets",
				"Himitsu refused to delete this environment because it still holds secrets. "+
					"Set confirm_secrets_on_destroy = true to allow it, or remove the secrets first.\n\n"+err.Error())
			return
		}
		resp.Diagnostics.AddError("Unable to delete environment", err.Error())
	}
}

// ImportState accepts "<project_id>/<environment_id>", because reading an
// environment requires both.
func (r *environmentResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	projectID, environmentID, ok := strings.Cut(req.ID, "/")
	if !ok || projectID == "" || environmentID == "" {
		resp.Diagnostics.AddError("Unexpected import identifier",
			fmt.Sprintf("Expected \"<project_id>/<environment_id>\", got %q.", req.ID))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("project_id"), projectID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), environmentID)...)
}

func applyEnvironment(environment *himitsu.Environment, model *environmentModel) {
	model.ID = types.StringValue(environment.ID)
	model.OrgID = types.StringValue(environment.OrgID)
	model.ProjectID = types.StringValue(environment.ProjectID)
	model.Name = types.StringValue(environment.Name)
	model.Slug = types.StringValue(environment.Slug)
	model.Protected = types.BoolValue(environment.Protected)
	model.DisplayOrder = types.Int64Value(int64(environment.DisplayOrder))
	// confirm_secrets_on_destroy is provider-side behaviour with no API
	// counterpart; default it so import does not leave it unknown.
	if model.ConfirmSecrets.IsNull() || model.ConfirmSecrets.IsUnknown() {
		model.ConfirmSecrets = types.BoolValue(false)
	}
}
