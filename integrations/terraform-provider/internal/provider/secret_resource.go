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
	_ resource.Resource                = (*secretResource)(nil)
	_ resource.ResourceWithConfigure   = (*secretResource)(nil)
	_ resource.ResourceWithImportState = (*secretResource)(nil)
)

type secretResource struct {
	client *himitsu.Client
}

// NewSecretResource returns the himitsu_secret resource.
func NewSecretResource() resource.Resource { return &secretResource{} }

type secretModel struct {
	ID                    types.String `tfsdk:"id"`
	ProjectID             types.String `tfsdk:"project_id"`
	EnvironmentID         types.String `tfsdk:"environment_id"`
	Key                   types.String `tfsdk:"key"`
	Value                 types.String `tfsdk:"value"`
	Notes                 types.String `tfsdk:"notes"`
	ChangeNote            types.String `tfsdk:"change_note"`
	AllowNonConformingKey types.Bool   `tfsdk:"allow_non_conforming_key"`
	TagIDs                types.Set    `tfsdk:"tag_ids"`
	CurrentVersion        types.Int64  `tfsdk:"current_version"`
}

func (r *secretResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secret"
}

func (r *secretResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A single encrypted secret in a Himitsu environment.\n\n" +
			"~> **The value is stored in Terraform state in plaintext.** This is inherent to " +
			"Terraform, not specific to Himitsu. Use an encrypted state backend with restricted access, " +
			"or manage secret values outside Terraform and use the `himitsu_secrets` data source to read them.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "Secret UUID.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"project_id": schema.StringAttribute{
				MarkdownDescription: "Project UUID.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"environment_id": schema.StringAttribute{
				MarkdownDescription: "Environment UUID.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"key": schema.StringAttribute{
				MarkdownDescription: "Secret key, e.g. `DATABASE_URL`. Changing it replaces the secret, " +
					"because the API has no rename operation and version history is bound to the key.",
				Required:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"value": schema.StringAttribute{
				MarkdownDescription: "Secret value. Writing a new value creates a new version server-side.",
				Required:            true,
				Sensitive:           true,
			},
			"notes": schema.StringAttribute{
				MarkdownDescription: "Optional non-secret note describing what this secret is for.",
				Optional:            true,
			},
			"change_note": schema.StringAttribute{
				MarkdownDescription: "Message recorded on the version created by this write, visible in the audit log.",
				Optional:            true,
			},
			"allow_non_conforming_key": schema.BoolAttribute{
				MarkdownDescription: "Permit a key that does not match Himitsu's recommended naming convention.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"tag_ids": schema.SetAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "Tag UUIDs attached to the secret.",
				Optional:            true,
			},
			"current_version": schema.Int64Attribute{
				MarkdownDescription: "Server-side version number, incremented on every value change.",
				Computed:            true,
			},
		},
	}
}

func (r *secretResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	clientFrom(req.ProviderData, &r.client, resp.Diagnostics.AddError)
}

func (r *secretResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan secretModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	input := himitsu.CreateSecretInput{
		Key:                   plan.Key.ValueString(),
		Value:                 plan.Value.ValueString(),
		AllowNonConformingKey: himitsu.Ptr(plan.AllowNonConformingKey.ValueBool()),
	}
	if !plan.Notes.IsNull() {
		input.Notes = himitsu.Ptr(plan.Notes.ValueString())
	}
	if !plan.ChangeNote.IsNull() {
		input.ChangeNote = himitsu.Ptr(plan.ChangeNote.ValueString())
	}
	resp.Diagnostics.Append(stringsFromSet(ctx, plan.TagIDs, &input.TagIDs)...)
	if resp.Diagnostics.HasError() {
		return
	}

	secret, err := r.client.CreateSecret(ctx,
		plan.ProjectID.ValueString(), plan.EnvironmentID.ValueString(), input)
	if err != nil {
		resp.Diagnostics.AddError("Unable to create secret", err.Error())
		return
	}

	resp.Diagnostics.Append(applySecretMetadata(ctx, secret, &plan)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *secretResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state secretModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// GetSecret returns the plaintext, which is what lets Terraform detect that
	// someone changed the value outside Terraform. It records a secret.read
	// audit event on every refresh — expected, and worth knowing about.
	secret, err := r.client.GetSecret(ctx, state.ID.ValueString())
	if err != nil {
		if himitsu.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Unable to read secret", err.Error())
		return
	}

	state.Value = types.StringValue(secret.Value)
	resp.Diagnostics.Append(applySecretMetadata(ctx, &secret.Secret, &state)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *secretResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state secretModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	input := himitsu.UpdateSecretInput{Value: plan.Value.ValueString()}
	if !plan.Notes.IsNull() {
		input.Notes = himitsu.Ptr(plan.Notes.ValueString())
	}
	if !plan.ChangeNote.IsNull() {
		input.ChangeNote = himitsu.Ptr(plan.ChangeNote.ValueString())
	}
	resp.Diagnostics.Append(stringsFromSet(ctx, plan.TagIDs, &input.TagIDs)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Send If-Match with the version we last observed. If another writer changed
	// the secret since the last refresh, the API rejects the write instead of
	// silently clobbering it.
	expected := int(state.CurrentVersion.ValueInt64())
	secret, err := r.client.UpdateSecret(ctx, state.ID.ValueString(), input, expected)
	if err != nil {
		if himitsu.IsConflict(err) {
			resp.Diagnostics.AddError("Secret changed outside Terraform",
				fmt.Sprintf("Secret %q was modified since Terraform last read it (expected version %d). "+
					"Run `terraform refresh` or `terraform apply -refresh-only` to reconcile, then re-apply.\n\n%s",
					state.Key.ValueString(), expected, err.Error()))
			return
		}
		resp.Diagnostics.AddError("Unable to update secret", err.Error())
		return
	}

	resp.Diagnostics.Append(applySecretMetadata(ctx, secret, &plan)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *secretResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state secretModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.DeleteSecret(ctx, state.ID.ValueString()); err != nil {
		if himitsu.IsNotFound(err) {
			return
		}
		resp.Diagnostics.AddError("Unable to delete secret", err.Error())
	}
}

// ImportState accepts "<project_id>/<environment_id>/<KEY>", since a secret is
// addressed by key rather than by an id a practitioner would know.
func (r *secretResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.Split(req.ID, "/")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		resp.Diagnostics.AddError("Unexpected import identifier",
			fmt.Sprintf("Expected \"<project_id>/<environment_id>/<KEY>\", got %q.", req.ID))
		return
	}
	projectID, environmentID, key := parts[0], parts[1], parts[2]

	if r.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Himitsu provider must be configured before import.")
		return
	}
	secret, err := r.client.FindSecretByKey(ctx, projectID, environmentID, key)
	if err != nil {
		resp.Diagnostics.AddError("Unable to import secret", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), secret.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("project_id"), projectID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("environment_id"), environmentID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("key"), key)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("allow_non_conforming_key"), false)...)
}

func applySecretMetadata(ctx context.Context, secret *himitsu.Secret, model *secretModel) (diagnostics diagnosticList) {
	model.ID = types.StringValue(secret.ID)
	model.ProjectID = types.StringValue(secret.ProjectID)
	model.EnvironmentID = types.StringValue(secret.EnvironmentID)
	model.Key = types.StringValue(secret.Key)
	model.Notes = optionalString(secret.Notes)
	model.CurrentVersion = types.Int64Value(int64(secret.CurrentVersion))

	// change_note describes a single write and is never echoed by the API, so
	// the configured value is preserved as-is.
	if model.ChangeNote.IsUnknown() {
		model.ChangeNote = types.StringNull()
	}
	if model.AllowNonConformingKey.IsNull() || model.AllowNonConformingKey.IsUnknown() {
		model.AllowNonConformingKey = types.BoolValue(false)
	}

	tagIDs, diags := setFromStrings(ctx, secret.TagIDs, model.TagIDs)
	diagnostics = append(diagnostics, diags...)
	model.TagIDs = tagIDs
	return diagnostics
}
