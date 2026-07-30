package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	himitsu "github.com/sirsjg/himitsu/integrations/client"
)

var (
	_ resource.Resource                = (*projectResource)(nil)
	_ resource.ResourceWithConfigure   = (*projectResource)(nil)
	_ resource.ResourceWithImportState = (*projectResource)(nil)
)

type projectResource struct {
	client *himitsu.Client
}

// NewProjectResource returns the himitsu_project resource.
func NewProjectResource() resource.Resource { return &projectResource{} }

type projectModel struct {
	ID                  types.String `tfsdk:"id"`
	OrgID               types.String `tfsdk:"org_id"`
	Name                types.String `tfsdk:"name"`
	Slug                types.String `tfsdk:"slug"`
	Description         types.String `tfsdk:"description"`
	DefaultEnvironments types.List   `tfsdk:"default_environments"`
	TagIDs              types.Set    `tfsdk:"tag_ids"`
}

func (r *projectResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_project"
}

func (r *projectResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A Himitsu project, which owns environments and secrets.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "Project UUID.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"org_id": schema.StringAttribute{
				MarkdownDescription: "Organization UUID that owns the project.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Human-readable project name.",
				Required:            true,
			},
			"slug": schema.StringAttribute{
				MarkdownDescription: "URL-safe identifier, unique within the organization.",
				Required:            true,
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "Optional description.",
				Optional:            true,
			},
			"default_environments": schema.ListAttribute{
				ElementType: types.StringType,
				MarkdownDescription: "Environment names created alongside the project. " +
					"These environments are **not** tracked by this resource; declare `himitsu_environment` " +
					"resources instead if you want Terraform to manage them.",
				Optional: true,
			},
			"tag_ids": schema.SetAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "Tag UUIDs attached to the project.",
				Optional:            true,
			},
		},
	}
}

func (r *projectResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	clientFrom(req.ProviderData, &r.client, resp.Diagnostics.AddError)
}

func (r *projectResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan projectModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	input := himitsu.CreateProjectInput{
		Name: plan.Name.ValueString(),
		Slug: plan.Slug.ValueString(),
	}
	if !plan.Description.IsNull() {
		input.Description = himitsu.Ptr(plan.Description.ValueString())
	}
	resp.Diagnostics.Append(stringsFromList(ctx, plan.DefaultEnvironments, &input.DefaultEnvironments)...)
	resp.Diagnostics.Append(stringsFromSet(ctx, plan.TagIDs, &input.TagIDs)...)
	if resp.Diagnostics.HasError() {
		return
	}

	project, err := r.client.CreateProject(ctx, input)
	if err != nil {
		resp.Diagnostics.AddError("Unable to create project", err.Error())
		return
	}

	resp.Diagnostics.Append(applyProject(ctx, project, &plan)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *projectResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state projectModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	project, err := r.client.GetProject(ctx, state.ID.ValueString())
	if err != nil {
		if himitsu.IsNotFound(err) {
			// Deleted outside Terraform: drop it from state so the next plan
			// recreates it rather than failing forever.
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Unable to read project", err.Error())
		return
	}
	// A soft-deleted project is gone as far as configuration is concerned.
	if project.DeletedAt != nil {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(applyProject(ctx, project, &state)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *projectResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan projectModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var state projectModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	input := himitsu.UpdateProjectInput{
		Name: himitsu.Ptr(plan.Name.ValueString()),
		Slug: himitsu.Ptr(plan.Slug.ValueString()),
	}
	if plan.Description.IsNull() {
		// An explicit null clears the description; omitting the field would
		// leave the old value in place.
		input.Description = nil
	} else {
		input.Description = himitsu.Ptr(plan.Description.ValueString())
	}
	resp.Diagnostics.Append(stringsFromList(ctx, plan.DefaultEnvironments, &input.DefaultEnvironments)...)
	resp.Diagnostics.Append(stringsFromSet(ctx, plan.TagIDs, &input.TagIDs)...)
	if resp.Diagnostics.HasError() {
		return
	}

	project, err := r.client.UpdateProject(ctx, state.ID.ValueString(), input)
	if err != nil {
		resp.Diagnostics.AddError("Unable to update project", err.Error())
		return
	}

	resp.Diagnostics.Append(applyProject(ctx, project, &plan)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *projectResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state projectModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.DeleteProject(ctx, state.ID.ValueString()); err != nil {
		if himitsu.IsNotFound(err) {
			return
		}
		resp.Diagnostics.AddError("Unable to delete project", err.Error())
	}
}

func (r *projectResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// applyProject copies API state onto the model, preserving the distinction
// between an unset optional and an empty one so Terraform does not report a
// permanent diff.
func applyProject(ctx context.Context, project *himitsu.Project, model *projectModel) (diagnostics diagnosticList) {
	model.ID = types.StringValue(project.ID)
	model.OrgID = types.StringValue(project.OrgID)
	model.Name = types.StringValue(project.Name)
	model.Slug = types.StringValue(project.Slug)
	model.Description = optionalString(project.Description)

	// default_environments is write-only: the API applies it at creation and
	// never echoes it back, so preserving the configured value is the only way
	// to avoid a phantom diff on every plan.
	if model.DefaultEnvironments.IsUnknown() {
		model.DefaultEnvironments = types.ListNull(types.StringType)
	}

	tagIDs, diags := setFromStrings(ctx, project.TagIDs, model.TagIDs)
	diagnostics = append(diagnostics, diags...)
	model.TagIDs = tagIDs
	return diagnostics
}
