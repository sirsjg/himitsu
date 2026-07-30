package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	himitsu "github.com/sirsjg/himitsu/integrations/client"
)

var (
	_ resource.Resource                = (*tagResource)(nil)
	_ resource.ResourceWithConfigure   = (*tagResource)(nil)
	_ resource.ResourceWithImportState = (*tagResource)(nil)
)

type tagResource struct {
	client *himitsu.Client
}

// NewTagResource returns the himitsu_tag resource.
func NewTagResource() resource.Resource { return &tagResource{} }

type tagModel struct {
	ID    types.String `tfsdk:"id"`
	Name  types.String `tfsdk:"name"`
	Color types.String `tfsdk:"color"`
}

func (r *tagResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_tag"
}

func (r *tagResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "An organization-wide label that can be attached to projects and secrets.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "Tag UUID.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Tag name, unique within the organization.",
				Required:            true,
			},
			"color": schema.StringAttribute{
				MarkdownDescription: "Six-digit hex colour, e.g. `#4F46E5`.",
				Required:            true,
				Validators: []validator.String{
					// Catch the format locally so a typo fails at plan time
					// rather than as a 400 mid-apply.
					stringvalidator.RegexMatches(hexColor, "must be a six-digit hex colour such as #4F46E5"),
				},
			},
		},
	}
}

func (r *tagResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	clientFrom(req.ProviderData, &r.client, resp.Diagnostics.AddError)
}

func (r *tagResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan tagModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tag, err := r.client.CreateTag(ctx, himitsu.CreateTagInput{
		Name:  plan.Name.ValueString(),
		Color: plan.Color.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("Unable to create tag", err.Error())
		return
	}

	applyTag(tag, &plan)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *tagResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state tagModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tag, err := r.client.GetTag(ctx, state.ID.ValueString())
	if err != nil {
		if himitsu.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Unable to read tag", err.Error())
		return
	}

	applyTag(tag, &state)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *tagResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state tagModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tag, err := r.client.UpdateTag(ctx, state.ID.ValueString(), himitsu.UpdateTagInput{
		Name:  himitsu.Ptr(plan.Name.ValueString()),
		Color: himitsu.Ptr(plan.Color.ValueString()),
	})
	if err != nil {
		resp.Diagnostics.AddError("Unable to update tag", err.Error())
		return
	}

	applyTag(tag, &plan)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *tagResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state tagModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.DeleteTag(ctx, state.ID.ValueString()); err != nil {
		if himitsu.IsNotFound(err) {
			return
		}
		resp.Diagnostics.AddError("Unable to delete tag", err.Error())
	}
}

func (r *tagResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func applyTag(tag *himitsu.Tag, model *tagModel) {
	model.ID = types.StringValue(tag.ID)
	model.Name = types.StringValue(tag.Name)
	model.Color = types.StringValue(tag.Color)
}
