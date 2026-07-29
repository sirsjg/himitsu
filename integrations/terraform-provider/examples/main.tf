terraform {
  required_providers {
    himitsu = {
      source  = "himitsu-io/himitsu"
      version = "~> 0.1"
    }
  }
}

# Credentials come from HIMITSU_API_URL and HIMITSU_TOKEN. Setting the token
# in configuration would commit it to version control.
provider "himitsu" {}

resource "himitsu_tag" "managed" {
  name  = "terraform-managed"
  color = "#4F46E5"
}

resource "himitsu_project" "payments" {
  name        = "Payments"
  slug        = "payments"
  description = "Payment processing service"
  tag_ids     = [himitsu_tag.managed.id]
}

resource "himitsu_environment" "production" {
  project_id = himitsu_project.payments.id
  name       = "Production"
  slug       = "production"

  # Restrict writes to owners and admins.
  protected = true
}

resource "himitsu_environment" "staging" {
  project_id = himitsu_project.payments.id
  name       = "Staging"
  slug       = "staging"
}

# Managing a value through Terraform puts it in state. Prefer sourcing it from
# somewhere that is already state-adjacent, such as another resource's output.
resource "himitsu_secret" "database_url" {
  project_id     = himitsu_project.payments.id
  environment_id = himitsu_environment.staging.id
  key            = "DATABASE_URL"
  value          = "postgres://app:${random_password.db.result}@db.internal:5432/payments"
  notes          = "Primary application database"
  change_note    = "Managed by Terraform"
  tag_ids        = [himitsu_tag.managed.id]
}

resource "random_password" "db" {
  length  = 32
  special = false
}

# A narrowly scoped token for the Kubernetes operator: read-only, and limited
# to the single environment it syncs.
resource "himitsu_api_key" "operator" {
  name           = "kubernetes-operator-production"
  access         = "read_only"
  project_id     = himitsu_project.payments.id
  environment_id = himitsu_environment.production.id
  expires_at     = "2027-01-31T00:00:00Z"
}

output "operator_token" {
  value     = himitsu_api_key.operator.token
  sensitive = true
}

# Reading an environment that something else populates. Values are sensitive;
# `keys` is not, which makes it usable in plan output and assertions.
data "himitsu_secrets" "production" {
  project_id     = himitsu_project.payments.id
  environment_id = himitsu_environment.production.id
}

output "production_secret_names" {
  value = data.himitsu_secrets.production.keys
}

# Looking up resources this configuration does not own.
data "himitsu_project" "legacy" {
  slug = "legacy-billing"
}

data "himitsu_environment" "legacy_production" {
  project_id = data.himitsu_project.legacy.id
  slug       = "production"
}
