terraform {
  required_version = ">= 1.5.0"
  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.0"          # pin it. the 2.x -> 3.0 rename matters, see Step 2
    }
  }
}

provider "azuread" {}

data "azuread_client_config" "current" {}

resource "azuread_application" "provenance_test" {
  display_name = "tf-provenance-test"
  owners       = [data.azuread_client_config.current.object_id]
}

resource "azuread_service_principal" "provenance_test" {
  client_id = azuread_application.provenance_test.client_id
  owners    = [data.azuread_client_config.current.object_id]
}

output "app_object_id" { value = azuread_application.provenance_test.object_id }
output "sp_object_id"  { value = azuread_service_principal.provenance_test.object_id }
