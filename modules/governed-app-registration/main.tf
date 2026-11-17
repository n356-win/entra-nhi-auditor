resource "azuread_application" "this" {
  display_name = var.display_name
  owners       = var.owners          # required variable - the plan FAILS without one

  dynamic "required_resource_access" {
    for_each = var.required_resource_access
    content {
      resource_app_id = required_resource_access.value.resource_app_id
      dynamic "resource_access" {
        for_each = required_resource_access.value.resource_access
        content {
          id   = resource_access.value.id
          type = resource_access.value.type
        }
      }
    }
  }
}

resource "azuread_service_principal" "this" {
  client_id = azuread_application.this.client_id
  owners    = var.owners
}

# Federated credential is the ONLY credential this module exposes.
# azuread_application_password is deliberately absent: the weaker option is not on the menu.
resource "azuread_application_federated_identity_credential" "this" {
  for_each       = var.federated_credentials
  application_id = azuread_application.this.id
  display_name   = each.key
  audiences      = ["api://AzureADTokenExchange"]
  issuer         = each.value.issuer
  subject        = each.value.subject
}
