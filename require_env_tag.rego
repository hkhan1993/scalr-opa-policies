package terraform

import rego.v1
import input.tfplan as tfplan

deny contains msg if {
  resource := tfplan.resource_changes[_]
  "create" in resource.change.actions
  is_object(resource.change.after.tags)
  not resource.change.after.tags.Environment
  msg := sprintf("Advisory: %s is missing the 'Environment' tag.", [resource.address])
}
