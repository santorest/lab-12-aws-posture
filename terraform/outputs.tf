# What the planted switches actually produced, read from the resources (used by terraform test).
output "posture" {
  description = "Per planted part: the setting the resources carry"
  value = merge(
    module.storage.posture,
    module.identity.posture,
    module.network.posture,
    module.keys.posture,
    { tagged = toset(concat(module.network.names, module.keys.names)) },
  )
}
