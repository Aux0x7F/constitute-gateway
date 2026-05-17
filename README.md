# constitute-gateway

`constitute-gateway` is the native swarm edge for a Constitution deployment.

It handles discovery/bootstrap, gateway presence, hosted-service inventory,
browser/service/CLI edge sessions, service admission, swarm-frame routing, and
release packaging for the gateway runtime. Nostr remains a bootstrap/fallback
carrier; normal service traffic routes as `SwarmFrame` records through the
swarm edge hub.

Gateway owns edge admission, route observations, and attached-session directory
truth. It routes and attests generic frames without owning NVR media semantics,
Logging query semantics, Storage object semantics, or identity authority.
