# Protocol Notes

## Discovery Plane

### Device Discovery Record
- Nostr `kind`: `30078`
- Tags:
  - `['t', 'swarm_discovery']`
  - `['type', 'device']`
- Content fields:
  - `devicePk`
  - `identityId`
  - `deviceLabel`
  - `updatedAt`
  - `expiresAt`
  - `role`
  - `relays`

### Zone Presence
- Nostr `kind`: `1`
- Tags:
  - `['t', 'constitute']`
  - `['z', '<zone_key>']`
- Content fields:
  - `type = zone_presence`
  - `zone`
  - `devicePk`
  - `swarm`
  - `role`
  - `relays`
  - `metrics`
  - `ts`
  - `ttl`

## App Channel Record Query
Incoming event:
- `type = swarm_record_request`
- Optional:
  - `requestId`
  - `timeoutMs`
  - `zone`
  - `identityId`
  - `devicePk`
  - `want: [identity, device]`

Incoming DHT query event:
- `type = swarm_dht_get`
- Required:
  - `scope` or `dhtScope`
  - `key` or `dhtKey`
- Optional:
  - `zone`
  - `requestId`
  - `timeoutMs`

Incoming DHT write event:
- `type = swarm_dht_put`
- Required:
  - `scope` or `dhtScope`
  - `key` or `dhtKey`
  - `value`
- Optional:
  - `zone`
  - `updatedAt`
  - `expiresAt`
  - `requestId`

Outgoing events:
- `swarm_identity_record`
- `swarm_device_record`
- `swarm_dht_record`
- `swarm_record_response` with `status`:
  - `pending`
  - `complete`
  - `timeout`

## UDP Gateway Transport
- Zone-scoped record gossip
- Targeted record request by `identityId`, `devicePk`, or (`dhtScope`, `dhtKey`)
- Fanout bounded by `udp_request_fanout`
- Forwarding bounded by `udp_request_max_hops`
- Message version is validated (`UDP_PROTOCOL_VERSION`)

## Compatibility Rule
Any protocol change in this repo must remain convergent with the web repo protocol contracts.

