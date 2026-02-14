# Protocol Notes

## Compatibility Rule
Protocol changes in this repo must remain convergent with the web repo contracts (`constitute`).

## Discovery Plane

### Device Discovery Record
- Nostr `kind`: `30078`
- Required tags:
  - `['t', 'swarm_discovery']`
  - `['type', 'device']`
- Content fields:
  - `devicePk`
  - `identityId` (optional)
  - `deviceLabel` (optional)
  - `updatedAt`
  - `expiresAt`
  - `role`
  - `relays`
  - `serviceVersion`

### Zone Presence
- Nostr `kind`: `1`
- Required tags:
  - `['t', 'constitute']`
  - `['z', '<zone_key>']`
- Content fields:
  - `type = zone_presence`
  - `zone`
  - `devicePk`
  - `swarm`
  - `role`
  - `relays`
  - `serviceVersion`
  - `metrics`
  - `ts`
  - `ttl`

## App Channel Queries
Incoming event type:
- `swarm_record_request`

Optional fields:
- `requestId`
- `timeoutMs`
- `zone`
- `identityId`
- `devicePk`
- `want: [identity, device]`

## DHT Events
### Read
Incoming type:
- `swarm_dht_get`

Required fields:
- `scope` or `dhtScope`
- `key` or `dhtKey`

Optional fields:
- `zone`
- `requestId`
- `timeoutMs`

### Write
Incoming type:
- `swarm_dht_put`

Required fields:
- `scope` or `dhtScope`
- `key` or `dhtKey`
- `value`

Optional fields:
- `zone`
- `updatedAt`
- `expiresAt`
- `requestId`

## Outgoing Gateway Events
- `swarm_identity_record`
- `swarm_device_record`
- `swarm_dht_record`
- `swarm_record_response` with status:
  - `pending`
  - `complete`
  - `timeout`

## UDP Transport Expectations
- Zone-scoped gossip/propagation
- Targeted request by `identityId`, `devicePk`, or (`dhtScope`, `dhtKey`)
- Fanout bounded by `udp_request_fanout`
- Forwarding bounded by `udp_request_max_hops`
- Message version validated via `UDP_PROTOCOL_VERSION`
