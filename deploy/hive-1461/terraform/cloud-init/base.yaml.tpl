#cloud-config
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Base layer only. Pins the function-encoded hostname and lays down common
# tooling + the role marker. The application layer (ai-memory binary, PG+AGE
# container, config.toml, TLS, federation units) is installed by the
# push-based, idempotent provision/ scripts so it can be re-run and audited
# live — cloud-init runs once and is hard to debug after the fact.
hostname: ${hostname}
fqdn: ${hostname}.${campaign}.local
preserve_hostname: false

package_update: true
package_upgrade: false
packages:
  - curl
  - ca-certificates
  - jq
  - gnupg
  - openssl

write_files:
  - path: /etc/ai-memory/node-role
    permissions: '0644'
    content: "${role}\n"
  - path: /etc/ai-memory/node-hostname
    permissions: '0644'
    content: "${hostname}\n"

runcmd:
  - [ mkdir, -p, /etc/ai-memory/tls ]
  - [ bash, -lc, "date -u +%Y-%m-%dT%H:%M:%SZ > /etc/ai-memory/.cloud-init-done" ]
