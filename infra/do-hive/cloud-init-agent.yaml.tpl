#cloud-config
# Track E1 -- IronClaw agent droplet bootstrap. Templated by main.tf.
# Each agent registers itself with the shared ai-memory substrate at
# ${memory_private_ip}:9077 using its per-droplet `agent_id`.
#
# IronClaw 1.1.0 "Reborn" is CONFIG-DRIVEN. The obsolete v0.28.1 flags
# (--provider / --base-url / --model) do NOT exist in 1.1.0 -- the binary
# rejects them at argument parsing, so the previous ExecStart could never
# have started. The Reborn runtime instead reads a "reborn home"
# (config.toml selection layer + providers.json catalog + webui-token) and
# is driven by subcommands: onboard / config / models / run / serve.
#
# This bootstrap is the recipe validated against the real 1.1.0 binary in
# the enterprise-cert campaign's Track B rerun (2026-08-09) -- see
# docs/v1.0.0/test-campaign-2026-08-08-enterprise-cert/PLAN.md section 5.
package_update: true
packages:
  - curl
  - jq
write_files:
  # -------------------------------------------------------------------------
  # Reborn home, SELECTION layer (config.toml).
  #
  # /opt/ironclaw is the ironclaw user's home, so this path is also the
  # binary's own default reborn home (HOME/.ironclaw/reborn): an operator
  # running `ironclaw ...` by hand on the droplet resolves the same home
  # whether or not IRONCLAW_REBORN_HOME is exported.
  #
  # write_files runs before the ironclaw user exists, so this lands
  # root-owned; the `chown -R ironclaw:ironclaw /opt/ironclaw` in runcmd
  # re-homes it.
  #
  # Secrets are referenced by ENV NAME only (api_key_env). Pasting a key
  # value here is rejected by the runtime at parse time -- do not do it.
  - path: /opt/ironclaw/.ironclaw/reborn/config.toml
    permissions: '0600'
    content: |
      api_version = "ironclaw.runtime/v1"

      [boot]
      profile = "local-dev"

      [identity]
      default_owner = "ai:hive-e1-agent-${agent_index}"
      default_agent = "ai:hive-e1-agent-${agent_index}"

      [runner]
      heartbeat_interval_secs = 5
      poll_interval_ms        = 200

      [skills]
      regex_activation_enabled = true

      [webui]
      # Loopback only. The hive firewall opens 9077 east-west plus ssh from
      # the operator CIDR; reach the WebUI over an ssh tunnel. Never bind
      # 0.0.0.0 here.
      listen_host = "127.0.0.1"
      listen_port = 3000

      [llm]

      [llm.default]
      # Grok 4.5 over the direct x.ai endpoint. The 1.1.0 provider catalog
      # has no built-in "xai" entry, so the direct endpoint is reached via
      # the built-in `openai_compatible` provider plus an explicit base_url.
      # No providers.json overlay is needed for this leg.
      provider_id = "openai_compatible"
      model       = "grok-4.5"
      base_url    = "https://api.x.ai/v1"
      api_key_env = "XAI_API_KEY"

      # Documented alternative -- the OpenRouter gateway leg that the cert
      # campaign's Track B ran locally. Replace the four fields above with
      # these and inject OPENROUTER_API_KEY instead of XAI_API_KEY:
      #   provider_id = "openrouter"
      #   model       = "x-ai/grok-4.5"
      #   api_key_env = "OPENROUTER_API_KEY"
  # -------------------------------------------------------------------------
  # Operator secret channel. Root-owned 0600: systemd reads EnvironmentFile
  # as root before dropping to User=ironclaw, so the agent process itself
  # never needs read access to the key material.
  - path: /etc/ironclaw/agent.env
    owner: 'root:root'
    permissions: '0600'
    content: |
      # Operator-injected secrets for ironclaw-agent.service.
      # Append the real key here at start time (NOT during the cloud-init
      # pass), then `systemctl start ironclaw-agent`:
      #   XAI_API_KEY=<key>
      # For the OpenRouter alternative documented in the reborn config:
      #   OPENROUTER_API_KEY=<key>
  - path: /etc/systemd/system/ironclaw-agent.service
    permissions: '0644'
    content: |
      [Unit]
      Description=IronClaw v1.1.0 agent #${agent_index} (Track E1 hive)
      After=network-online.target
      Wants=network-online.target

      [Service]
      Type=simple
      User=ironclaw
      Group=ironclaw
      # IronClaw 1.1.0 refuses to build its runtime when the working
      # directory is an ancestor of the reborn home's skill root ("workspace
      # root must not overlap default skill root"). systemd's default
      # WorkingDirectory (/) trips that on every boot, so drive the service
      # from a sibling workspace directory.
      WorkingDirectory=/opt/ironclaw/agent-ws
      Environment=AI_MEMORY_AGENT_ID=hive-e1-agent-${agent_index}
      Environment=AI_MEMORY_HTTP=http://${memory_private_ip}:9077
      Environment=IRONCLAW_REBORN_HOME=/opt/ironclaw/.ironclaw/reborn
      Environment=XAI_API_KEY=__OPERATOR_INJECTED_AT_BOOT__
      # systemd applies EnvironmentFile= over Environment=, so the operator's
      # root-owned 0600 file replaces the placeholder above without editing
      # (or leaking a live key into) this unit. `-` tolerates its absence.
      EnvironmentFile=-/etc/ironclaw/agent.env
      ExecStart=/opt/ironclaw/bin/ironclaw serve --host 127.0.0.1 --port 3000
      Restart=on-failure
      RestartSec=5

      [Install]
      WantedBy=multi-user.target
runcmd:
  - useradd -m -d /opt/ironclaw -s /bin/bash ironclaw
  - mkdir -p /opt/ironclaw/bin /opt/ironclaw/agent-ws /opt/ironclaw/.ironclaw/reborn
  - curl -fsSL "${ironclaw_image_url}" -o /tmp/ironclaw.tar.gz
  # The 1.1.0 release tarball wraps everything in a top-level
  # ironclaw-x86_64-unknown-linux-gnu/ directory; strip it so the binary
  # lands exactly at the ExecStart path.
  - tar -xzf /tmp/ironclaw.tar.gz --strip-components=1 -C /opt/ironclaw/bin
  - chmod 0755 /opt/ironclaw/bin/ironclaw
  - chown -R ironclaw:ironclaw /opt/ironclaw
  # Provision the rest of the reborn home as the ironclaw user: the
  # providers.json catalog, the WebChat bearer token that `serve` requires,
  # and the onboarding marker. A non-interactive `onboard` WITHOUT --force
  # PRESERVES an existing config.toml, so the selection layer written above
  # survives verbatim. --no-service keeps IronClaw from installing its own
  # competing systemd unit.
  - ["sudo", "-u", "ironclaw", "-H", "sh", "-c", "cd /opt/ironclaw/agent-ws && IRONCLAW_REBORN_HOME=/opt/ironclaw/.ironclaw/reborn /opt/ironclaw/bin/ironclaw onboard --no-service </dev/null"]
  - systemctl daemon-reload
  # Service is NOT enabled by default -- the operator appends the real key to
  # /etc/ironclaw/agent.env and runs `systemctl start ironclaw-agent` via the
  # post-spawn playbook, so no live key is written to disk during the
  # cloud-init pass.
  # A one-shot agentic turn (the shape Track B drove) uses the same home:
  #   sudo -u ironclaw -H sh -c 'cd /opt/ironclaw/agent-ws &&
  #     IRONCLAW_REBORN_HOME=/opt/ironclaw/.ironclaw/reborn
  #     /opt/ironclaw/bin/ironclaw run -m "<prompt>"'
