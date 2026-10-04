#cloud-config
# Track E2 — IronClaw agent bootstrap. Each agent talks MCP stdio with
# IronClaw, which calls the vLLM endpoint over openai-compatible HTTP
# (so the agent code is unchanged from the Track E1 DO variant; only
# the inference base URL is swapped from xAI to local vLLM).
package_update: true
packages:
  - curl
  - jq
bootcmd:
  # #4628: root-only directory for the memory-node credentials (the API key and
  # the node certificate to trust), created before anything else can write.
  - [bash, -c, "[ -d /etc/ironclaw ] || (umask 077 && mkdir /etc/ironclaw)"]
write_files:
  # #4628: the memory daemon refuses every plaintext bind (tls_bind_guard,
  # src/daemon_runtime.rs), so the agent talks https and trusts the memory
  # node's certificate. Neither the API key nor the certificate is in user-data
  # (the instance metadata service serves user-data to any local process): the
  # operator's post-spawn SSH step installs them root-only, from the memory node:
  #   ssh <memory> sudo cat /etc/ai-memory/tls/node.crt  -> /etc/ironclaw/memory-ca.crt (root:ironclaw 0640; public cert)
  #   printf 'AI_MEMORY_API_KEY=%s\n' "$(ssh <memory> sudo cat /etc/ai-memory/api-key)" \
  #     > /etc/ironclaw/memory.env   (umask 077, root:root 0600)
  # The unit starts only when both exist, and systemd reads EnvironmentFile as
  # root, so the key is never on an argv or in the unit file.
  - path: /etc/systemd/system/ironclaw-agent.service
    permissions: '0644'
    content: |
      [Unit]
      Description=IronClaw v1.1.0 agent #${agent_index} (Track E2 burst)
      After=network-online.target
      Wants=network-online.target
      ConditionPathExists=/etc/ironclaw/memory.env
      ConditionPathExists=/etc/ironclaw/memory-ca.crt

      [Service]
      Type=simple
      User=ironclaw
      Group=ironclaw
      Environment=AI_MEMORY_AGENT_ID=burst-e2-agent-${agent_index}
      EnvironmentFile=/etc/ironclaw/memory.env
      Environment=SSL_CERT_FILE=/etc/ironclaw/memory-ca.crt
      Environment=AI_MEMORY_HTTP=https://${memory_private_ip}:9077
      ExecStart=/opt/ironclaw/bin/ironclaw --provider openai-compatible --base-url http://${vllm_private_ip}:8000/v1 --model auto
      Restart=on-failure

      [Install]
      WantedBy=multi-user.target
runcmd:
  - useradd -m -d /opt/ironclaw -s /bin/bash ironclaw
  - mkdir -p /opt/ironclaw/bin
  - chown -R ironclaw:ironclaw /opt/ironclaw
  - chown root:ironclaw /etc/ironclaw
  - chmod 0750 /etc/ironclaw
  - curl -fsSL "${ironclaw_image_url}" -o /tmp/ironclaw.tar.gz
  - tar -xzf /tmp/ironclaw.tar.gz -C /opt/ironclaw/bin
  - chmod 0755 /opt/ironclaw/bin/ironclaw
  - systemctl daemon-reload
  # NOT enabled by default — operator starts via post-spawn playbook
  # after confirming vLLM is healthy (vLLM cold-start takes ~3-5min
  # while it downloads/warms the model).
