#cloud-config
# Track E1 -- ai-memory + PostgreSQL 18 + pgvector + Apache AGE bootstrap on the
# DO substrate droplet. Templated by `infra/do-hive/main.tf`. Operator-triggered.
#
# #1842 fix (v0.8.1): the prior template installed postgresql-16 but never
# installed pgvector and never built Apache AGE (AGE is source-only -- not an
# apt package -- and `CREATE EXTENSION age` failed). It also used the invalid
# `--bind` flag. This template installs pgvector, builds AGE from source
# against pg16, preloads AGE, creates the db + both extensions, and runs serve
# with the correct `--host/--port` flags and the postgres store URL read from
# AI_MEMORY_STORE_URL_FILE (#4577; never on argv).
#
# #2293 fix (v1.0.0): the noble apt package `postgresql-16-pgvector` pins
# pgvector 0.6.0, below the daemon's tested 0.7.x-0.8.x range (the v0.9.0 GA
# reference round certified 0.8.4). pgvector is now built from source, same
# as AGE, pinned to the certified v0.8.4 tag.
#
# All provisioning is logged to /var/log/ai-memory-provision.log for SSH triage.
package_update: true
package_upgrade: false
bootcmd:
  # #4619: cloud-init write_files creates the file under the process umask and
  # chmods it AFTER writing (cloudinit/util.py write_file: open, write, flush,
  # chmod). bootcmd runs before write_files, so create /etc/ai-memory root-only
  # (0700, umask 077) first: no other UID can traverse it while the store-url
  # file briefly has the umask mode. Guarded so later boots never reset the
  # 0750 root:aimemory mode the fed-bootstrap script sets (install -d) once the
  # service user exists.
  - [bash, -c, "[ -d /etc/ai-memory ] || (umask 077 && mkdir /etc/ai-memory)"]
  # PG 18 is supplied by PGDG on Ubuntu Noble. Install the signed repository
  # before cloud-init's packages module runs; never fall back to Ubuntu's PG16.
  - [bash, -c, "set -e; install -d -m 0755 /usr/share/postgresql-common/pgdg; rm -f /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc.new; curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc.new; echo '0144068502a1eddd2a0280ede10ef607d1ec592ce819940991203941564e8e76  /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc.new' | sha256sum -c -; mv -f /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc.new /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc; echo 'deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt noble-pgdg main' > /etc/apt/sources.list.d/pgdg.list; apt-get update"]
packages:
  - postgresql-18=18.6-1.pgdg24.04+2
  - postgresql-server-dev-18=18.6-1.pgdg24.04+2
  - build-essential
  - flex
  - bison
  - libreadline-dev
  - zlib1g-dev
  - git
  - curl
  - jq
  - openssl
write_files:
  # #4577: the Postgres DSN (it carries the db password) reaches the daemon
  # through AI_MEMORY_STORE_URL_FILE, never on the serve argv where every local
  # UID can read it from /proc/<pid>/cmdline and `ps auxww`. cloud-init writes
  # the file first and applies permissions/owner afterwards (#4619), so the mode
  # alone leaves a short window; the 0700 /etc/ai-memory created in bootcmd above
  # is what keeps other UIDs out during it. provision.sh hands the file to the
  # aimemory service user once that user exists (serve refuses a file with any
  # group/world mode bit, src/store_url.rs). A trailing newline is trimmed.
  # #4654: the daemon connects straight to Postgres on the default port 5432
  # (no pooler) with sslmode=verify-full against the CA that provision.sh mints
  # (#4635); the host is localhost, which the certificate's SAN covers (with 127.0.0.1 and ::1).
  # CHANGEME is a placeholder, not a credential: no Terraform secret is
  # interpolated into user-data, which droplet metadata serves to any local
  # process. provision.sh replaces it with a random role password minted on the
  # node, and reads the role password from this one file (as in the AWS template).
  - path: /etc/ai-memory/store-url
    permissions: '0600'
    owner: root:root
    content: |
      postgres://aimemory:CHANGEME@localhost/aimemory?sslmode=verify-full&sslrootcert=/etc/ai-memory/tls/pg-ca.crt
  - path: /etc/systemd/system/ai-memory.service
    permissions: '0644'
    content: |
      [Unit]
      Description=ai-memory daemon (autonomous tier, Track E1 postgres+AGE substrate)
      After=postgresql.service network-online.target
      Wants=postgresql.service network-online.target

      [Service]
      Type=simple
      User=aimemory
      Group=aimemory
      # #2853: even in postgres-store mode the daemon opens a local sqlite
      # ai-memory.db (deferred-audit journal + federation nonce cache). With no
      # WorkingDirectory systemd's default CWD is /, which User=aimemory cannot
      # write, so the open fails SQLITE_CANTOPEN (exit 75). Give it the aimemory
      # home (writable) as CWD so the relative ai-memory.db lands there. The
      # home is /var/lib/ai-memory, NOT /opt/ai-memory, and the binary lives in
      # the root-owned /usr/local/lib/ai-memory/bin, outside every directory the
      # service user can write, so nothing it can write is ever executed by
      # root (#4674, #4712).
      WorkingDirectory=/var/lib/ai-memory
      Environment=AI_MEMORY_STORE_URL_FILE=/etc/ai-memory/store-url
      Environment=AI_MEMORY_PERMISSIONS_MODE=enforce
      Environment=AI_MEMORY_AUTONOMOUS_HOOKS=0
      Environment=RUST_LOG=ai_memory=info,store::postgres=info
      # Public binding is permitted only with TLS + fingerprint-pinned mTLS.
      # Request authn additionally uses the per-node API key; header trust stays off.
      EnvironmentFile=/etc/ai-memory/fed/runtime.env
      ExecStart=/usr/local/lib/ai-memory/bin/ai-memory serve --host 0.0.0.0 --port 9077 --tls-cert /etc/ai-memory/fed/node.crt --tls-key /etc/ai-memory/fed/node.key --mtls-allowlist /etc/ai-memory/fed/peers.allowlist
      Restart=on-failure
      RestartSec=5

      [Install]
      WantedBy=multi-user.target
  # =====================================================================
  # Track D -- REAL federated multi-node ai-memory (v1.0.0 enterprise-cert
  # campaign, docs/v1.0.0/test-campaign-2026-08-08-enterprise-cert/PLAN.md
  # Track D + section 3). Rendered ONLY when main.tf's memory_count >= 2;
  # at memory_count == 1 every byte below is absent and this template is
  # byte-identical to the pre-Track-D single-substrate bootstrap.
  #
  # Topology mirrors the certified LOCAL 2-node config
  # (infra/do-hive/crypto/test-federation-mtls.sh +
  # infra/do-hive/crypto/test-fed-write-sig-attestation.sh), re-hosted onto
  # droplets: each node presents its own leaf cert as BOTH its server cert
  # and its outbound quorum client cert, pins every other node's cert
  # fingerprint in peers.allowlist, dials peers as
  # https://<peer-private-ip>:9077, and runs --quorum-writes W.
  #
  # AI_MEMORY_FED_* knobs are DELIBERATELY LEFT UNSET. At v1.0.0 the
  # secure posture IS the compiled default -- write-sig (#94), signal-sig
  # (#96), transition-sig (#87), checkpoint-sig (#125), nonce (#30),
  # peer-enrollment (#43) and policy-current (#132) are all fail-closed
  # with the env absent. Setting them to 1 would be redundant AND would
  # make the cert evidence weaker: it would prove "the flag works", not
  # "the shipped default is secure". The same reasoning the local leg
  # applies at test-fed-write-sig-attestation.sh ("env left unset on
  # purpose to prove the DEFAULT-ON posture").
  #
  # ---------------------------------------------------------------------
  # SECRETS-IN-TERRAFORM-STATE TRADEOFF (chosen approach + rejected ones)
  # ---------------------------------------------------------------------
  # CHOSEN: private crypto material NEVER touches terraform. Terraform
  # passes only plan-time, non-secret facts (node_index, node_count,
  # fed_identity, quorum_writes). The mTLS bundle is minted on the
  # OPERATOR host by infra/do-hive/federate.sh (which reuses
  # crypto/gen-certs.sh) and scp'd to /etc/ai-memory/fed/ over SSH; the
  # node's Ed25519 federation signing key is generated ON the droplet and
  # its PRIVATE half never leaves. Only public material (peer .pub files,
  # the author .pub) is ever moved between nodes. Consequence: zero
  # secrets in terraform.tfstate -- which matters concretely here because
  # spawn.sh COPIES terraform.tfstate into .local-runs/do-hive-runs/<ts>/
  # on every apply, so anything in state is also in a plaintext audit
  # dump on the orchestrator disk.
  #
  # REJECTED (a) pre-generate locally, inject via templatefile vars: a
  # droplet's user_data is stored verbatim in terraform state AND is
  # readable from the droplet's own metadata service, so every peer
  # private key + CA key would land in both. Directly contradicts the
  # brief's own "keep secrets out of terraform state where feasible".
  #
  # REJECTED (b) generate on droplet 1, distribute to the others: there
  # is no authenticated channel between two fresh droplets before the
  # mTLS material exists (that is the material). Any bootstrap over the
  # VPC would be trust-on-first-use over plaintext -- which would make
  # the cert round's Leg-2 "unauthorised + plaintext peers are refused"
  # assertion rest on a plaintext, unauthenticated key exchange. A
  # federation-encryption certification cannot be built on that.
  #
  # HONEST COST of the chosen approach: `terraform apply` alone does not
  # yield a running mesh. It yields two nodes parked in a fail-closed
  # wait, and one operator command (federate.sh) completes them. That is
  # a real extra step, and it is the step the existing DO staging notes
  # already prescribe ("scp/rsync the whole crypto/ dir onto each
  # droplet" -- infra/do-hive/crypto/KNOWN-DO-STAGING.md section 1).
  #
  # RESIDUAL RISK this approach ACCEPTS (disclosed, not closed): the SSH
  # push is trust-on-first-use. federate.sh defaults to
  # StrictHostKeyChecking=accept-new on the very channel that carries the
  # CA private key and each node's leaf node.key, so a first-contact MITM
  # on the operator->droplet path would obtain them. Accepted because the
  # hive is ephemeral, money-gated, and operator->own-droplet; closable by
  # pre-seeding known_hosts or exporting SSH_OPTS with
  # StrictHostKeyChecking=yes and a pinned host key. Named here because
  # disclosing only the exposure this design CLOSES while omitting the one
  # it DEPENDS ON would be a one-sided ledger.
  # =====================================================================
  - path: /etc/systemd/system/ai-memory.service.d/10-federation.conf
    permissions: '0644'
    content: |
      # Track D federated overlay for node ${node_index} of ${node_count}.
      #
      # A systemd DROP-IN, deliberately NOT a fork of ai-memory.service: the
      # base unit stays byte-identical at every memory_count, so the
      # single-substrate hive and the federated mesh can never drift apart
      # in the postgres/AGE/pgvector half. Only the serve invocation and the
      # federation environment are overridden. Environment= is a list
      # directive, so the base unit's PERMISSIONS_MODE / AUTONOMOUS_HOOKS /
      # RUST_LOG settings are preserved, not replaced.
      #
      # WHY THIS UNIT REFUSES TO START BEFORE federate.sh HAS RUN:
      # EnvironmentFile has NO leading '-', so systemd refuses to start the
      # service until /etc/ai-memory/fed/peers.conf exists. That is
      # deliberate fail-closed wiring. A "federated" node that booted with
      # an empty peer list would accept writes, satisfy W=1 locally, and
      # report healthy while replicating to nobody -- a substrate that
      # reports success while doing nothing. Refusing to start is the
      # honest degrade.
      [Service]
      Environment=AI_MEMORY_FED_IDENTITY=${fed_identity}
      Environment=AI_MEMORY_KEY_DIR=/etc/ai-memory/keys
      Environment=XDG_CONFIG_HOME=/etc/ai-memory/xdg
      Environment=HOME=/var/lib/ai-memory
      EnvironmentFile=/etc/ai-memory/fed/peers.conf
      ExecStart=
      ExecStart=/usr/local/lib/ai-memory/bin/ai-memory serve --host 0.0.0.0 --port 9077 --tls-cert /etc/ai-memory/fed/node.crt --tls-key /etc/ai-memory/fed/node.key --mtls-allowlist /etc/ai-memory/fed/peers.allowlist%{ if federation_enabled } --quorum-writes ${quorum_writes} --quorum-peers $${AI_MEMORY_QUORUM_PEERS} --quorum-client-cert /etc/ai-memory/fed/node.crt --quorum-client-key /etc/ai-memory/fed/node.key --quorum-ca-cert /etc/ai-memory/fed/ca.crt --quorum-timeout-ms 8000%{ endif }
  - path: /etc/systemd/system/ai-memory-fed-bootstrap.service
    permissions: '0644'
    content: |
      [Unit]
      Description=ai-memory Track D federation bootstrap (identity mint, peer enrollment, mesh verify)
      After=network-online.target postgresql.service
      Wants=network-online.target

      [Service]
      Type=oneshot
      RemainAfterExit=yes
      # The script owns its own bounded retry loops (wait for the operator
      # bundle, then wait for each peer to answer over the mutually
      # authenticated channel), so systemd must neither time it out nor
      # race it with a Restart= of its own. Re-run after fixing a problem
      # with: systemctl restart ai-memory-fed-bootstrap
      TimeoutStartSec=0
      ExecStart=/usr/local/sbin/ai-memory-fed-bootstrap.sh

      [Install]
      WantedBy=multi-user.target
  # #4674: the two scripts root runs (this unit has no User=; provision.sh is
  # run by runcmd) live in /usr/local/sbin, root:root 0755 under root-owned,
  # non-group/other-writable parents. They must never sit in a directory the
  # aimemory service user owns: it could rewrite them and gain root at the next
  # boot or bootstrap restart.
  - path: /usr/local/sbin/ai-memory-fed-bootstrap.sh
    permissions: '0755'
    owner: root:root
    content: |
      #!/usr/bin/env bash
      # =================================================================
      # Track D federation bootstrap -- node ${node_index} of ${node_count}.
      #
      # Cloud-init cannot know a peer's private IP (DO allocates it at
      # create time and a terraform resource cannot reference itself), so
      # this one-shot completes the wiring AFTER both droplets exist. It
      # is a resumable state machine, idempotent at every stage:
      #
      #   A  mint this node's Ed25519 federation identity; publish only
      #      the .pub for cross-enrollment (private half never leaves)
      #   B  mint a local api_key + write config.toml (the daemon REFUSES
      #      a non-loopback bind without one -- see KNOWN-DO-STAGING.md
      #      section 3; that refusal is the product working as designed)
      #   C  wait for the operator-delivered mTLS bundle + peer list
      #   D  local #2477 pre-check: refuse a non-https peer URL here too
      #   E  install peer public keys into the key dir (the transport
      #      lane's enrollment -- exactly the cross-copy that
      #      infra/lan-parity-test/provision-peer-keys.sh does for the
      #      docker mesh, #1803, and only ever public material)
      #   F  start the daemon; wait for local /health over mTLS
      #   G  wait until EVERY peer answers /health over the mutually
      #      authenticated channel (the retry loop the mesh needs)
      #   H  register + bind the cert-round author pubkey so the CONTENT
      #      write-sig lane can reach attest_level=agent_attested at this
      #      receiver (test-fed-write-sig-attestation.sh binds the author
      #      on BOTH dbs; the CLI `agents bind-key` speaks sqlite only, so
      #      on this postgres substrate it must go over the admin-gated
      #      PUT /api/v1/agents/{id}/pubkey route, #1539)
      #
      # Every failure exits non-zero and leaves a diagnosis in
      # /var/log/ai-memory-federation.log + journalctl. Nothing here ever
      # deletes or rewrites durable memory text.
      # =================================================================
      set -uo pipefail
      exec > >(tee -a /var/log/ai-memory-federation.log) 2>&1
      echo "=== ai-memory federation bootstrap node ${node_index}/${node_count} $(date -u) ==="

      FED_DIR=/etc/ai-memory/fed
      KEY_DIR=/etc/ai-memory/keys
      XDG_DIR=/etc/ai-memory/xdg
      BIN=/usr/local/lib/ai-memory/bin/ai-memory
      FED_ID='${fed_identity}'
      ADMIN_ID=ai:hive-admin
      LOCAL=https://127.0.0.1:9077
      MATERIAL_TRIES=720
      MATERIAL_SLEEP=10
      PEER_TRIES=240
      PEER_SLEEP=5

      fail() { echo "[fed-bootstrap] FAIL: $*" >&2; exit 1; }

      # CUSTODY SPLIT. Everything the daemon only needs to READ stays
      # root-owned, group aimemory, non-writable by the service user: a
      # compromised daemon can use its trust anchors but cannot rewrite them.
      # Same separable-custody principle the substrate already applies to
      # AI_MEMORY_WITNESS_KEY_DIR ("a mount the daemon can READ but a
      # compromised daemon process cannot overwrite"). Only $KEY_DIR is
      # daemon-writable, because `identity generate` runs as aimemory and the
      # daemon owns its own signing keys by design.
      install -d -m 0750 -o root -g aimemory \
        /etc/ai-memory "$FED_DIR" "$FED_DIR/peers" "$XDG_DIR" "$XDG_DIR/ai-memory"
      install -d -m 0700 -o aimemory -g aimemory "$KEY_DIR"

      # --- A. mint this node's federation identity ---------------------
      [ -x "$BIN" ] || fail "no ai-memory binary at $BIN; scp a --features sal-postgres build over it, then: systemctl restart ai-memory-fed-bootstrap"
      if [ ! -f "$KEY_DIR/$FED_ID.priv" ]; then
        sudo -u aimemory env AI_MEMORY_NO_CONFIG=1 AI_MEMORY_DB=/var/lib/ai-memory/identity.db \
          /usr/local/lib/ai-memory/bin/ai-memory identity generate --agent-id "$FED_ID" --key-dir "$KEY_DIR" \
          || fail "identity generate failed for $FED_ID"
      fi
      runuser -u aimemory -- cat "$KEY_DIR/$FED_ID.pub" > "$FED_DIR/$FED_ID.pub.new" \
        || fail "could not read $KEY_DIR/$FED_ID.pub as the service user"
      chmod 0644 "$FED_DIR/$FED_ID.pub.new"
      mv -f "$FED_DIR/$FED_ID.pub.new" "$FED_DIR/$FED_ID.pub"
      echo "[fed-bootstrap] published $FED_DIR/$FED_ID.pub (public half only) for cross-enrollment"

      # --- B. local api_key + admin allowlist --------------------------
      # Minted HERE, not passed through terraform, so the shared secret
      # never enters terraform.tfstate or the spawn.sh audit dump. The
      # operator reads it with: ssh root@<node> cat /etc/ai-memory/api-key
      if [ ! -s /etc/ai-memory/api-key ]; then
        ( umask 077; openssl rand -hex 32 > /etc/ai-memory/api-key ) \
          || fail "could not mint the local api key"
      fi
      chown root:aimemory /etc/ai-memory/api-key
      chmod 0640 /etc/ai-memory/api-key
      API_KEY="$(cat /etc/ai-memory/api-key)"
      # The umask subshell matters: config.toml carries the api_key, so it must
      # never exist even momentarily at the inherited 0644.
      # #2852: the daemon's config resolver (AppConfig::config_path,
      # src/config.rs) reads $HOME/.config/ai-memory/config.toml and IGNORES
      # XDG_CONFIG_HOME. In the serve drop-in $HOME=/var/lib/ai-memory, so the daemon
      # loads /var/lib/ai-memory/.config/ai-memory/config.toml. Writing the api_key
      # config to $XDG_DIR left it UNREAD and serve fail-closed on the 0.0.0.0
      # bind ("api_key is unset", exit 75). Write to the path the daemon loads.
      DAEMON_CFG_DIR=/var/lib/ai-memory/.config/ai-memory
      ( umask 077
        runuser -u aimemory -- mkdir -p "$DAEMON_CFG_DIR" \
          && printf 'schema_version = 2\napi_key = "%s"\n\n[admin]\nagent_ids = ["%s"]\n' "$API_KEY" "$ADMIN_ID" \
            | runuser -u aimemory -- tee "$DAEMON_CFG_DIR/config.toml.new" >/dev/null \
          && runuser -u aimemory -- mv -f "$DAEMON_CFG_DIR/config.toml.new" "$DAEMON_CFG_DIR/config.toml"
      ) || fail "could not write the daemon config"
      # Unit environment is explicit and auditable. Header trust is
      # intentionally absent/off: the mTLS-enrolled load generator must also
      # present this node's API key before its admin agent id is considered.
      printf 'AI_MEMORY_ADMIN_AGENT_IDS=ai:hive-loadgen-f2\n' > "$FED_DIR/runtime.env"
      chown root:aimemory "$FED_DIR/runtime.env"
      chmod 0640 "$FED_DIR/runtime.env"
      # NOTE: tier is left unset, so the daemon keeps its compiled default
      # (semantic). A Track-D-only run that does not need the embedder can
      # add `tier = "keyword"` to that file and restart -- the same
      # embedder-free posture KNOWN-DO-STAGING.md section 2 documents.

      # --- C. wait for the operator-delivered mTLS bundle --------------
      i=0
      while [ ! -f "$FED_DIR/ENROLLED" ]; do
        i=$((i + 1))
        if [ "$i" -gt "$MATERIAL_TRIES" ]; then
          fail "timed out after $((MATERIAL_TRIES * MATERIAL_SLEEP))s waiting for $FED_DIR/ENROLLED; run infra/do-hive/federate.sh on the orchestrator host, then: systemctl restart ai-memory-fed-bootstrap"
        fi
        if [ $((i % 30)) -eq 1 ]; then
          echo "[fed-bootstrap] waiting for $FED_DIR/ENROLLED (federate.sh) ... try $i/$MATERIAL_TRIES"
        fi
        sleep "$MATERIAL_SLEEP"
      done
      for f in ca.crt node.crt node.key peers.allowlist peers.conf author.id author.pub; do
        [ -s "$FED_DIR/$f" ] || fail "federation material incomplete: $FED_DIR/$f missing or empty"
      done

      # --- D. local #2477 pre-check on the delivered peer list ---------
      # The daemon refuses a plaintext non-loopback peer at boot (#2477).
      # Repeating the check here turns that into a named, logged refusal
      # instead of an opaque unit start failure.
      # PARSED, never sourced. systemd reads this file as a plain KEY=value
      # EnvironmentFile, so `.` would give it shell-execution semantics this
      # script does not need and systemd does not grant -- a needless
      # arbitrary-code surface on an over-the-wire-delivered file.
      PEERS="$(sed -n 's/^AI_MEMORY_QUORUM_PEERS=//p' "$FED_DIR/peers.conf" | tail -1 | tr -d '"\r')"
%{ if federation_enabled }
      [ -n "$PEERS" ] || fail "peers.conf carries no AI_MEMORY_QUORUM_PEERS; refusing to start a federated node with an empty peer list"
%{ endif }
      BAD_PEER=0
      OLD_IFS=$IFS
      IFS=,
      for u in $PEERS; do
        case "$u" in
          https://*) ;;
          *) echo "[fed-bootstrap] non-https peer URL in peers.conf: $u"; BAD_PEER=1 ;;
        esac
      done
      IFS=$OLD_IFS
      [ "$BAD_PEER" -eq 0 ] || fail "peers.conf contains a non-https peer URL; refused locally (the daemon refuses the same shape at boot, #2477)"

      # --- E. install peer public keys (transport-lane enrollment) -----
      PEER_PUBS=$(ls -1 "$FED_DIR"/peers/*.pub 2>/dev/null | wc -l)
%{ if federation_enabled }
      [ "$PEER_PUBS" -ge 1 ] || fail "no peer public keys under $FED_DIR/peers"
%{ endif }
      # $FED_DIR stays root-owned (custody split above); the daemon reads it as
      # group aimemory and cannot rewrite its own trust anchors.
      chown -R root:aimemory "$FED_DIR"
      chmod 0750 "$FED_DIR" "$FED_DIR/peers"
%{ if federation_enabled }
      chmod 0644 "$FED_DIR"/peers/*.pub
      # Copied as the service user: $KEY_DIR is the service user's directory, so
      # root never writes through a link planted there.
      runuser -u aimemory -- cp "$FED_DIR"/peers/*.pub "$KEY_DIR"/ || fail "could not install peer public keys"
%{ endif }
      chmod 0640 "$FED_DIR/node.key"
      chmod 0644 "$FED_DIR/ca.crt" "$FED_DIR/node.crt" "$FED_DIR/peers.allowlist" "$FED_DIR/peers.conf"
      echo "[fed-bootstrap] enrolled $PEER_PUBS peer public key(s) into $KEY_DIR"

      # --- F. start the daemon; wait for local health over mTLS --------
      systemctl daemon-reload
      systemctl enable ai-memory >/dev/null 2>&1 || true
      systemctl restart ai-memory || fail "ai-memory failed to start (journalctl -u ai-memory)"

      mtls_code() {
        curl -sS --max-time 10 \
          --cacert "$FED_DIR/ca.crt" --cert "$FED_DIR/node.crt" --key "$FED_DIR/node.key" \
          -o /dev/null -w '%%{http_code}' "$1" 2>/dev/null
      }

      i=0
      until [ "$(mtls_code "$LOCAL/api/v1/health")" = "200" ]; do
        i=$((i + 1))
        [ "$i" -gt 60 ] && fail "local daemon never answered /api/v1/health over mTLS (journalctl -u ai-memory)"
        sleep 5
      done
      echo "[fed-bootstrap] local daemon healthy over mTLS"

      # --- G. wait for every peer over the mutually authenticated channel
      IFS=,
      for u in $PEERS; do
        i=0
        until [ "$(mtls_code "$u/api/v1/health")" = "200" ]; do
          i=$((i + 1))
          if [ "$i" -gt "$PEER_TRIES" ]; then
            IFS=$OLD_IFS
            fail "peer $u never answered /api/v1/health over the mutually authenticated channel after $((PEER_TRIES * PEER_SLEEP))s"
          fi
          [ $((i % 12)) -eq 1 ] && echo "[fed-bootstrap] waiting for peer $u ... try $i/$PEER_TRIES"
          sleep "$PEER_SLEEP"
        done
        echo "[fed-bootstrap] peer $u reachable over mTLS"
      done
      IFS=$OLD_IFS

      # --- H. bind the cert-round author pubkey (content write-sig lane)
      AUTHOR_ID="$(cat "$FED_DIR/author.id")"
      AUTHOR_PUB="$(cat "$FED_DIR/author.pub")"
      admin_call() {
        printf 'header = "x-api-key: %s"\n' "$API_KEY" | curl -sS --max-time 15 --config - \
          --cacert "$FED_DIR/ca.crt" --cert "$FED_DIR/node.crt" --key "$FED_DIR/node.key" \
          -H "content-type: application/json" -H "x-agent-id: $ADMIN_ID" \
          -o /dev/null -w '%%{http_code}' "$@" 2>/dev/null
      }
      i=0
      while :; do
        RC=$(admin_call -X POST "$LOCAL/api/v1/agents" -d "{\"agent_id\":\"$AUTHOR_ID\",\"agent_type\":\"system\"}")
        case "$RC" in 200|201|409) break ;; esac
        i=$((i + 1))
        [ "$i" -gt 12 ] && fail "could not register author $AUTHOR_ID (last HTTP $RC)"
        sleep 5
      done
      i=0
      while :; do
        RC=$(admin_call -X PUT "$LOCAL/api/v1/agents/$AUTHOR_ID/pubkey" -d "{\"pubkey_b64\":\"$AUTHOR_PUB\"}")
        [ "$RC" = "200" ] && break
        i=$((i + 1))
        [ "$i" -gt 12 ] && fail "could not bind author pubkey for $AUTHOR_ID (last HTTP $RC)"
        sleep 5
      done
      echo "[fed-bootstrap] author $AUTHOR_ID pubkey bound on this node"

      : > "$FED_DIR/MESH-READY"
      echo "[fed-bootstrap] MESH READY node ${node_index}/${node_count} identity=$FED_ID peers=$PEERS author=$AUTHOR_ID"
  - path: /usr/local/sbin/ai-memory-provision.sh
    permissions: '0755'
    owner: root:root
    content: |
      #!/usr/bin/env bash
      set -euo pipefail
      # No `set -x` and a root-only log: the role password and the store URL
      # pass through this script (#4638).
      # Create the log root-only WITHOUT truncating it: a re-run must keep the
      # record of a failed first run (#4709).
      ( umask 077; : >> /var/log/ai-memory-provision.log ); chmod 0600 /var/log/ai-memory-provision.log
      exec >> /var/log/ai-memory-provision.log 2>&1
      echo "=== ai-memory postgres+AGE+pgvector provision $(date -u) ==="

      # --- user + dirs ---
      # #4674/#4712: the service user's home (data, ai-memory.db, .config) is
      # /var/lib/ai-memory. The binary lives in /usr/local/lib/ai-memory/bin,
      # root:root 0755 (nothing here is recursively chowned to aimemory), and
      # only the paths the daemon writes are handed to it.
      id aimemory >/dev/null 2>&1 || useradd -m -d /var/lib/ai-memory -s /bin/bash aimemory
      install -d -o root -g root -m 0755 /usr/local/lib/ai-memory /usr/local/lib/ai-memory/bin
      install -d -o aimemory -g aimemory -m 0750 /var/lib/ai-memory /var/log/ai-memory
      # #4577/#4619: the service user traverses /etc/ai-memory and owns the DSN
      # file (mode stays 0600).
      chown root:aimemory /etc/ai-memory
      chmod 0750 /etc/ai-memory
      # The role password is minted here, on the node, from the placeholder
      # (hex, so it needs no URL or SQL quoting); a re-run keeps the one the
      # file already carries.
      if grep -q CHANGEME /etc/ai-memory/store-url; then
        NEW_SECRET="$(openssl rand -hex 24)"
        # The script reaches sed on stdin: the secret is never on an argv.
        printf 's/CHANGEME/%s/\n' "$NEW_SECRET" | sed -i -f - /etc/ai-memory/store-url
        unset NEW_SECRET
      fi
      # Fail closed: the shipped placeholder must never reach a running node.
      if grep -q CHANGEME /etc/ai-memory/store-url; then
        echo "placeholder db password still in /etc/ai-memory/store-url"; exit 1
      fi
      chown aimemory:aimemory /etc/ai-memory/store-url
      chmod 0600 /etc/ai-memory/store-url

      # Fetch ONE full commit and refuse anything else (#4636): a branch or a
      # re-pointed tag cannot change the code built here and loaded into the
      # postgres server (shared_preload_libraries).
      fetch_pinned() { # <url> <dir> <full 40-hex commit>
        rm -rf "$2" && git init -q "$2" \
          && git -C "$2" remote add origin "$1" \
          && git -C "$2" fetch -q --depth 1 origin "$3" \
          && git -C "$2" checkout -q --detach FETCH_HEAD \
          && [ "$(git -C "$2" rev-parse HEAD)" = "$3" ] \
          || { echo "pin mismatch: $1 did not resolve to $3"; return 1; }
      }
      # pgvector v0.8.6 (git ls-remote https://github.com/pgvector/pgvector.git
      # refs/tags/v0.8.6).
      PGVECTOR_COMMIT=8ee86c96f0fd72390f890aa8a336fda6d3ab4c6c
      # Apache AGE 1.8.0 for PG18 = tag PG18/v1.8.0-rc0 (AGE tags every release
      # X.Y.Z-rc0; docs/v1.0.0/release-notes.md:322), the release the certified
      # pgdg 1.8.0~rc0 package ships (git ls-remote
      # https://github.com/apache/age.git refs/tags/PG18/v1.8.0-rc0).
      AGE_COMMIT=e43dc1a12b78fba4acef9835b2b10379b8d243b4

      # --- build + install certified pgvector 0.8.6 against PG18 ---
      # Build the exact certified v0.8.6 commit rather than accepting apt drift.
      if [ ! -f "$(/usr/bin/pg_config --pkglibdir)/vector.so" ]; then
        fetch_pinned https://github.com/pgvector/pgvector.git /opt/pgvector-src "$PGVECTOR_COMMIT"
        cd /opt/pgvector-src
        make PG_CONFIG=/usr/bin/pg_config
        make install PG_CONFIG=/usr/bin/pg_config
      fi

      # --- build + install Apache AGE 1.8.0 (commit AGE_COMMIT, tag PG18/v1.8.0-rc0, not a branch) against PG18 ---
      if [ ! -f "$(/usr/bin/pg_config --pkglibdir)/age.so" ]; then
        fetch_pinned https://github.com/apache/age.git /opt/age-src "$AGE_COMMIT"
        cd /opt/age-src
        # bison 3.8 flags AGE's %pure-parser as deprecated; under -Werror that is
        # fatal (same fix as the f1 macOS tier build). Drop -Werror outright -
        # "-Wno-error=other" is not a valid gcc warning name and fails the build.
        sed -i 's/-Werror//g' Makefile
        make PG_CONFIG=/usr/bin/pg_config
        make install PG_CONFIG=/usr/bin/pg_config
      fi

      # --- PostgreSQL server TLS (#4635) ---------------------------------
      # The store URL pins sslmode=verify-full (the connect funnel refuses
      # anything weaker: src/store/postgres/dsn.rs:213-283, floor
      # src/transit_encryption.rs:436-446). A local RSA CA signs a server
      # cert whose SAN is the host the URL dials (localhost). RSA, not
      # Ed25519: RSA keeps the chain usable by libpq clients such as psql with channel_binding (#2658); the daemon itself does not channel-bind.
      # Shape follows infra/do-hive/crypto/gen-certs.sh:62-72 and :97-99 (RSA CA 4096,
      # leaf 2048, CA-signed, SAN = dialed host) and the hostssl pg_hba of
      # infra/do-hive/crypto/test-pg-verifyfull.sh (hostssl, scram-sha-256).
      TLSD=/etc/ai-memory/tls
      PGTLS=/etc/postgresql/18/main/tls
      # #4675/#4698: the CA private key exists only in RAM (/run, tmpfs, no
      # swap) while the leaf is signed, and is wiped on every success, failure
      # or exit, so a compromised node cannot mint certificates the daemon
      # would trust.
      PGCA=/run/ai-memory-pgca
      wipe_pgca() { rm -rf "$PGCA"; }
      trap wipe_pgca EXIT
      install -d -o root -g aimemory -m 0750 "$TLSD"
      # An earlier image kept the CA key here: remove it unconditionally.
      rm -f "$TLSD/pg-ca.key" "$TLSD/pg-ca.srl"
      if [ ! -s "$TLSD/pg-ca.crt" ] || [ ! -s "$PGTLS/server.key" ]; then
        [ "$(findmnt -n -o FSTYPE --target /run)" = tmpfs ] \
          || { echo "/run is not tmpfs: refusing to write the CA key"; exit 1; }
        [ -z "$(swapon --show --noheadings)" ] \
          || { echo "swap is active: refusing to write the CA key"; exit 1; }
        wipe_pgca
        install -d -m 0700 "$PGCA"
        ( umask 077
          openssl genrsa -out "$PGCA/pg-ca.key" 4096
          openssl req -x509 -new -key "$PGCA/pg-ca.key" -sha256 -days 365 \
            -subj "/CN=ai-memory-hive-pg-CA" -out "$PGCA/pg-ca.crt"
          openssl genrsa -out "$PGCA/pg-server.key" 2048
          openssl req -new -key "$PGCA/pg-server.key" -subj "/CN=localhost" \
            -out "$PGCA/pg-server.csr"
          printf 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:0:0:0:0:0:0:0:1\n' \
            > "$PGCA/pg-server.ext"
          openssl x509 -req -in "$PGCA/pg-server.csr" -CA "$PGCA/pg-ca.crt" \
            -CAkey "$PGCA/pg-ca.key" -CAcreateserial -days 365 -sha256 \
            -extfile "$PGCA/pg-server.ext" -out "$PGCA/pg-server.crt" ) \
          || { echo "could not mint the postgres TLS pair"; exit 1; }
        install -o root -g aimemory -m 0644 "$PGCA/pg-ca.crt" "$TLSD/pg-ca.crt"
        install -d -o postgres -g postgres -m 0700 "$PGTLS"
        install -o postgres -g postgres -m 0600 "$PGCA/pg-server.key" "$PGTLS/server.key"
        install -o postgres -g postgres -m 0644 "$PGCA/pg-server.crt" "$PGTLS/server.crt"
        wipe_pgca
      fi
      # The service user reads only the CA certificate (the trust anchor).
      chown root:aimemory "$TLSD/pg-ca.crt"
      chmod 0644 "$TLSD/pg-ca.crt"

      # --- preload AGE + TLS settings + restart postgres ---
      PGCONF="/etc/postgresql/18/main/postgresql.conf"
      if ! grep -q "shared_preload_libraries.*age" "$PGCONF"; then
        echo "shared_preload_libraries = 'age'" >> "$PGCONF"
      fi
      # Appended last, so it overrides the packaged snakeoil ssl settings.
      if ! grep -q "^# ai-memory-tls (#4635)" "$PGCONF"; then
        printf '%s\n' "# ai-memory-tls (#4635)" "ssl = on" \
          "ssl_cert_file = '$PGTLS/server.crt'" "ssl_key_file = '$PGTLS/server.key'" \
          "ssl_min_protocol_version = 'TLSv1.2'" >> "$PGCONF"
      fi
      # No role may log in to any database, or open a physical-replication
      # connection, over TCP without TLS (#4676): the first two lines reject
      # every non-TLS TCP attempt (hostnossl, all roles, all addresses; `all`
      # does not match the replication pseudo-database, so it has its own line),
      # so the packaged `host all all` and `host replication all` lines below
      # are only reachable over TLS (first matching line wins). Unix-socket
      # `local` lines are unaffected.
      HBA="/etc/postgresql/18/main/pg_hba.conf"
      if ! grep -q "^# ai-memory-tls (#4635)" "$HBA"; then
        { printf '%s\n' "# ai-memory-tls (#4635)" \
            "hostnossl all all all reject" \
            "hostnossl replication all all reject" \
            "hostssl aimemory aimemory 127.0.0.1/32 scram-sha-256" \
            "hostssl aimemory aimemory ::1/128 scram-sha-256"
          cat "$HBA"; } > "$HBA.new"
        chown --reference="$HBA" "$HBA.new"
        chmod --reference="$HBA" "$HBA.new"
        mv "$HBA.new" "$HBA"
      fi
      systemctl restart postgresql
      sleep 5

      # --- db + role + extensions (idempotent). The role password is read
      # from the store-url file and reaches psql on stdin, never on an argv.
      # The DSN userinfo is percent-decoded here the way the daemon's URL parser
      # decodes it, and any single quote is doubled for the SQL literal. psql runs with ON_ERROR_STOP so a failed statement
      # stops the script instead of falling through to CREATE DATABASE.
      DB_PASS="$(sed -n 's#^postgres://aimemory:\([^@]*\)@.*#\1#p' /etc/ai-memory/store-url)"
      [ -n "$DB_PASS" ] || { echo "no db password in /etc/ai-memory/store-url"; exit 1; }
      sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='aimemory'" | grep -q 1 || \
        printf '%s' "$DB_PASS" \
          | python3 -c 'import sys,urllib.parse as u;p=u.unquote(sys.stdin.read());q=chr(39);print("CREATE USER aimemory WITH PASSWORD "+q+p.replace(q,q+q)+q+";")' \
          | sudo -u postgres psql -v ON_ERROR_STOP=1
      sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='aimemory'" | grep -q 1 || \
        sudo -u postgres psql -c "CREATE DATABASE aimemory OWNER aimemory;"
      sudo -u postgres psql -d aimemory -c "CREATE EXTENSION IF NOT EXISTS vector;"
      sudo -u postgres psql -d aimemory -c "ALTER EXTENSION vector UPDATE;" || true
      sudo -u postgres psql -d aimemory -c "CREATE EXTENSION IF NOT EXISTS age;"
      sudo -u postgres psql -d aimemory -c "GRANT ALL ON SCHEMA ag_catalog TO aimemory;" || true
      sudo -u postgres psql -d aimemory -c "SELECT extname, extversion FROM pg_extension WHERE extname IN ('vector','age');"

      echo "PostgreSQL: $(sudo -u postgres psql -Atc 'SELECT version()')"
      sudo -u postgres psql -d aimemory -Atc "SELECT extname || ': ' || extversion FROM pg_extension WHERE extname IN ('age','vector') ORDER BY extname"

      # --- ai-memory binary (operator-published sal-postgres tarball) ---
      # NOTE: the binary MUST be compiled with --features sal-postgres for the
      # postgres+AGE path. For ad-hoc runs the operator leaves ai_memory_image_url
      # empty, scp's a local build over /usr/local/lib/ai-memory/bin/ai-memory and runs
      # `systemctl restart ai-memory`.
      # #4637 (form copied from infra/aws-gpu-burst/cloud-init-memory.yaml.tpl):
      # the tarball is downloaded into a root-only directory, its SHA-256 is
      # checked against the operator-supplied digest BEFORE it is extracted, and
      # the version probe runs as the unprivileged service user, so the
      # unverified download is not executed as root. A mismatch (or a malformed
      # digest) stops the script before the systemctl enable line below.
      if [ -n "${ai_memory_image_url}" ]; then
        DL=/var/cache/ai-memory-provision
        install -d -m 0700 "$DL"
        curl -fsSL "${ai_memory_image_url}" -o "$DL/ai-memory.tar.gz"
        echo "${ai_memory_image_sha256}  $DL/ai-memory.tar.gz" | sha256sum -c - \
          || { echo "ai-memory tarball digest mismatch"; rm -f "$DL/ai-memory.tar.gz"; exit 1; }
        # #4673/#4665: extract only the one member into a root-only staging dir
        # (never into a directory the service user can write). #4697: the member
        # must be a regular file, not a symlink install would dereference.
        # #4712: the binary goes to the root-owned /usr/local/lib/ai-memory/bin,
        # outside the service home, so the service user cannot rename its
        # directory aside and substitute it.
        rm -rf "$DL/x"
        install -d -m 0700 "$DL/x"
        tar -xzf "$DL/ai-memory.tar.gz" --no-same-owner -C "$DL/x" ai-memory
        [ -f "$DL/x/ai-memory" ] && [ ! -L "$DL/x/ai-memory" ] \
          || { echo "tarball member ai-memory is not a regular file"; exit 1; }
        install -o root -g root -m 0755 "$DL/x/ai-memory" /usr/local/lib/ai-memory/bin/ai-memory
        rm -rf "$DL/x"
        runuser -u aimemory -- /usr/local/lib/ai-memory/bin/ai-memory --version
      fi

      systemctl daemon-reload
      # TLS is universal: do NOT start serve here. The overlay binds
      # an EnvironmentFile that only exists once federate.sh has delivered the
      # peer list, so an early start would just crash-loop. The one-shot
      # bootstrap unit owns the ordering; --no-block keeps cloud-init's runcmd
      # from hanging on a unit that legitimately waits for the operator.
      if [ -x /usr/local/lib/ai-memory/bin/ai-memory ]; then
        systemctl enable ai-memory || true
      fi
      systemctl enable ai-memory-fed-bootstrap || true
      systemctl start --no-block ai-memory-fed-bootstrap || true
      echo "=== provision complete $(date -u) ==="
runcmd:
  - bash /usr/local/sbin/ai-memory-provision.sh
