#cloud-config
# ai-memory v1.0.0 perf data tier -- dedicated DigitalOcean droplet.
#
# NOTHING IN THIS FILE DESCRIBES THE POSTGRES STACK.
# ---------------------------------------------------
# Every substrate-defining artifact below is a @@PLACEHOLDER@@ that provision.sh
# SPLICES from the certified local stack at render time:
#
#   Dockerfile               <- pg-age-stack/Dockerfile
#   docker-compose pg svc    <- pg-age-stack/docker-compose.yml   (the pg-main service)
#   initdb/00-extensions.sql <- pg-age-stack/initdb/00-extensions.sql
#   initdb/01-tls-hba.sh     <- pg-age-stack/initdb/01-tls-hba.sh
#
# This is deliberate and load-bearing. A hand-written paraphrase of the certified
# stack failed four separate times, every time on something the certified files
# had already solved:
#   1. $${VAR} escaping         -> failed to parse stage name "{PG_IMAGE}"
#   2. missing ca-certificates  -> git clone: Problem with the SSL CA cert
#   3. non-ASCII em-dashes      -> cloud-init silently discards the whole config
#   4. pgdata:/var/lib/postgresql/data -> PG18 entrypoint refuses to initialise
# The certified compose file literally carries the comment
#   "PG18+ convention: mount at /var/lib/postgresql, NOT /var/lib/postgresql/data."
# Splicing makes divergence between the droplet and the local tier impossible,
# rather than merely discouraged. Do not inline any of it back into this file.
#
# ASCII ONLY. A single non-ASCII byte (a U+2014 em-dash) once made cloud-init
# silently discard an entire config and boot a bare droplet with none of the
# substrate installed -- see issue #1880. provision.sh transliterates every
# spliced source and then re-checks the RENDERED file, not just this source.
#
# Versions come from the spliced Dockerfile, SHA-pinned, not from here:
#   PostgreSQL 18.4, Apache AGE 1.7.0 (806fa2eb), pgvector 0.8.6 (8ee86c96).

package_update: true
package_upgrade: false

packages:
  - ca-certificates
  - curl
  - git
  - gnupg
  - jq
  - postgresql-client
  - sysstat
  - ufw

write_files:
  # --- SPLICED: certified Dockerfile ---------------------------------------
  - path: /opt/ai-memory-perf/Dockerfile
    permissions: '0644'
    content: |
@@CERTIFIED_DOCKERFILE@@

  # --- SPLICED: certified pg service, with perf-tier deltas applied by
  #     provision.sh (container name, private-IP bind, PGPASS, tuning GUCs).
  #     The mount path, the TLS block and the initdb wiring are VERBATIM.
  - path: /opt/ai-memory-perf/docker-compose.yml
    permissions: '0644'
    content: |
      # GENERATED -- spliced from the certified local stack. Do not hand-edit.
      name: ai-memory-perf
      services:
@@CERTIFIED_COMPOSE_PG@@
      volumes:
        pgdata:
          name: ai-memory-pg-perf-data

  # --- SPLICED: certified TLS-enforced pg_hba.conf writer ------------------
  # This is the file that makes a cleartext TCP connection REFUSED rather than
  # silently downgraded. A stack that merely offers TLS while still accepting
  # cleartext would produce benchmark numbers from an unencrypted path while we
  # claim an encrypted one.
  #
  # ORDERING IS LOAD-BEARING, and inverted relative to the certified local stack
  # (00-extensions / 01-tls-hba). The entrypoint runs initdb.d in lexical order
  # under `psql -v ON_ERROR_STOP=1`, so a failure in ANY earlier script aborts
  # the whole init loop -- and because the container restarts with a now
  # NON-EMPTY PGDATA, initdb is SKIPPED on the retry and the database serves
  # forever on the entrypoint's default pg_hba.conf, whose last line is a plain
  # `host all all all scram-sha-256`. Cleartext ACCEPTED, container healthy,
  # nothing in the logs after the restart. Observed 2026-08-01: a failing
  # create_graph() call in the extensions script silently disarmed the entire
  # encryption leg exactly this way. Writing the HBA FIRST makes the encryption
  # guarantee independent of every other init script.
  - path: /opt/ai-memory-perf/initdb/00-tls-hba.sh
    permissions: '0755'
    content: |
@@CERTIFIED_INITDB_TLS_HBA@@

  # --- SPLICED: certified first-boot extension wiring ----------------------
  - path: /opt/ai-memory-perf/initdb/01-extensions.sql
    permissions: '0644'
    content: |
@@CERTIFIED_INITDB_EXTENSIONS@@

  - path: /opt/ai-memory-perf/.env
    permissions: '0600'
    content: |
      # docker compose auto-loads this. BIND_ADDR is appended by start.sh from
      # the droplet metadata, because the VPC private IP is not knowable until
      # the droplet exists.
      PGPASS=${PGPASS}

  - path: /opt/ai-memory-perf/wait-for-certs.sh
    permissions: '0755'
    content: |
      #!/usr/bin/env bash
      # Fail-closed TLS material gate.
      #
      # The server certificate SAN must carry THIS droplet's VPC private IP, and
      # that IP does not exist until after the droplet is created -- so the certs
      # cannot be baked into user-data. provision.sh generates them locally with
      # infra/do-hive/crypto/gen-certs.sh and scps them in while the AGE/pgvector
      # compile is still running.
      #
      # If they never arrive, postgres is NOT started. There is deliberately no
      # cleartext fallback: a droplet with no TLS material must fail the provision,
      # never quietly serve an unencrypted port.
      set -euo pipefail
      CERTS=/opt/ai-memory-perf/certs
      for i in $(seq 1 180); do
        if [ -s "$CERTS/server.crt" ] && [ -s "$CERTS/server.key" ] && [ -s "$CERTS/ca.crt" ]; then
          # postgres refuses to start if the private key is group/world readable
          # or is owned by neither root nor the database user. 999:999 is the
          # postgres uid/gid inside the official image.
          chown 999:999 "$CERTS/server.key" "$CERTS/server.crt" "$CERTS/ca.crt"
          chmod 600 "$CERTS/server.key"
          chmod 644 "$CERTS/server.crt" "$CERTS/ca.crt"
          echo "TLS material present after $((i*10))s"
          exit 0
        fi
        sleep 10
      done
      echo "FATAL: TLS material never arrived at $CERTS -- refusing to start postgres" >&2
      exit 1

  - path: /opt/ai-memory-perf/start.sh
    permissions: '0755'
    content: |
      #!/usr/bin/env bash
      set -euo pipefail
      cd /opt/ai-memory-perf

      # `ufw --force reset` + `ufw --force enable` in runcmd above flush the
      # DOCKER / DOCKER-USER iptables chains that dockerd installs at daemon
      # start. Published-port DNAT then silently stops working -- the container
      # comes up healthy and the port is simply unreachable, which would look
      # exactly like a firewall problem and waste a provisioning cycle.
      # Reinstate the chains before anything is published.
      systemctl restart docker
      sleep 5

      # Publish postgres on the VPC private interface ONLY.
      #
      # ufw is NOT sufficient on its own here: docker's published-port DNAT
      # bypasses the ufw INPUT chain, so `ufw deny` would leave 5433 reachable
      # from the public internet. Binding the published port to the private IP
      # removes the exposure at the source rather than filtering it afterwards.
      PRIV="$(curl -sf --max-time 15 http://169.254.169.254/metadata/v1/interfaces/private/0/ipv4/address || true)"
      [ -n "$PRIV" ] || { echo "FATAL: no VPC private IP from droplet metadata" >&2; exit 1; }
      grep -q '^BIND_ADDR=' .env || printf 'BIND_ADDR=%s\n' "$PRIV" >> .env
      echo "BIND_ADDR: $PRIV"

      # AGE and pgvector are compiled from source against the 18.4 headers; this
      # is the long pole (~15-20 min). Do it before waiting on the certs.
      docker compose build

      /opt/ai-memory-perf/wait-for-certs.sh
      docker compose up -d
      /opt/ai-memory-perf/verify.sh

  - path: /opt/ai-memory-perf/verify.sh
    permissions: '0755'
    content: |
      #!/usr/bin/env bash
      # Fail-closed provisioning proof.
      #
      # A droplet that came up without the extensions is worse than no droplet,
      # because it would silently produce numbers for a stack nobody is testing.
      # The same argument applies to encryption: a tier that ACCEPTS cleartext
      # would produce numbers off an unencrypted path while the writeup claims an
      # encrypted one. CHECK 3 is therefore the load-bearing one -- checks 1, 2
      # and 4 confirm configuration, check 3 confirms ENFORCEMENT.
      #
      # Note: -e is deliberately NOT set. Two checks assert that a command FAILS.
      set -uo pipefail
      cd /opt/ai-memory-perf
      . ./.env

      PRIV="$(curl -sf --max-time 15 http://169.254.169.254/metadata/v1/interfaces/private/0/ipv4/address || true)"
      [ -n "$PRIV" ] || { echo "FATAL: no VPC private IP from droplet metadata" >&2; exit 1; }
      CA=/opt/ai-memory-perf/certs/ca.crt
      export PGPASSWORD="$PGPASS"
      URI_BASE="postgresql://ai_memory@$PRIV:5433/ai_memory_test"
      fail=0

      echo "== ai-memory perf data tier verification =="
      echo "host: $PRIV:5433"

      for i in $(seq 1 120); do
        docker compose exec -T pg pg_isready -U ai_memory -d ai_memory_test >/dev/null 2>&1 && break
        sleep 5
      done

      # --- CHECK 1: extensions + graph ---------------------------------------
      STACK="$(docker compose exec -T pg psql -U ai_memory -d ai_memory_test -tAc \
        "select current_setting('server_version')
             ||'|'||coalesce((select extversion from pg_extension where extname='age'),'MISSING')
             ||'|'||coalesce((select extversion from pg_extension where extname='vector'),'MISSING')
             ||'|'||coalesce((select name::text from ag_catalog.ag_graph where name::text='memory_graph'),'NOGRAPH')" 2>&1)"
      echo "CHECK 1 stack (pg|age|vector|graph): $STACK"
      case "$STACK" in
        *MISSING*|*NOGRAPH*|'') echo "CHECK 1 FAIL - extension or memory_graph absent"; fail=1 ;;
        *) echo "CHECK 1 PASS - age, vector and memory_graph present" ;;
      esac

      # --- CHECK 2: the server reports ssl = on -------------------------------
      SSLGUC="$(docker compose exec -T pg psql -U ai_memory -d ai_memory_test -tAc 'show ssl' 2>&1 | tr -d '[:space:]')"
      echo "CHECK 2 ssl GUC: '$SSLGUC'"
      if [ "$SSLGUC" = "on" ]; then
        echo "CHECK 2 PASS - ssl = on"
      else
        echo "CHECK 2 FAIL - expected ssl = on"; fail=1
      fi

      # --- CHECK 3: a cleartext connection is REFUSED (LOAD-BEARING) ---------
      # A bare "it failed" is not proof: a wrong password, a closed port or an
      # unreachable host would also fail, and would hand back a false PASS. The
      # refusal must come from the HBA -- libpq reports the server's
      #   "no pg_hba.conf entry for host ..., no encryption"
      # and CHECK 4 proves the same host/port/credentials DO work over TLS.
      CLEAR_ERR="$(psql "$URI_BASE?sslmode=disable" -tAc 'select 1' 2>&1)"
      CLEAR_RC=$?
      if [ $CLEAR_RC -eq 0 ]; then
        echo "CHECK 3 FAIL - CLEARTEXT CONNECTION SUCCEEDED. The tier accepts an"
        echo "               unencrypted path; any number taken here would be a lie."
        fail=1
      elif printf '%s' "$CLEAR_ERR" | grep -qiE 'no encryption|no pg_hba\.conf entry'; then
        echo "CHECK 3 PASS - cleartext connection REFUSED by pg_hba.conf:"
        printf '%s\n' "$CLEAR_ERR" | sed 's/^/               /'
      else
        echo "CHECK 3 FAIL - cleartext connection failed for the WRONG reason"
        echo "               (not an HBA refusal; cannot be counted as proof):"
        printf '%s\n' "$CLEAR_ERR" | sed 's/^/               /'
        fail=1
      fi

      # --- CHECK 4: sslmode=verify-full with the CA succeeds ------------------
      TLSOUT="$(psql "$URI_BASE?sslmode=verify-full&sslrootcert=$CA" -tAc \
        "select 'ssl='||ssl||' '||version||' '||cipher from pg_stat_ssl where pid=pg_backend_pid()" 2>&1)"
      if [ $? -eq 0 ] && printf '%s' "$TLSOUT" | grep -q 'ssl=t'; then
        echo "CHECK 4 PASS - sslmode=verify-full connected: $TLSOUT"
      else
        echo "CHECK 4 FAIL - verify-full did not connect: $TLSOUT"; fail=1
      fi

      if [ "$fail" -ne 0 ]; then
        echo "PROVISION FAILED - see the failing check(s) above" >&2
        exit 1
      fi
      echo "PROVISION OK - stack verified and TLS enforcement proven"

runcmd:
  - install -m 0755 -d /etc/apt/keyrings
  - curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  - chmod a+r /etc/apt/keyrings/docker.asc
  - >
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc]
    https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable"
    > /etc/apt/sources.list.d/docker.list
  - apt-get update
  - apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  # Firewall: the data tier is reachable ONLY from inside the VPC. Note that the
  # real containment for 5433 is the private-IP port bind in start.sh -- docker's
  # DNAT bypasses ufw's INPUT chain, so these rules alone would NOT keep 5433 off
  # the public internet. Both are applied; neither is trusted alone.
  - ufw --force reset
  - ufw default deny incoming
  - ufw default allow outgoing
  - ufw allow 22/tcp
  - ufw allow from ${VPC_CIDR} to any port 5433 proto tcp
  - ufw --force enable
  - /opt/ai-memory-perf/start.sh 2>&1 | tee /var/log/ai-memory-provision.log

final_message: "ai-memory perf data tier ready after $UPTIME seconds. Check /var/log/ai-memory-provision.log for the fail-closed stack + TLS verification."
