#cloud-config
# Track E2 - ai-memory + PostgreSQL 18 + pgvector + Apache AGE bootstrap on the
# burst substrate. Operator-triggered; templated by infra/aws-gpu-burst/main.tf.
#
# #4616: the prior template could not produce a running daemon. (1) serve
# refuses a non-loopback bind without an API key (api_key_bind_guard,
# src/daemon_runtime.rs:5970); (2) the apt postgresql-16 package ships no
# Apache AGE, so CREATE EXTENSION age failed. This template follows the
# infra/do-hive/cloud-init-memory.yaml.tpl precedent: PostgreSQL 18 from PGDG,
# pgvector and AGE built from source, a per-node API key and a self-signed
# TLS pair minted ON the node (never in user-data), and serve flags that exist
# in ServeArgs (--host, --port, --tls-cert, --tls-key). The TLS flags are a
# policy choice, not a serve refusal: with no flags serve resolves its own
# certificate (resolve_tls_material, src/daemon_runtime.rs:6163-6225; it mints
# a local-CA certificate for the declared singleton shape and refuses a
# declared fleet shape that has no operator certificate). Supplying the pair
# here puts the node's private IP in the certificate SAN for agents on other
# hosts, and a flag pair is accepted whatever shape is declared
# (src/daemon_runtime.rs:6226-6232).
# The tarball binary must be built with --features sal-postgres: serve refuses
# a postgres store URL otherwise (refuse_postgres_store_url_without_feature),
# so a wrong binary fails closed at start with a message naming the feature.
#
# All provisioning is logged (no xtrace, no secret values) to
# /var/log/ai-memory-provision.log for SSH triage.
package_update: true
bootcmd:
  # #4619: cloud-init write_files creates the file under the process umask and
  # chmods it AFTER writing (cloudinit/util.py write_file: open, write, flush,
  # chmod). bootcmd runs before write_files, so create /etc/ai-memory root-only
  # (0700, umask 077) first: no other UID can traverse it while the store-url
  # file briefly has the umask mode. Guarded so later boots never reset the
  # 0750 root:aimemory mode the provision script sets once the service user
  # exists.
  - [bash, -c, "[ -d /etc/ai-memory ] || (umask 077 && mkdir /etc/ai-memory)"]
  # PG 18 is supplied by PGDG on Ubuntu Noble. Install the signed repository
  # before cloud-init's packages module runs; never fall back to Ubuntu's PG16.
  - [bash, -c, "install -d -m 0755 /usr/share/postgresql-common/pgdg && curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc"]
  - [bash, -c, "echo 'deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt noble-pgdg main' > /etc/apt/sources.list.d/pgdg.list && apt-get update"]
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
  # is what keeps other UIDs out during it. The provision script hands the file
  # to the aimemory user once that user exists (serve refuses a file with any
  # group/world mode bit, src/store_url.rs). CHANGEME is the database password:
  # replace it before real use. The provision script reads the role password
  # from this one file, so there is no second copy to keep in step.
  - path: /etc/ai-memory/store-url
    permissions: '0600'
    owner: root:root
    content: |
      postgres://aimemory:CHANGEME@localhost/aimemory?sslmode=verify-full&sslrootcert=/etc/ai-memory/tls/pg-ca.crt
  - path: /etc/systemd/system/ai-memory.service
    permissions: '0644'
    content: |
      [Unit]
      Description=ai-memory MCP daemon (Track E2 burst substrate)
      After=postgresql.service network-online.target
      Wants=postgresql.service network-online.target

      [Service]
      Type=simple
      User=aimemory
      Group=aimemory
      # The daemon opens a local sqlite ai-memory.db even in postgres-store mode
      # (#2853); give it a writable CWD. HOME is /opt/ai-memory, so the api_key
      # config is read from /opt/ai-memory/.config/ai-memory/config.toml.
      WorkingDirectory=/opt/ai-memory
      Environment=AI_MEMORY_STORE_URL_FILE=/etc/ai-memory/store-url
      Environment=AI_MEMORY_PERMISSIONS_MODE=enforce
      Environment=AI_MEMORY_AUTONOMOUS_HOOKS=1
      ExecStart=/usr/local/lib/ai-memory/bin/ai-memory serve --host 0.0.0.0 --port 9077 --tls-cert /etc/ai-memory/tls/node.crt --tls-key /etc/ai-memory/tls/node.key
      Restart=on-failure

      [Install]
      WantedBy=multi-user.target
  # Root-only: outside /opt/ai-memory so the service user can never edit a
  # script root runs.
  - path: /usr/local/sbin/ai-memory-provision.sh
    permissions: '0700'
    content: |
      #!/usr/bin/env bash
      set -euo pipefail
      install -m 0600 /dev/null /var/log/ai-memory-provision.log
      exec >> /var/log/ai-memory-provision.log 2>&1
      echo "=== ai-memory postgres+AGE+pgvector provision $(date -u) ==="

      # --- user + dirs ---
      id aimemory >/dev/null 2>&1 || useradd -m -d /opt/ai-memory -s /bin/bash aimemory
      # #4695: useradd -m made the home service-owned. Root never chowns, writes
      # or walks a path inside it (the service user could plant a symlink there);
      # it only checks the owner. The binary lives outside it (#4696).
      [ "$(stat -c %U /opt/ai-memory)" = aimemory ] \
        || { echo "/opt/ai-memory is not owned by aimemory"; exit 1; }
      # #4577/#4619: the service user traverses /etc/ai-memory and owns the DSN
      # file (mode stays 0600).
      chown root:aimemory /etc/ai-memory
      chmod 0750 /etc/ai-memory
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

      # --- build + install pgvector 0.8.6 (commit PGVECTOR_COMMIT, tag v0.8.6) against PG18 ---
      if [ ! -f "$(/usr/bin/pg_config --pkglibdir)/vector.so" ]; then
        fetch_pinned https://github.com/pgvector/pgvector.git /opt/pgvector-src "$PGVECTOR_COMMIT"
        cd /opt/pgvector-src
        make PG_CONFIG=/usr/bin/pg_config
        make install PG_CONFIG=/usr/bin/pg_config
      fi

      # --- build + install Apache AGE 1.8.0 (commit AGE_COMMIT, tag PG18/v1.8.0-rc0) against PG18 (source-only) ---
      if [ ! -f "$(/usr/bin/pg_config --pkglibdir)/age.so" ]; then
        fetch_pinned https://github.com/apache/age.git /opt/age-src "$AGE_COMMIT"
        cd /opt/age-src
        # bison 3.8 flags AGE's %pure-parser as deprecated; under -Werror that
        # is fatal. Drop -Werror outright.
        sed -i 's/-Werror//g' Makefile
        make PG_CONFIG=/usr/bin/pg_config
        make install PG_CONFIG=/usr/bin/pg_config
      fi

      # --- PostgreSQL server TLS (#4635) ---------------------------------
      # The store URL pins sslmode=verify-full (the connect funnel refuses
      # anything weaker: src/store/postgres/dsn.rs:213-283, floor
      # src/transit_encryption.rs:436-446). A local RSA CA signs a server
      # cert whose SAN is the host the URL dials (localhost). RSA, not
      # Ed25519: libpq channel binding has no digest for Ed25519 (#2658).
      # Shape follows infra/do-hive/crypto/gen-certs.sh:40-56 (RSA CA 4096,
      # leaf 2048, CA-signed, SAN = dialed host) and the hostssl pg_hba of
      # infra/do-hive/crypto/test-pg-verifyfull.sh (hostssl, scram-sha-256).
      TLSD=/etc/ai-memory/tls
      PGTLS=/etc/postgresql/18/main/tls
      # #4666: the CA private key exists only in a root-only work dir on tmpfs
      # (RAM, never written to the volume) for the few seconds it takes to sign
      # the server certificate. The dir is removed on success AND on any
      # failure or exit, so a compromised node cannot mint certificates the
      # daemon would trust.
      PGCA=/run/ai-memory-pgca
      wipe_pgca() { rm -rf "$PGCA"; }
      trap wipe_pgca EXIT
      install -d -o root -g aimemory -m 0750 "$TLSD"
      # An earlier image kept the CA key here: remove it unconditionally.
      rm -f "$TLSD/pg-ca.key" "$TLSD/pg-ca.srl"
      if [ ! -s "$TLSD/pg-ca.crt" ] || [ ! -s "$PGTLS/server.key" ]; then
        # #4698: the key may only be written to RAM: refuse unless /run is
        # tmpfs and no swap device is active.
        [ "$(findmnt -n -o FSTYPE --target /run)" = tmpfs ] \
          || { echo "/run is not tmpfs: refusing to write the CA key"; exit 1; }
        [ -z "$(swapon --show --noheadings)" ] \
          || { echo "swap is active: refusing to write the CA key"; exit 1; }
        wipe_pgca
        install -d -m 0700 "$PGCA"
        ( umask 077
          openssl genrsa -out "$PGCA/pg-ca.key" 4096
          openssl req -x509 -new -key "$PGCA/pg-ca.key" -sha256 -days 365 \
            -subj "/CN=ai-memory-burst-pg-CA" -out "$PGCA/pg-ca.crt"
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
      # aimemory may only connect with TLS over TCP: hostssl lines first, then
      # a reject for any non-TLS TCP attempt (first matching line wins).
      HBA="/etc/postgresql/18/main/pg_hba.conf"
      if ! grep -q "^# ai-memory-tls (#4635)" "$HBA"; then
        { printf '%s\n' "# ai-memory-tls (#4635)" \
            "hostssl aimemory aimemory 127.0.0.1/32 scram-sha-256" \
            "hostssl aimemory aimemory ::1/128 scram-sha-256" \
            "hostnossl aimemory aimemory all reject"
          cat "$HBA"; } > "$HBA.new"
        chown --reference="$HBA" "$HBA.new"
        chmod --reference="$HBA" "$HBA.new"
        mv "$HBA.new" "$HBA"
      fi
      systemctl restart postgresql
      sleep 5

      # --- db + role + extensions (idempotent). The role password is read
      # from the store-url file and reaches psql on stdin, never on an argv.
      # The DSN userinfo is percent-encoded (a password containing @ : / ? # %
      # must be written %40 etc. in the DSN, #4638/#4642): it is decoded here the
      # way the daemon's URL parser decodes it, and any single quote is doubled
      # for the SQL literal. psql runs with ON_ERROR_STOP so a failed statement
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
      sudo -u postgres psql -d aimemory -c "CREATE EXTENSION IF NOT EXISTS age;"
      sudo -u postgres psql -d aimemory -c "GRANT ALL ON SCHEMA ag_catalog TO aimemory;"
      sudo -u postgres psql -d aimemory -Atc "SELECT extname || ': ' || extversion FROM pg_extension WHERE extname IN ('age','vector') ORDER BY extname"

      # --- per-node API key (minted here, never in user-data) -----------
      # serve refuses a non-loopback bind without an api_key. The key goes in
      # the config file the daemon loads, written under umask 077, never on an
      # argv. The operator reads it with: ssh <node> sudo cat /etc/ai-memory/api-key
      if [ ! -s /etc/ai-memory/api-key ]; then
        ( umask 077; openssl rand -hex 32 > /etc/ai-memory/api-key ) \
          || { echo "could not mint the api key"; exit 1; }
      fi
      chown root:root /etc/ai-memory/api-key
      chmod 0600 /etc/ai-memory/api-key
      API_KEY="$(cat /etc/ai-memory/api-key)"
      # #4695: the config lives in the service-owned home, so it is written by
      # the service user (never by root through a path it controls); the key
      # reaches it on stdin.
      printf '%s' "$API_KEY" | runuser -u aimemory -- bash -c 'umask 077 && d=/opt/ai-memory/.config/ai-memory && mkdir -p "$d" && k="$(cat)" && printf "schema_version = 2\napi_key = \"%s\"\n" "$k" > "$d/config.toml.new" && mv -f "$d/config.toml.new" "$d/config.toml"' \
        || { echo "could not write the daemon config"; exit 1; }

      # --- self-signed TLS pair for the listener (--tls-cert/--tls-key) ----
      install -d -o root -g aimemory -m 0750 /etc/ai-memory/tls
      if [ ! -s /etc/ai-memory/tls/node.key ]; then
        PRIV_IP="$(hostname -I | cut -d' ' -f1)"
        ( umask 077; openssl req -x509 -newkey rsa:3072 -nodes -days 365 \
            -subj "/CN=ai-memory-burst" \
            -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:$PRIV_IP" \
            -keyout /etc/ai-memory/tls/node.key -out /etc/ai-memory/tls/node.crt ) \
          || { echo "could not mint the TLS pair"; exit 1; }
      fi
      chown root:aimemory /etc/ai-memory/tls/node.key /etc/ai-memory/tls/node.crt
      chmod 0640 /etc/ai-memory/tls/node.key
      chmod 0644 /etc/ai-memory/tls/node.crt

      # --- ai-memory binary (operator-published sal-postgres tarball) ---
      # #4637: the tarball is downloaded into a root-only directory, its SHA-256
      # is checked against the operator-supplied digest BEFORE it is extracted,
      # and the version probe runs as the unprivileged service user, so the
      # unverified download is not executed as root. A mismatch (or a malformed
      # digest) stops the script before the systemctl enable line below.
      DL=/var/cache/ai-memory-provision
      install -d -m 0700 "$DL"
      curl -fsSL "${ai_memory_image_url}" -o "$DL/ai-memory.tar.gz"
      echo "${ai_memory_image_sha256}  $DL/ai-memory.tar.gz" | sha256sum -c - \
        || { echo "ai-memory tarball digest mismatch"; rm -f "$DL/ai-memory.tar.gz"; exit 1; }
      # #4665: extract only the one member into a root-only staging dir (never
      # into a directory the service user can write). #4697: the member must be
      # a regular file, not a symlink install would dereference. #4696: the
      # binary goes to a root-owned prefix outside the service home, so the
      # service user cannot rename its directory aside and substitute it.
      rm -rf "$DL/x"
      install -d -m 0700 "$DL/x"
      tar -xzf "$DL/ai-memory.tar.gz" --no-same-owner -C "$DL/x" ai-memory
      [ -f "$DL/x/ai-memory" ] && [ ! -L "$DL/x/ai-memory" ] \
        || { echo "tarball member ai-memory is not a regular file"; exit 1; }
      install -d -o root -g root -m 0755 /usr/local/lib/ai-memory /usr/local/lib/ai-memory/bin
      install -o root -g root -m 0755 "$DL/x/ai-memory" /usr/local/lib/ai-memory/bin/ai-memory
      rm -rf "$DL/x"
      runuser -u aimemory -- /usr/local/lib/ai-memory/bin/ai-memory --version

      systemctl daemon-reload
      systemctl enable --now ai-memory
      echo "=== provision complete $(date -u) ==="
runcmd:
  - [bash, /usr/local/sbin/ai-memory-provision.sh]
