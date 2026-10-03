#cloud-config
# Track E2 - ai-memory + PostgreSQL 18 + pgvector + Apache AGE bootstrap on the
# burst substrate. Operator-triggered; templated by infra/aws-gpu-burst/main.tf.
#
# #4616: the prior template could not produce a running daemon. (1) serve
# refuses a non-loopback bind without an API key (api_key_bind_guard,
# src/daemon_runtime.rs); (2) serve also refuses any bind without in-process
# TLS (tls_bind_guard, src/daemon_runtime.rs); (3) the apt postgresql-16
# package ships no Apache AGE, so CREATE EXTENSION age failed. This template
# follows the infra/do-hive/cloud-init-memory.yaml.tpl precedent: PostgreSQL 18
# from PGDG, pgvector and AGE built from the certified tags, a per-node API
# key and a self-signed TLS pair minted ON the node (never in user-data), and
# serve flags that exist in ServeArgs (--host, --port, --tls-cert, --tls-key).
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
      ExecStart=/opt/ai-memory/bin/ai-memory serve --host 0.0.0.0 --port 9077 --tls-cert /etc/ai-memory/tls/node.crt --tls-key /etc/ai-memory/tls/node.key
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
      mkdir -p /opt/ai-memory/bin
      chown -R aimemory:aimemory /opt/ai-memory
      # #4577/#4619: the service user traverses /etc/ai-memory and owns the DSN
      # file (mode stays 0600).
      chown root:aimemory /etc/ai-memory
      chmod 0750 /etc/ai-memory
      chown aimemory:aimemory /etc/ai-memory/store-url
      chmod 0600 /etc/ai-memory/store-url

      # --- build + install pgvector 0.8.6 against PG18 ---
      if [ ! -f "$(/usr/bin/pg_config --pkglibdir)/vector.so" ]; then
        rm -rf /opt/pgvector-src
        git clone --branch v0.8.6 --depth 1 https://github.com/pgvector/pgvector.git /opt/pgvector-src
        cd /opt/pgvector-src
        make PG_CONFIG=/usr/bin/pg_config
        make install PG_CONFIG=/usr/bin/pg_config
      fi

      # --- build + install Apache AGE 1.8.0 against PG18 (source-only) ---
      if [ ! -f "$(/usr/bin/pg_config --pkglibdir)/age.so" ]; then
        rm -rf /opt/age-src
        git clone https://github.com/apache/age.git /opt/age-src
        cd /opt/age-src
        git checkout release/PG18/1.8.0
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
      install -d -o root -g aimemory -m 0750 "$TLSD"
      if [ ! -s "$TLSD/pg-ca.crt" ] || [ ! -s "$PGTLS/server.key" ]; then
        ( umask 077
          openssl genrsa -out "$TLSD/pg-ca.key" 4096
          openssl req -x509 -new -key "$TLSD/pg-ca.key" -sha256 -days 365 \
            -subj "/CN=ai-memory-burst-pg-CA" -out "$TLSD/pg-ca.crt"
          openssl genrsa -out "$TLSD/pg-server.key" 2048
          openssl req -new -key "$TLSD/pg-server.key" -subj "/CN=localhost" \
            -out "$TLSD/pg-server.csr"
          printf 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:0:0:0:0:0:0:0:1\n' \
            > "$TLSD/pg-server.ext"
          openssl x509 -req -in "$TLSD/pg-server.csr" -CA "$TLSD/pg-ca.crt" \
            -CAkey "$TLSD/pg-ca.key" -CAcreateserial -days 365 -sha256 \
            -extfile "$TLSD/pg-server.ext" -out "$TLSD/pg-server.crt" ) \
          || { echo "could not mint the postgres TLS pair"; exit 1; }
        install -d -o postgres -g postgres -m 0700 "$PGTLS"
        install -o postgres -g postgres -m 0600 "$TLSD/pg-server.key" "$PGTLS/server.key"
        install -o postgres -g postgres -m 0644 "$TLSD/pg-server.crt" "$PGTLS/server.crt"
        rm -f "$TLSD/pg-server.key" "$TLSD/pg-server.csr" "$TLSD/pg-server.ext" "$TLSD/pg-server.crt"
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
      DB_PASS="$(sed -n 's#^postgres://aimemory:\([^@]*\)@.*#\1#p' /etc/ai-memory/store-url)"
      [ -n "$DB_PASS" ] || { echo "no db password in /etc/ai-memory/store-url"; exit 1; }
      sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='aimemory'" | grep -q 1 || \
        printf "CREATE USER aimemory WITH PASSWORD '%s';\n" "$DB_PASS" | sudo -u postgres psql
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
      CFG_DIR=/opt/ai-memory/.config/ai-memory
      install -d -o aimemory -g aimemory -m 0750 /opt/ai-memory/.config "$CFG_DIR"
      ( umask 077; printf 'schema_version = 2\napi_key = "%s"\n' "$API_KEY" > "$CFG_DIR/config.toml" ) \
        || { echo "could not write the daemon config"; exit 1; }
      chown root:aimemory "$CFG_DIR/config.toml"
      chmod 0640 "$CFG_DIR/config.toml"

      # --- self-signed TLS pair (serve refuses a plaintext bind) --------
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
      curl -fsSL "${ai_memory_image_url}" -o /opt/ai-memory/ai-memory.tar.gz
      tar -xzf /opt/ai-memory/ai-memory.tar.gz -C /opt/ai-memory/bin
      chmod 0755 /opt/ai-memory/bin/ai-memory
      chown -R aimemory:aimemory /opt/ai-memory/bin
      /opt/ai-memory/bin/ai-memory --version

      systemctl daemon-reload
      systemctl enable --now ai-memory
      echo "=== provision complete $(date -u) ==="
runcmd:
  - [bash, /usr/local/sbin/ai-memory-provision.sh]
