#cloud-config
# Track E1 -- ai-memory + PostgreSQL 16 + pgvector + Apache AGE bootstrap on the
# DO substrate droplet. Templated by `infra/do-hive/main.tf`. Operator-triggered.
#
# #1842 fix (v0.8.1): the prior template installed postgresql-16 but never
# installed pgvector and never built Apache AGE (AGE is source-only -- not an
# apt package -- and `CREATE EXTENSION age` failed). It also used the invalid
# `--bind` flag. This template installs pgvector (apt), builds AGE from source
# against pg16, preloads AGE, creates the db + both extensions, and runs serve
# with the correct `--host/--port` flags + a postgres `--store-url`.
#
# All provisioning is logged to /var/log/ai-memory-provision.log for SSH triage.
package_update: true
package_upgrade: false
packages:
  - postgresql-16
  - postgresql-16-pgvector
  - postgresql-server-dev-16
  - build-essential
  - flex
  - bison
  - libreadline-dev
  - zlib1g-dev
  - git
  - curl
  - jq
write_files:
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
      Environment=AI_MEMORY_PERMISSIONS_MODE=enforce
      Environment=AI_MEMORY_AUTONOMOUS_HOOKS=0
      Environment=RUST_LOG=ai_memory=info,store::postgres=info
      ExecStart=/opt/ai-memory/bin/ai-memory serve --host 0.0.0.0 --port 9077 --store-url "postgres://aimemory:${db_password}@localhost/aimemory"
      Restart=on-failure
      RestartSec=5

      [Install]
      WantedBy=multi-user.target
  - path: /opt/ai-memory/provision.sh
    permissions: '0755'
    content: |
      #!/usr/bin/env bash
      set -euxo pipefail
      exec > >(tee -a /var/log/ai-memory-provision.log) 2>&1
      echo "=== ai-memory postgres+AGE+pgvector provision $(date -u) ==="

      # --- user + dirs ---
      id aimemory >/dev/null 2>&1 || useradd -m -d /opt/ai-memory -s /bin/bash aimemory
      mkdir -p /opt/ai-memory/bin /var/log/ai-memory
      chown -R aimemory:aimemory /opt/ai-memory /var/log/ai-memory

      # --- build + install Apache AGE from source against pg16 ---
      # AGE is source-only. master supports PG16; pin the PG16 release branch.
      if [ ! -f "$(/usr/bin/pg_config --pkglibdir)/age.so" ]; then
        rm -rf /opt/age-src
        git clone https://github.com/apache/age.git /opt/age-src
        cd /opt/age-src
        git checkout PG16 || git checkout master
        make PG_CONFIG=/usr/bin/pg_config
        make install PG_CONFIG=/usr/bin/pg_config
      fi

      # --- preload AGE + restart postgres ---
      PGCONF="/etc/postgresql/16/main/postgresql.conf"
      if ! grep -q "shared_preload_libraries.*age" "$PGCONF"; then
        echo "shared_preload_libraries = 'age'" >> "$PGCONF"
      fi
      systemctl restart postgresql
      sleep 5

      # --- db + role + extensions (idempotent) ---
      sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='aimemory'" | grep -q 1 || \
        sudo -u postgres psql -c "CREATE USER aimemory WITH PASSWORD '${db_password}';"
      sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='aimemory'" | grep -q 1 || \
        sudo -u postgres psql -c "CREATE DATABASE aimemory OWNER aimemory;"
      sudo -u postgres psql -d aimemory -c "CREATE EXTENSION IF NOT EXISTS vector;"
      sudo -u postgres psql -d aimemory -c "CREATE EXTENSION IF NOT EXISTS age;"
      sudo -u postgres psql -d aimemory -c "GRANT ALL ON SCHEMA ag_catalog TO aimemory;" || true
      sudo -u postgres psql -d aimemory -c "SELECT extname, extversion FROM pg_extension WHERE extname IN ('vector','age');"

      # --- ai-memory binary (operator-published sal-postgres tarball) ---
      # NOTE: the binary MUST be compiled with --features sal-postgres for the
      # postgres+AGE path. For ad-hoc runs the operator scp's a local build over
      # this and `systemctl restart ai-memory`.
      if [ -n "${ai_memory_image_url}" ]; then
        curl -fsSL "${ai_memory_image_url}" -o /opt/ai-memory/ai-memory.tar.gz || true
        tar -xzf /opt/ai-memory/ai-memory.tar.gz -C /opt/ai-memory/bin || true
        chmod 0755 /opt/ai-memory/bin/ai-memory || true
      fi
      chown -R aimemory:aimemory /opt/ai-memory

      systemctl daemon-reload
      # serve only starts once a sal-postgres binary is present.
      if [ -x /opt/ai-memory/bin/ai-memory ]; then
        systemctl enable --now ai-memory || true
      fi
      echo "=== provision complete $(date -u) ==="
runcmd:
  - bash /opt/ai-memory/provision.sh
