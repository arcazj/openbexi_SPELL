#!/bin/sh
set -eu

if [ "$#" -eq 0 ] || [ "${1#-}" != "$1" ]; then
  set -- postgres "$@"
fi

if [ "$1" != "postgres" ]; then
  exec "$@"
fi
shift

PGDATA="${PGDATA:-/var/lib/postgresql/18/docker}"
POSTGRES_USER="${POSTGRES_USER:-postgres}"
POSTGRES_DB="${POSTGRES_DB:-$POSTGRES_USER}"

mkdir -p "$PGDATA" /var/run/postgresql
chmod 700 "$PGDATA"
chmod 3775 /var/run/postgresql

if [ ! -s "$PGDATA/PG_VERSION" ]; then
  if [ -z "${POSTGRES_PASSWORD:-}" ] && [ "${POSTGRES_HOST_AUTH_METHOD:-}" != "trust" ]; then
    echo "POSTGRES_PASSWORD is required unless POSTGRES_HOST_AUTH_METHOD=trust" >&2
    exit 1
  fi

  initdb_args="--username=$POSTGRES_USER"
  password_file=""
  if [ -n "${POSTGRES_PASSWORD:-}" ]; then
    password_file="$(mktemp)"
    chmod 600 "$password_file"
    printf '%s\n' "$POSTGRES_PASSWORD" > "$password_file"
    initdb_args="$initdb_args --pwfile=$password_file"
  fi
  if [ "${POSTGRES_HOST_AUTH_METHOD:-}" = "trust" ]; then
    initdb_args="$initdb_args --auth-host=trust --auth-local=trust"
  else
    initdb_args="$initdb_args --auth-host=scram-sha-256 --auth-local=trust"
  fi

  initdb -D "$PGDATA" $initdb_args
  if [ -n "$password_file" ]; then
    rm -f "$password_file"
  fi
  printf "\nlisten_addresses = '*'\n" >> "$PGDATA/postgresql.conf"
  if [ "${POSTGRES_HOST_AUTH_METHOD:-}" = "trust" ]; then
    printf 'host all all all trust\n' >> "$PGDATA/pg_hba.conf"
  else
    printf 'host all all all scram-sha-256\n' >> "$PGDATA/pg_hba.conf"
  fi

  pg_ctl -D "$PGDATA" -o "-c listen_addresses=''" -w start
  if [ "$POSTGRES_DB" != "postgres" ]; then
    createdb --username "$POSTGRES_USER" "$POSTGRES_DB"
  fi
  pg_ctl -D "$PGDATA" -m fast -w stop
fi

exec postgres -D "$PGDATA" "$@"
