#!/bin/sh
set -eu

if [ -z "${MIZAN_APP_PASSWORD:-}" ]; then
  echo "MIZAN_APP_PASSWORD is required to provision the runtime login" >&2
  exit 1
fi

psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set=ON_ERROR_STOP=1 --set=app_password="$MIZAN_APP_PASSWORD" <<'SQL'
ALTER ROLE mizan_app LOGIN PASSWORD :'app_password';
SQL
