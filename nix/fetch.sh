# secret-broker-fetch: build one file from values read through ssh-secret-broker.
#
# usage: secret-broker-fetch <path> <owner> <group> <mode> <units> <spec>...
#
#   <units>  space-separated systemd units to restart when the content changes
#            (may be empty)
#   <spec>   KEY=<item>/<field>  one `KEY=value` line of an env file
#            =<item>/<field>     the bare value, as a line of its own
#
# Environment:
#   SECRET_BROKER_HOST         broker host name (required)
#   SECRET_BROKER_VAULT        vault to read from (required)
#   SECRET_BROKER_KNOWN_HOSTS  known_hosts file pinning the broker's key (required)
#   SECRET_BROKER_PORT         default 2222
#   SECRET_BROKER_IDENTITY     default /etc/ssh/ssh_host_ed25519_key
#
# The one rule: a failed fetch never costs a working secret. The new content is
# built in a temp file next to the target and moved into place only when every
# value was read. On any failure the target is left exactly as it was and the
# exit status is non-zero.

if [ "$#" -lt 6 ]; then
  echo "usage: secret-broker-fetch <path> <owner> <group> <mode> <units> <spec>..." >&2
  exit 64
fi

path=$1 owner=$2 group=$3 mode=$4 units=$5
shift 5

host=${SECRET_BROKER_HOST:?}
vault=${SECRET_BROKER_VAULT:?}
known_hosts=${SECRET_BROKER_KNOWN_HOSTS:?}
port=${SECRET_BROKER_PORT:-2222}
identity=${SECRET_BROKER_IDENTITY:-/etc/ssh/ssh_host_ed25519_key}

# -F none: nothing in the system or user ssh config can add an identity, a
# proxy or a looser host key policy. The user name is ignored by the broker.
read_value() {
  ssh -F none -p "$port" \
    -i "$identity" -o IdentitiesOnly=yes \
    -o BatchMode=yes -o ConnectTimeout=5 \
    -o UserKnownHostsFile="$known_hosts" -o StrictHostKeyChecking=yes \
    "broker@$host" read "$vault/$1"
}

# ssh exits 255 when it could not connect at all, which is what a broker still
# starting at boot looks like. Only that is worth waiting for: a denial (1) or a
# backend error (2) will not change in ten seconds.
read_retrying() {
  local n=0 rc
  while true; do
    rc=0
    read_value "$1" || rc=$?
    n=$((n + 1))
    if [ "$rc" -ne 255 ] || [ "$n" -ge 6 ]; then
      return "$rc"
    fi
    sleep 2
  done
}

mkdir -p "$(dirname "$path")"
tmp=$(mktemp "$path.XXXXXX")
trap 'rm -f "$tmp"' EXIT
chmod 0600 "$tmp"

for spec in "$@"; do
  key=${spec%%=*}
  ref=${spec#*=}
  if ! value=$(read_retrying "$ref"); then
    echo "secret-broker: could not read $ref; $path left as it was" >&2
    exit 1
  fi
  if [ -z "$value" ]; then
    echo "secret-broker: $ref is empty; $path left as it was" >&2
    exit 1
  fi
  if [ -n "$key" ]; then
    # One line per variable, written as-is: the format systemd's
    # EnvironmentFile and docker's env_file agree on for plain tokens.
    case $value in
      *$'\n'*)
        echo "secret-broker: $ref has several lines, which an env file cannot hold" >&2
        exit 1
        ;;
    esac
    printf '%s=%s\n' "$key" "$value" >> "$tmp"
  else
    printf '%s\n' "$value" >> "$tmp"
  fi
done

chown "$owner:$group" "$tmp"
chmod "$mode" "$tmp"

if [ -e "$path" ] && cmp -s "$tmp" "$path"; then
  chown "$owner:$group" "$path"
  chmod "$mode" "$path"
  echo "secret-broker: $path is up to date"
  exit 0
fi

mv -f "$tmp" "$path"
echo "secret-broker: $path updated"

# A running consumer still has the old value. try-restart leaves a stopped unit
# alone, and --no-block matters at boot: the consumer is queued behind the unit
# running this script, and waiting for it here would deadlock.
for unit in $units; do
  systemctl try-restart --no-block "$unit"
done
