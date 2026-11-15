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
# exit status is non-zero:
#   1   a failure that may pass: broker unreachable, backend error, bad value
#   78  a refusal, which trying again will not change: this host's key is not
#       accepted, the broker's host key is not the pinned one, or the item is
#       missing or out of scope. The NixOS unit does not restart on it.
#   64  usage

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

# ssh exits 255 for every failure of its own. A broker still starting at boot
# looks like that and is worth waiting for. A rejected key or a host key
# mismatch looks like that too, and will not change in ten seconds: retrying
# those only delays the failure and fills the broker's audit log with denials.
# A denial (1) or a backend error (2) from the broker is never retried.
read_retrying() {
  local n=0 rc
  while true; do
    rc=0
    read_value "$1" 2> "$err" || rc=$?
    cat "$err" >&2
    n=$((n + 1))
    if [ "$rc" -ne 255 ] || [ "$n" -ge 6 ]; then
      return "$rc"
    fi
    if ssh_refused; then
      return "$rc"
    fi
    sleep 2
  done
}

# Whether the last ssh attempt failed on the keys rather than the connection.
ssh_refused() {
  case $(< "$err") in
    *"Permission denied"* | *"Host key verification failed"*) return 0 ;;
  esac
  return 1
}

mkdir -p "$(dirname "$path")"
tmp=$(mktemp "$path.XXXXXX")
err=$(mktemp) # ssh's stderr for the attempt in progress; never holds a value
trap 'rm -f "$tmp" "$err"' EXIT
chmod 0600 "$tmp"

for spec in "$@"; do
  key=${spec%%=*}
  ref=${spec#*=}
  rc=0
  value=$(read_retrying "$ref") || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "secret-broker: could not read $ref; $path left as it was" >&2
    # The broker answers 1 for "not found or not permitted".
    if [ "$rc" -eq 1 ] || { [ "$rc" -eq 255 ] && ssh_refused; }; then
      exit 78
    fi
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
