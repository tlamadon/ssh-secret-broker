# Runs fetch.sh against a stubbed ssh, systemctl and sleep.
# usage: bash fetch-test.sh <path to fetch.sh>
#
# fetch.sh is run with `-euo pipefail`, as writeShellApplication runs it.
set -u

fetch=$1
T=$(mktemp -d)
export T
mkdir "$T/bin" "$T/out"

# No /usr/bin/env in a Nix build sandbox, so the stubs name bash by its path.
bash_path=$(command -v bash)

{ echo "#!$bash_path"; cat <<'STUB'
echo "ssh $*" >> "$T/calls"
ref=${!#}
case "$MODE" in
  ok) printf '%s' "${VAL:-tok-1}" ;;
  deny) echo "not found or not permitted" >&2; exit 1 ;;
  backend) exit 2 ;;
  down) exit 255 ;;
  empty) exit 0 ;;
  multi) printf 'a\nb' ;;
  flaky)
    n=$(cat "$T/n" 2>/dev/null || echo 0)
    echo $((n + 1)) > "$T/n"
    [ "$n" -lt 2 ] && exit 255
    printf tok-flaky ;;
  second-fails) case "$ref" in */b/*) exit 2 ;; *) printf good ;; esac ;;
esac
STUB
} > "$T/bin/ssh"
printf '#!%s\necho "systemctl $*" >> "$T/calls"\n' "$bash_path" > "$T/bin/systemctl"
printf '#!%s\nexit 0\n' "$bash_path" > "$T/bin/sleep"
chmod +x "$T"/bin/*
PATH=$T/bin:$PATH

export SECRET_BROKER_HOST=broker.test SECRET_BROKER_VAULT=v SECRET_BROKER_KNOWN_HOSTS=/dev/null
file=$T/out/x.env
user=$(id -un) group=$(id -gn)
failures=0

# run <mode> <units> <spec>...   sets $rc
run() {
  local mode=$1 units=$2
  shift 2
  : > "$T/calls"
  rc=0
  MODE=$mode bash -euo pipefail "$fetch" "$file" "$user" "$group" 0400 "$units" "$@" > "$T/log" 2>&1 || rc=$?
}

check() { # check <name> <want rc> <want content, | for newline>
  local got
  got=$( { tr '\n' '|' < "$file"; } 2>/dev/null || true)
  local stray
  stray=$(find "$T/out" -mindepth 1 ! -name x.env | wc -l)
  if [ "$rc" != "$2" ] || [ "$got" != "$3" ] || [ "$stray" != 0 ]; then
    echo "FAIL $1: rc=$rc (want $2) content=[$got] (want [$3]) stray=$stray"
    sed 's/^/    /' "$T/log"
    failures=$((failures + 1))
  else
    echo "ok   $1"
  fi
}

count() { grep -c "$1" "$T/calls" || true; }
expect() { # expect <name> <got> <want>
  if [ "$2" != "$3" ]; then
    echo "FAIL $1: got $2, want $3"
    failures=$((failures + 1))
  else
    echo "ok   $1"
  fi
}

run ok "a.service b.service" CF=item/password
check "first fetch writes the file" 0 "CF=tok-1|"
expect "file mode" "$(stat -c %a "$file")" 400
expect "ssh is pinned and non-interactive" \
  "$(grep -c -- '-F none .*IdentitiesOnly=yes .*BatchMode=yes .*UserKnownHostsFile=/dev/null .*StrictHostKeyChecking=yes broker@broker.test read v/item/password' "$T/calls")" 1

run ok "a.service b.service" CF=item/password
check "unchanged content is left alone" 0 "CF=tok-1|"
expect "no restart when unchanged" "$(count systemctl)" 0

VAL=tok-2 run ok "a.service b.service" CF=item/password
check "rotated value replaces the file" 0 "CF=tok-2|"
expect "every unit restarted on change" "$(count 'systemctl try-restart --no-block')" 2

run deny "a.service" CF=item/password
check "denial keeps the old file" 1 "CF=tok-2|"
expect "denial is not retried" "$(count '^ssh')" 1

run backend "a.service" CF=item/password
check "backend error keeps the old file" 1 "CF=tok-2|"
expect "backend error is not retried" "$(count '^ssh')" 1

run down "a.service" CF=item/password
check "unreachable broker keeps the old file" 1 "CF=tok-2|"
expect "unreachable broker is retried six times" "$(count '^ssh')" 6
expect "no restart on failure" "$(count systemctl)" 0

run empty "a.service" CF=item/password
check "empty value keeps the old file" 1 "CF=tok-2|"

run multi "a.service" CF=item/password
check "multi-line value is refused for an env file" 1 "CF=tok-2|"

run second-fails "a.service" A=a/password B=b/password
check "one failing value means no partial file" 1 "CF=tok-2|"

rm -f "$T/n"
run flaky "a.service" CF=item/password
check "a broker that comes up is waited for" 0 "CF=tok-flaky|"

run ok "" =item/password
check "bare value file" 0 "tok-1|"
expect "no units, no restart" "$(count systemctl)" 0

run multi "" =item/password
check "bare value may span lines" 0 "a|b|"

rm -f "$file"
run down "a.service" CF=item/password
check "no file yet and a failure leaves no file" 1 ""

rc=0
bash -euo pipefail "$fetch" "$file" > "$T/log" 2>&1 || rc=$?
expect "usage error" "$rc" 64

rm -rf "$T"
if [ "$failures" != 0 ]; then
  echo "$failures failed"
  exit 1
fi
echo "all passed"
