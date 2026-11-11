#!/usr/bin/env bash
# Self-test for leak-check.sh: plants fake leaks in a throwaway repository and checks each is found, that no value is ever printed,
# that clean text and allowed exceptions pass, and that commit identities are judged correctly. Run in CI.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
T="$(mktemp -d)"; H="$(mktemp -d)"; trap 'rm -rf "$T" "$H"' EXIT
fail=0; ok() { echo "ok   $1"; }; bad() { echo "FAIL $1"; fail=1; }
cd "$T" && git init -q . && git config user.name t && git config user.email "1+t@users.noreply.github.com"
export HOME="$H"                                              # outside the repository: no personal name list leaks into the test
run() { "$HERE/leak-check.sh" "$@" 2>&1; }

# 1. every rule fires, with the value kept out of the output
declare -A plant=(
  ["free-mail address"]="contact: someone.private@gmail.com"
  ["private network address"]="server at 192.168.7.15 and 10.1.2.3"
  ["global IPv6 address"]="prefix 2001:8003:9423:abcd::1"
  ["secret-shaped string"]="token ghp_abcdefghijklmnopqrstuvwxyz0123456789AB"
  ["32-character hex id"]="zone 0123456789abcdef0123456789abcdef"
  ["your own name list"]="the box is called secrethostname"
)
mkdir -p "$HOME/.config/leakcheck"; echo 'secrethostname' > "$HOME/.config/leakcheck/names"
for rule in "${!plant[@]}"; do
    rm -f ./*.txt; printf '%s\n' "${plant[$rule]}" > f.txt; git add f.txt
    out="$(run --files-only)"; rc=$?
    if [ $rc -eq 1 ] && printf '%s' "$out" | grep -q "\[$rule\]"; then ok "finds: $rule"; else bad "did not find: $rule (rc=$rc)"; fi
    for secret in someone.private 192.168.7.15 2001:8003 ghp_abcdef 0123456789abcdef0123 secrethostname; do
        printf '%s' "$out" | grep -q "$secret" && bad "the output printed a value ($secret)"
    done
done

# 2. clean text, documentation addresses and placeholders pass
rm -f ./*.txt; printf '%s\n' "mail you@example.com" "documentation 203.0.113.9 and 2001:db8::1" "placeholder aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" "regex ^192\\.168\\." > f.txt; git add f.txt
out="$(run --files-only)"; [ $? -eq 0 ] && ok "clean text and placeholders pass" || bad "false positive: $out"

# 3. an allowed exception is honoured
rm -f ./*.txt; echo "range 192.168.0.0/16 is private" > f.txt; echo '^f\.txt:.*192\.168\.0\.0/16' > .leakcheck-allow; git add -A
out="$(run --files-only)"; [ $? -eq 0 ] && ok "allow-list exception works" || bad "allow-list ignored: $out"
rm -f .leakcheck-allow f.txt; rm -f "$HOME/.config/leakcheck/names"; git add -A

# 4. commit identities: a noreply author passes, a free-mail author fails
git add -A; git commit -q -m base --allow-empty
base="$(git rev-parse HEAD)"
git -c user.email="1+t@users.noreply.github.com" commit -q --allow-empty -m good
out="$(run --range "$base..HEAD")"; [ $? -eq 0 ] && ok "noreply commit passes" || bad "noreply commit rejected: $out"
git -c user.email="someone.private@gmail.com" commit -q --allow-empty -m leaky
out="$(run --range "$base..HEAD")"; rc=$?
if [ $rc -eq 1 ] && printf '%s' "$out" | grep -q "author or committer address is not a noreply address"; then ok "a real address as commit author fails"; else bad "leaky commit not caught (rc=$rc)"; fi
printf '%s' "$out" | grep -q "someone.private" && bad "the output printed the commit address"

[ $fail -eq 0 ] && echo "ALL OK" || { echo "SELF-TEST FAILED"; exit 1; }
