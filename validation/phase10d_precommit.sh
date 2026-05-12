#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(pwd)"
REPO_REV="$(git rev-parse HEAD)"
TMPDIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

python3 -m venv "$TMPDIR/venv"
"$TMPDIR/venv/bin/pip" install --quiet pre-commit

cd "$TMPDIR"
git init --quiet
git config user.email "lurkr-smoke@example.invalid"
git config user.name "Lurkr Smoke"
mkdir -p .github/workflows
cp "$REPO_ROOT/fixtures/dangerous_github_project/.github/workflows/dangerous.yml" \
  .github/workflows/
cat > .pre-commit-config.yaml <<EOF
repos:
  - repo: file://$REPO_ROOT
    rev: $REPO_REV
    hooks:
      - id: lurkr
        args: ["--fail-on", "high"]
EOF
git add .
"$TMPDIR/venv/bin/pre-commit" install

set +e
commit_output="$(PATH="$TMPDIR/venv/bin:$PATH" git commit -m "test" 2>&1)"
commit_status=$?
set -e

if [ "$commit_status" -eq 0 ]; then
  echo "FAIL: pre-commit should have blocked commit"
  exit 1
fi

echo "$commit_output" | grep -q "Failed" || {
  echo "FAIL: expected pre-commit failure output"
  exit 1
}

echo "PASS: pre-commit hook blocks high-severity commit"
