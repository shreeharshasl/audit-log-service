#!/usr/bin/env bash
# Source this before building: `source scripts/env.sh`
#
# JAVA_HOME is pinned explicitly because /usr/libexec/java_home fails on this
# machine even though several JDKs are installed, which leaves bare `java`
# unresolvable and makes Maven pick up whatever happens to be first on PATH.

CORRETTO_21="/Library/Java/JavaVirtualMachines/amazon-corretto-21.jdk/Contents/Home"
TEMURIN_21="/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home"

if [ -x "$CORRETTO_21/bin/java" ]; then
  export JAVA_HOME="$CORRETTO_21"
elif [ -x "$TEMURIN_21/bin/java" ]; then
  export JAVA_HOME="$TEMURIN_21"
else
  echo "No JDK 21 found. Install one, for example: brew install --cask corretto@21" >&2
  return 1 2>/dev/null || exit 1
fi

export PATH="$JAVA_HOME/bin:/opt/homebrew/opt/postgresql@16/bin:$PATH"

export AUDIT_DB_URL="${AUDIT_DB_URL:-jdbc:postgresql://localhost:5432/auditlog}"
export AUDIT_DB_USER="${AUDIT_DB_USER:-$(whoami)}"
export AUDIT_BOOTSTRAP_API_KEY="${AUDIT_BOOTSTRAP_API_KEY:-dev-local-key}"

echo "JAVA_HOME=$JAVA_HOME"
echo "java: $(java -version 2>&1 | head -1)"
