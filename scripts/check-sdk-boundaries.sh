#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

tree=$(cargo tree -p daimon-sdk-embedded --edges normal --depth 1 --locked --offline)
if [[ $(printf '%s\n' "$tree" | wc -l | tr -d ' ') != 2 ]] \
  || ! printf '%s\n' "$tree" | rg -q 'daimon-harness'; then
  printf '%s\n' "$tree" >&2
  echo 'Daimon embedded SDK escaped its harness-only closure' >&2
  exit 1
fi

echo 'Daimon embedded SDK dependency closure verified'

metadata=$(cargo metadata --no-deps --format-version 1 --locked --offline)

direct_dependencies() {
  local package=$1
  printf '%s\n' "$metadata" | node -e '
    let input = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", chunk => input += chunk);
    process.stdin.on("end", () => {
      const pkg = JSON.parse(input).packages.find(candidate => candidate.name === process.argv[1]);
      if (!pkg) process.exit(2);
      process.stdout.write(pkg.dependencies
        .filter(dependency => dependency.kind === null)
        .map(dependency => dependency.name)
        .sort()
        .join(","));
    });
  ' "$package"
}

expect_dependencies() {
  local package=$1
  local expected=$2
  local actual
  actual=$(direct_dependencies "$package")
  [[ "$actual" == "$expected" ]] || {
    echo "$package production dependencies: $actual" >&2
    echo "$package expected production dependencies: $expected" >&2
    exit 1
  }
}

expect_dependencies daimon-protocol ''
expect_dependencies daimon-host 'daimon-protocol'
expect_dependencies daimon-client 'daimon-protocol,daimon-wire'
expect_dependencies daimon-service 'daimon-harness,daimon-host,daimon-protocol,sha2'
expect_dependencies daimon-wire 'daimon-protocol'
expect_dependencies daimon-local-daemon 'daimon-client,daimon-host,daimon-protocol,daimon-service,daimon-wire'
echo 'Daimon native service dependency direction verified'

expect_dependencies daimon-aegis 'aegis-client,aegis-protocol,daimon-host,daimon-protocol'
echo 'Daimon Aegis adapter public-client dependency closure verified'

expect_dependencies daimon-process 'base64,serde_json,sha2'
echo 'Daimon provider process isolation dependency closure verified'

expect_dependencies daimon-process-boundary 'base64,processkit,serde,serde_json,tokio,tokio-util'
echo 'Daimon terminal process-group boundary dependency closure verified'

expect_dependencies daimon-acp 'daimon-host,daimon-process,daimon-protocol,serde_json,sha2'
echo 'Daimon ACP adapter dependency closure verified'

expect_dependencies daimon-agent-router 'daimon-host,daimon-protocol'
echo 'Daimon mixed agent-provider router dependency closure verified'

expect_dependencies daimon-claude 'daimon-host,daimon-process,daimon-protocol,serde_json,sha2'
echo 'Daimon Claude stream-JSON adapter dependency closure verified'

expect_dependencies daimon-chronos 'chronos-client,chronos-protocol,daimon-host,daimon-protocol'
echo 'Daimon Chronos adapter public-client dependency closure verified'

expect_dependencies daimon-checkpoint 'daimon-host,daimon-protocol,keystone-codec,keystone-storage'
echo 'Daimon checkpoint mechanism dependency closure verified'

expect_dependencies daimon-local 'daimon-checkpoint,keystone-storage-directory'
echo 'Daimon local storage composition boundary verified'

expect_dependencies daimon-openai-local 'daimon-host,daimon-protocol,serde,serde_json,sha2'
echo 'Daimon OpenAI-compatible adapter dependency closure verified'

expect_dependencies daimon-dendrite 'daimon-host,daimon-protocol,serde,serde_json,sha2'
echo 'Daimon Dendrite adapter dependency closure verified'

expect_dependencies daimon-local-model 'aegis-client,aegis-local-daemon,aegis-protocol,aegis-wire,chronos-client,chronos-protocol,chronos-wire,daimon-aegis,daimon-checkpoint,daimon-chronos,daimon-dendrite,daimon-harness,daimon-host,daimon-local,daimon-local-daemon,daimon-openai-local,daimon-protocol,daimon-service,daimon-wire,serde,serde_json,sha2'
echo 'Daimon local model composition dependency closure verified'

expect_dependencies daimon-local-agent 'aegis-client,aegis-local-daemon,aegis-protocol,aegis-wire,chronos-client,chronos-protocol,chronos-wire,daimon-acp,daimon-aegis,daimon-agent-router,daimon-checkpoint,daimon-chronos,daimon-claude,daimon-harness,daimon-host,daimon-local,daimon-local-daemon,daimon-process,daimon-protocol,daimon-service,daimon-wire,serde,serde_json,sha2'
echo 'Daimon local agent composition dependency closure verified'
