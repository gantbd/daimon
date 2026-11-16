.PHONY: check check-public-source check-local-model-config check-peer-profiles check-sdk-boundaries fmt lint test doc qualify-agent-router qualify-agent-router-live qualify-agent-router-live-ensemble qualify-local-agent qualify-chronos-attempt qualify-openai-live qualify-claude-transport qualify-claude-live qualify-gemini-transport qualify-acp-reattach-live qualify-acp-permission-live qualify-acp-tck

check: check-public-source check-sdk-boundaries check-local-model-config fmt lint test doc check-peer-profiles

check-public-source:
	bash scripts/check-public-source.sh

check-local-model-config:
	cargo run -p daimon-local-model --locked --offline -- --check config/local-model.example.json
	DENDRITE_TOKEN=example-token cargo run -p daimon-local-model --locked --offline -- --check config/local-model-dendrite.example.json
	cargo run -p daimon-local-agent --locked --offline -- --check config/local-agent.example.json

check-peer-profiles: qualify-agent-router qualify-local-agent qualify-chronos-attempt

check-sdk-boundaries:
	./scripts/check-sdk-boundaries.sh

fmt:
	cargo fmt --all -- --check

lint:
	cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings

test:
	cargo test --workspace --all-targets --locked --offline

doc:
	cargo test --workspace --doc --locked --offline
	RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked --offline

qualify-chronos-attempt:
	cargo fmt --manifest-path qualification/chronos-attempt/Cargo.toml -- --check
	cargo clippy --manifest-path qualification/chronos-attempt/Cargo.toml --all-targets --locked --offline -- -D warnings
	cargo test --manifest-path qualification/chronos-attempt/Cargo.toml --all-targets --locked --offline

qualify-agent-router:
	cargo fmt -p daimon-agent-router -- --check
	cargo clippy -p daimon-agent-router --all-targets --locked --offline -- -D warnings
	cargo test -p daimon-agent-router --all-targets --locked --offline

qualify-agent-router-live:
	@test -n "$(DAIMON_ROUTER_ACP_PROGRAM)" || (echo 'DAIMON_ROUTER_ACP_PROGRAM is required' >&2; exit 2)
	@test -n "$(DAIMON_ROUTER_CLAUDE_PROGRAM)" || (echo 'DAIMON_ROUTER_CLAUDE_PROGRAM is required' >&2; exit 2)
	DAIMON_ROUTER_ACP_PROGRAM='$(DAIMON_ROUTER_ACP_PROGRAM)' DAIMON_ROUTER_ACP_ARGS='$(DAIMON_ROUTER_ACP_ARGS)' DAIMON_ROUTER_ACP_ENV='$(DAIMON_ROUTER_ACP_ENV)' DAIMON_ROUTER_ACP_AUTH_METHOD='$(DAIMON_ROUTER_ACP_AUTH_METHOD)' DAIMON_ROUTER_CLAUDE_PROGRAM='$(DAIMON_ROUTER_CLAUDE_PROGRAM)' DAIMON_ROUTER_CLAUDE_ARGS='$(DAIMON_ROUTER_CLAUDE_ARGS)' DAIMON_ROUTER_CLAUDE_ENV='$(DAIMON_ROUTER_CLAUDE_ENV)' cargo test -p daimon-agent-router --test live_provider_router genuine_acp_and_claude_sessions_share_one_provider_neutral_router --locked --offline -- --ignored --exact --nocapture

qualify-agent-router-live-ensemble:
	@test "$(DAIMON_ROUTER_ENABLE_PROMPTS)" = "1" || (echo 'DAIMON_ROUTER_ENABLE_PROMPTS=1 is required to authorize one turn per provider' >&2; exit 2)
	@test -x "$(DAIMON_ROUTER_ACP_PROGRAM)" || (echo 'DAIMON_ROUTER_ACP_PROGRAM must name an executable ACP agent' >&2; exit 2)
	@test -x "$(DAIMON_ROUTER_CLAUDE_PROGRAM)" || (echo 'DAIMON_ROUTER_CLAUDE_PROGRAM must name an executable Claude command' >&2; exit 2)
	DAIMON_ROUTER_ENABLE_PROMPTS=1 DAIMON_ROUTER_ACP_PROGRAM='$(DAIMON_ROUTER_ACP_PROGRAM)' DAIMON_ROUTER_ACP_ARGS='$(DAIMON_ROUTER_ACP_ARGS)' DAIMON_ROUTER_ACP_ENV='$(DAIMON_ROUTER_ACP_ENV)' DAIMON_ROUTER_ACP_AUTH_METHOD='$(DAIMON_ROUTER_ACP_AUTH_METHOD)' DAIMON_ROUTER_CLAUDE_PROGRAM='$(DAIMON_ROUTER_CLAUDE_PROGRAM)' DAIMON_ROUTER_CLAUDE_ARGS='$(DAIMON_ROUTER_CLAUDE_ARGS)' DAIMON_ROUTER_CLAUDE_ENV='$(DAIMON_ROUTER_CLAUDE_ENV)' cargo test -p daimon-agent-router --test live_provider_router genuine_acp_and_claude_complete_distinct_no_tool_turns_through_router --locked --offline -- --ignored --exact --nocapture

qualify-local-agent:
	cargo fmt -p daimon-local-agent -- --check
	cargo clippy -p daimon-local-agent --all-targets --locked --offline -- -D warnings
	cargo build -p daimon-process-boundary --locked --offline
	cargo test -p daimon-local-agent --all-targets --locked --offline
	DAIMON_PROCESS_BOUNDARY='$(CURDIR)/target/debug/daimon-process-boundary' cargo test -p daimon-local-agent --test process_journey --locked --offline

qualify-openai-live:
	@test -n "$(DAIMON_OPENAI_LIVE_MODEL)" || (echo 'DAIMON_OPENAI_LIVE_MODEL is required' >&2; exit 2)
	DAIMON_OPENAI_LIVE_MODEL='$(DAIMON_OPENAI_LIVE_MODEL)' DAIMON_OPENAI_LIVE_ADDRESS='$(or $(DAIMON_OPENAI_LIVE_ADDRESS),127.0.0.1:11434)' cargo test -p daimon-openai-local live_loopback_provider_returns_attributed_bounded_completion --locked --offline -- --exact --nocapture

qualify-claude-transport:
	@test -n "$(DAIMON_CLAUDE_PROGRAM)" || (echo 'DAIMON_CLAUDE_PROGRAM is required' >&2; exit 2)
	DAIMON_CLAUDE_PROGRAM='$(DAIMON_CLAUDE_PROGRAM)' DAIMON_CLAUDE_ARGS='$(DAIMON_CLAUDE_ARGS)' cargo test -p daimon-claude --test live_provider genuine_claude_initializes_and_closes_without_prompt --locked --offline -- --ignored --exact --nocapture

qualify-claude-live:
	@test "$(DAIMON_CLAUDE_ENABLE_PROMPT)" = "1" || (echo 'DAIMON_CLAUDE_ENABLE_PROMPT=1 is required' >&2; exit 2)
	@test -n "$(DAIMON_CLAUDE_PROGRAM)" || (echo 'DAIMON_CLAUDE_PROGRAM is required' >&2; exit 2)
	DAIMON_CLAUDE_ENABLE_PROMPT=1 DAIMON_CLAUDE_PROGRAM='$(DAIMON_CLAUDE_PROGRAM)' DAIMON_CLAUDE_ARGS='$(DAIMON_CLAUDE_ARGS)' cargo test -p daimon-claude --test live_provider genuine_claude_completes_one_no_tool_prompt --locked --offline -- --ignored --exact --nocapture

qualify-gemini-transport:
	@test -x "$(DAIMON_GEMINI_PROGRAM)" || (echo 'DAIMON_GEMINI_PROGRAM must name an executable Gemini CLI' >&2; exit 2)
	DAIMON_ACP_PROGRAM='$(DAIMON_GEMINI_PROGRAM)' DAIMON_ACP_ARGS='--acp' DAIMON_ACP_ENV='$(or $(DAIMON_GEMINI_ENV),HOME PATH GEMINI_API_KEY GOOGLE_API_KEY GOOGLE_CLOUD_PROJECT GOOGLE_CLOUD_LOCATION)' DAIMON_ACP_AUTH_METHOD='$(DAIMON_GEMINI_AUTH_METHOD)' cargo test -p daimon-acp --test live_provider genuine_provider_negotiates_creates_and_closes_without_prompt --locked --offline -- --ignored --exact --nocapture

qualify-acp-reattach-live:
	@test "$(DAIMON_ACP_ENABLE_REATTACH)" = "1" || (echo 'DAIMON_ACP_ENABLE_REATTACH=1 is required' >&2; exit 2)
	@test "$(DAIMON_ACP_ENABLE_REATTACH_PROMPT)" = "1" || (echo 'DAIMON_ACP_ENABLE_REATTACH_PROMPT=1 is required to authorize one seed model turn' >&2; exit 2)
	@test -x "$(DAIMON_ACP_PROGRAM)" || (echo 'DAIMON_ACP_PROGRAM must name an executable ACP agent' >&2; exit 2)
	DAIMON_ACP_ENABLE_REATTACH=1 DAIMON_ACP_ENABLE_REATTACH_PROMPT=1 DAIMON_ACP_PROGRAM='$(DAIMON_ACP_PROGRAM)' DAIMON_ACP_ARGS='$(DAIMON_ACP_ARGS)' DAIMON_ACP_ENV='$(DAIMON_ACP_ENV)' DAIMON_ACP_AUTH_METHOD='$(DAIMON_ACP_AUTH_METHOD)' cargo test -p daimon-acp --test live_provider genuine_provider_reattaches_idle_session_without_history_replay --locked --offline -- --ignored --exact --nocapture

qualify-acp-permission-live:
	@test "$(DAIMON_ACP_ENABLE_PERMISSION_PROMPT)" = "1" || (echo 'DAIMON_ACP_ENABLE_PERMISSION_PROMPT=1 is required' >&2; exit 2)
	@test -n "$(DAIMON_ACP_PROGRAM)" || (echo 'DAIMON_ACP_PROGRAM is required' >&2; exit 2)
	DAIMON_ACP_ENABLE_PERMISSION_PROMPT=1 DAIMON_ACP_PROGRAM='$(DAIMON_ACP_PROGRAM)' DAIMON_ACP_ARGS='$(DAIMON_ACP_ARGS)' DAIMON_ACP_ENV='$(DAIMON_ACP_ENV)' DAIMON_ACP_AUTH_METHOD='$(DAIMON_ACP_AUTH_METHOD)' cargo test -p daimon-acp --test live_provider genuine_provider_permission_can_be_rejected_without_granting_capability --locked --offline -- --ignored --exact --nocapture

# The upstream TCK drives an ACP agent directly and sends model prompts. It is
# provider evidence complementary to daimon-acp's client-adapter gates, not a
# substitute for them. Pin/install the TCK separately for reproducible results.
qualify-acp-tck:
	@test "$(DAIMON_ACP_TCK_ENABLE_MODEL_SPEND)" = "1" || (echo 'DAIMON_ACP_TCK_ENABLE_MODEL_SPEND=1 is required' >&2; exit 2)
	@test -x "$(DAIMON_ACP_TCK)" || (echo 'DAIMON_ACP_TCK must name an executable pinned acp-tck' >&2; exit 2)
	@test -x "$(DAIMON_ACP_PROGRAM)" || (echo 'DAIMON_ACP_PROGRAM must name an executable ACP agent' >&2; exit 2)
	@test -n "$(DAIMON_ACP_TCK_REPORT)" || (echo 'DAIMON_ACP_TCK_REPORT is required' >&2; exit 2)
	@test -d "$(DAIMON_ACP_TCK_WORKSPACE)" || (echo 'DAIMON_ACP_TCK_WORKSPACE must name an existing scratch directory' >&2; exit 2)
	"$(DAIMON_ACP_TCK)" --protocol-version 1 --agent-cwd "$(DAIMON_ACP_TCK_WORKSPACE)" --timeout 90 --test-timeout 300 --report-json "$(DAIMON_ACP_TCK_REPORT)" -- "$(DAIMON_ACP_PROGRAM)" $(DAIMON_ACP_ARGS)

