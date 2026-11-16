#!/bin/sh
set -eu

[ "$#" -eq 11 ] || exit 20
[ "$1" = "--output-format" ] || exit 21
[ "$2" = "stream-json" ] || exit 22
[ "$3" = "--verbose" ] || exit 23
[ "$4" = "--input-format" ] || exit 24
[ "$5" = "stream-json" ] || exit 25
[ "$6" = "--permission-prompt-tool" ] || exit 26
[ "$7" = "stdio" ] || exit 27
[ "$8" = "--permission-mode" ] || exit 28
[ "$9" = "default" ] || exit 29
mode="${10}"
expected_workspace="${11}"
permission_cancelled=0

[ "${CLAUDE_CODE_SDK_READS_SESSION_STATE:-}" = "1" ] || exit 30
[ -z "${DAIMON_CLAUDE_MUST_NOT_LEAK:-}" ] || exit 31
[ "$(pwd)" = "$expected_workspace" ] || exit 33
if [ "$mode" = "environment" ]; then
  [ -n "${PATH:-}" ] || exit 42
  [ -z "${HOME:-}" ] || exit 43
fi

while IFS= read -r line; do
  case "$line" in
    *'"subtype":"initialize"'*)
      printf '%s\n' '{"type":"control_response","response":{"subtype":"success","request_id":"daimon-initialize-1","response":{"commands":[],"output_style":"default"}}}'
      ;;
    *'"type":"user"'*)
      case "$mode" in
        stream)
          printf '%s\n' '{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"first slice"}]},"session_id":"fixture"}'
          /bin/sleep 0.08
          printf '%s\n' '{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"second slice"}]},"session_id":"fixture"}'
          printf '%s\n' '{"type":"result","subtype":"success","is_error":false,"result":"done","usage":{"input_tokens":3,"output_tokens":4},"session_id":"fixture"}'
          ;;
        permission)
          printf '%s\n' '{"type":"control_request","request_id":"permission-1","request":{"subtype":"can_use_tool","tool_name":"Bash","input":{"command":"mix test"},"tool_use_id":"tool-1","title":"Run the test suite"}}'
          ;;
        cancel)
          printf '%s\n' '{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"started"}]},"session_id":"fixture"}'
          ;;
        cancel_race)
          printf '%s\n' '{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"started"}]},"session_id":"fixture"}'
          /bin/sleep 0.05
          printf '%s\n' '{"type":"result","subtype":"success","is_error":false,"result":"done","session_id":"fixture"}'
          ;;
        exit_after_prompt)
          exit 41
          ;;
        context)
          case "$line" in
            *'"client_composed":true'*'daimon-context kind=dendrite-grounding'*'ambient expertise'*)
              printf '%s\n' '{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"grounded"}]},"session_id":"fixture"}'
              printf '%s\n' '{"type":"result","subtype":"success","is_error":false,"result":"done","session_id":"fixture"}'
              ;;
            *) exit 32 ;;
          esac
          ;;
        malformed)
          printf '%s\n' '{"type":"mystery","payload":{}}'
          ;;
        report_claude)
          printf '%s\n' '{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"{\"schema\":\"moira.member-response.v1\",\"claims\":[{\"kind\":\"normative\",\"statement\":\"Claude rigor reviewer retained the constraint\",\"evidence_digests\":[\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"],\"dissent_digests\":[]}] }"}]},"session_id":"fixture"}'
          printf '%s\n' '{"type":"result","subtype":"success","is_error":false,"result":"done","session_id":"fixture"}'
          ;;
      esac
      ;;
    *'"request_id":"permission-1"'*'"behavior":"allow"'*'"command":"mix test"'*)
      printf '%s\n' '{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"permission accepted"}]},"session_id":"fixture"}'
      printf '%s\n' '{"type":"result","subtype":"success","is_error":false,"result":"done","session_id":"fixture"}'
      ;;
    *'"request_id":"permission-1"'*'"behavior":"deny"'*'"interrupt":true'*)
      permission_cancelled=1
      ;;
    *'"subtype":"interrupt"'*)
      if [ "$mode" = "permission" ]; then
        [ "$permission_cancelled" -eq 1 ] || exit 34
      fi
      printf '%s\n' '{"type":"control_response","response":{"subtype":"success","request_id":"daimon-interrupt-2","response":{}}}'
      printf '%s\n' '{"type":"result","subtype":"error_during_execution","is_error":true,"errors":["interrupted"],"session_id":"fixture"}'
      ;;
  esac
done
