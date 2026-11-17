#!/bin/sh
set -eu

mode="${1:-stream}"
fixture_path="${2:-}"

if [ "$mode" = "sandbox_stream" ] || [ "$mode" = "sandbox_file_read" ] || [ "$mode" = "sandbox_terminal" ]; then
  forbidden_path="${2:?forbidden path required}"
  if printf '%s' forbidden > "$forbidden_path"; then
    exit 44
  fi
  if [ "$mode" = "sandbox_file_read" ]; then
    fixture_path="${3:?fixture path required}"
    mode="file_read"
  elif [ "$mode" = "sandbox_terminal" ]; then
    fixture_path="${3:?workspace path required}"
    mode="terminal"
  else
    mode="stream"
  fi
fi

if [ "$mode" = "environment" ]; then
  [ -n "${PATH:-}" ] || exit 42
  [ -z "${HOME:-}" ] || exit 43
fi

while IFS= read -r line; do
  case "$line" in
    *'"method":"initialize"'*)
      case "$mode" in
        client_capabilities)
          case "$line" in
            *'"clientCapabilities":{"fs":{"readTextFile":false,"writeTextFile":false},"terminal":false}'*) ;;
            *) exit 45 ;;
          esac
          ;;
        file_read|file_read_delayed)
          case "$line" in
            *'"clientCapabilities":{"fs":{"readTextFile":true,"writeTextFile":false},"terminal":false}'*) ;;
            *) exit 46 ;;
          esac
          ;;
        terminal|terminal_cancel)
          case "$line" in
            *'"clientCapabilities":{"fs":{"readTextFile":false,"writeTextFile":false},"terminal":true}'*) ;;
            *) exit 48 ;;
          esac
          ;;
      esac
      if [ "$mode" = "agent_auth" ] || [ "$mode" = "agent_auth_error" ]; then
        printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1,"agentCapabilities":{"sessionCapabilities":{"close":{}}},"authMethods":[{"id":"fixture-login","name":"Fixture login","type":"agent"}]}}'
      elif [ "$mode" = "missing_jsonrpc" ]; then
        printf '%s\n' '{"id":1,"result":{"protocolVersion":1}}'
      elif [ "$mode" = "ambiguous_response" ]; then
        printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1},"error":{"code":-32603,"message":"ambiguous"}}'
      elif [ "$mode" = "unexpected_initialize_response" ]; then
        printf '%s\n' '{"jsonrpc":"2.0","id":99,"result":{}}'
        printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1}}'
      elif [ "$mode" = "terminal_auth" ]; then
        printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1,"agentCapabilities":{"sessionCapabilities":{"close":{}}},"authMethods":[{"id":"fixture-login","name":"Fixture login","type":"terminal","args":[],"env":{}}]}}'
      elif [ "$mode" = "duplicate_auth" ]; then
        printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1,"agentCapabilities":{"sessionCapabilities":{"close":{}}},"authMethods":[{"id":"fixture-login","name":"Agent login","type":"agent"},{"id":"fixture-login","name":"Terminal login","type":"terminal","args":[],"env":{}}]}}'
      elif [ "$mode" = "false_capabilities" ]; then
        printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1,"agentCapabilities":{"loadSession":false,"sessionCapabilities":{"resume":null,"close":null,"modes":{},"models":{}}}}}'
      elif [ "$mode" = "malformed_capabilities" ]; then
        printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1,"agentCapabilities":{"loadSession":"true","sessionCapabilities":{"resume":true,"close":false}}}}'
      elif [ "$mode" = "advertised_capabilities" ] || [ "$mode" = "resume" ] || [ "$mode" = "resume_error" ]; then
        printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1,"agentCapabilities":{"loadSession":true,"sessionCapabilities":{"resume":{},"close":{}}}}}'
      else
        printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1,"agentCapabilities":{"sessionCapabilities":{"close":{}}}}}'
      fi
      ;;
    *'"method":"authenticate"'*)
      case "$mode" in
        agent_auth|agent_auth_error) ;;
        *) exit 50 ;;
      esac
      case "$line" in
        *'"id":2'*'"params":{"methodId":"fixture-login"}'*) ;;
        *) exit 51 ;;
      esac
      if [ "$mode" = "agent_auth_error" ]; then
        printf '%s\n' '{"jsonrpc":"2.0","id":2,"error":{"code":-32000,"message":"authentication refused"}}'
      else
        printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{}}'
      fi
      ;;
    *'"method":"session/new"'*)
      if [ "$mode" = "resume_error" ]; then
        exit 54
      elif [ "$mode" = "agent_auth" ]; then
        printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"sessionId":"fixture-session"}}'
      elif [ "$mode" = "false_capabilities" ]; then
        printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"sessionId":"fixture-session","modes":null,"models":null}}'
      elif [ "$mode" = "malformed_capabilities" ]; then
        printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"sessionId":"fixture-session","modes":{},"models":{}}}'
      elif [ "$mode" = "advertised_capabilities" ]; then
        printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"sessionId":"fixture-session","modes":{"currentModeId":"default","availableModes":[{"id":"default","name":"Default"}]},"models":{"currentModelId":"default","availableModels":[{"modelId":"default","name":"Default"}]}}}'
      else
        printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"sessionId":"fixture-session"}}'
      fi
      ;;
    *'"method":"session/resume"'*)
      [ "$mode" = "resume" ] || [ "$mode" = "resume_error" ] || exit 52
      case "$line" in
        *'"mcpServers":[]'*'"sessionId":"fixture-session"'*) ;;
        *) exit 53 ;;
      esac
      if [ "$mode" = "resume_error" ]; then
        printf '%s\n' '{"jsonrpc":"2.0","id":2,"error":{"code":-32600,"message":"no rollout found"}}'
      else
        printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{}}'
      fi
      ;;
    *'"method":"session/prompt"'*)
      case "$mode" in
        stream|controlled_stream)
          printf '%s\n' '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"fixture-session","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"first slice"}}}}'
          if [ "$mode" = "controlled_stream" ]; then
            while [ ! -f "$fixture_path.gate" ]; do sleep 0.01; done
          else
            sleep 0.08
          fi
          printf '%s\n' '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"fixture-session","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"second slice"}}}}'
          printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"stopReason":"end_turn"}}'
          if [ "$mode" = "controlled_stream" ]; then
            : > "$fixture_path.emitted"
          fi
          ;;
        resume)
          printf '%s\n' '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"fixture-session","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"resumed session"}}}}'
          printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"stopReason":"end_turn"}}'
          ;;
        permission)
          printf '%s\n' '{"jsonrpc":"2.0","id":"permission-1","method":"session/request_permission","params":{"sessionId":"fixture-session","toolCall":{"toolCallId":"call-1","title":"Run tests","kind":"execute"},"options":[{"optionId":"allow-once","name":"Allow once","kind":"allow_once"},{"optionId":"reject-once","name":"Reject","kind":"reject_once"}]}}'
          ;;
        cancel)
          printf '%s\n' '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"fixture-session","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"started"}}}}'
          ;;
        cancel_race|controlled_cancel_race)
          printf '%s\n' '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"fixture-session","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"started"}}}}'
          if [ "$mode" = "controlled_cancel_race" ]; then
            while [ ! -f "$fixture_path.gate" ]; do sleep 0.01; done
          else
            sleep 0.05
          fi
          printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"stopReason":"end_turn"}}'
          if [ "$mode" = "controlled_cancel_race" ]; then
            : > "$fixture_path.emitted"
          fi
          ;;
        silent)
          :
          ;;
        unexpected_prompt_response)
          printf '%s\n' '{"jsonrpc":"2.0","id":99,"result":{}}'
          ;;
        foreign_session_update)
          printf '%s\n' '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"foreign-session","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"must not cross sessions"}}}}'
          printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"stopReason":"end_turn"}}'
          ;;
        update_as_request)
          printf '%s\n' '{"jsonrpc":"2.0","id":"not-a-notification","method":"session/update","params":{"sessionId":"fixture-session","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"must not be admitted"}}}}'
          printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"stopReason":"end_turn"}}'
          ;;
        non_text_with_text_field)
          printf '%s\n' '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"fixture-session","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"image","mimeType":"image/png","data":"AA==","text":"must not be reinterpreted"}}}}'
          printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"stopReason":"end_turn"}}'
          ;;
        malformed_structured_updates)
          printf '%s\n' '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"fixture-session","update":{"sessionUpdate":"tool_call","title":"missing identity"}}}'
          printf '%s\n' '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"fixture-session","update":{"sessionUpdate":"plan","entries":{"not":"an array"}}}}'
          printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"stopReason":"end_turn"}}'
          ;;
        exit_after_prompt)
          exit 41
          ;;
        context)
          case "$line" in
            *'daimon-context kind=dendrite-grounding'*'ambient expertise'*)
              printf '%s\n' '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"fixture-session","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"grounded"}}}}'
              printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"stopReason":"end_turn"}}'
              ;;
            *) exit 31 ;;
          esac
          ;;
        file_read)
          [ -n "$fixture_path" ] || exit 47
          printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":\"read-1\",\"method\":\"fs/read_text_file\",\"params\":{\"sessionId\":\"fixture-session\",\"path\":\"$fixture_path\",\"line\":1,\"limit\":1}}"
          ;;
        file_read_delayed)
          [ -n "$fixture_path" ] || exit 47
          sleep 0.08
          printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":\"read-1\",\"method\":\"fs/read_text_file\",\"params\":{\"sessionId\":\"fixture-session\",\"path\":\"$fixture_path\",\"line\":1,\"limit\":1}}"
          ;;
        terminal|terminal_cancel)
          terminal_cwd="${fixture_path:-$(pwd)}"
          printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":\"terminal-create\",\"method\":\"terminal/create\",\"params\":{\"sessionId\":\"fixture-session\",\"command\":\"printf\",\"args\":[\"ok\"],\"env\":[{\"name\":\"MODE\",\"value\":\"test\"}],\"cwd\":\"$terminal_cwd\",\"outputByteLimit\":64}}"
          ;;
        report_acp)
          printf '%s\n' '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"fixture-session","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"{\"schema\":\"moira.member-response.v1\",\"claims\":[{\"kind\":\"empirical\",\"statement\":\"ACP historian retained the chronology\",\"evidence_digests\":[\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"],\"dissent_digests\":[]}] }"}}}}'
          printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"stopReason":"end_turn"}}'
          ;;
      esac
      ;;
    *'"id":"read-1"'*'"result":{"content":"[package]\n"}'*)
      printf '%s\n' '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"fixture-session","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"file grounded"}}}}'
      printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"stopReason":"end_turn"}}'
      ;;
    *'"id":"terminal-create"'*'"terminalId":"'*)
      terminal_id=${line#*\"terminalId\":\"}
      terminal_id=${terminal_id%%\"*}
      [ -n "$terminal_id" ] || exit 49
      if [ "$mode" = "terminal" ]; then
        printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":\"terminal-output\",\"method\":\"terminal/output\",\"params\":{\"sessionId\":\"fixture-session\",\"terminalId\":\"$terminal_id\"}}"
      fi
      ;;
    *'"id":"terminal-output"'*'"output":"ok"'*|*'"id":"terminal-output"'*'"output":"ok\n"'*)
      printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":\"terminal-wait\",\"method\":\"terminal/wait_for_exit\",\"params\":{\"sessionId\":\"fixture-session\",\"terminalId\":\"$terminal_id\"}}"
      ;;
    *'"id":"terminal-wait"'*'"exitCode":0'*)
      printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":\"terminal-kill\",\"method\":\"terminal/kill\",\"params\":{\"sessionId\":\"fixture-session\",\"terminalId\":\"$terminal_id\"}}"
      ;;
    *'"id":"terminal-kill"'*'"result":null'*)
      printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":\"terminal-release\",\"method\":\"terminal/release\",\"params\":{\"sessionId\":\"fixture-session\",\"terminalId\":\"$terminal_id\"}}"
      ;;
    *'"id":"terminal-release"'*'"result":null'*)
      printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"stopReason":"end_turn"}}'
      ;;
    *'"id":"permission-1"'*'"optionId":"allow-once"'*)
      printf '%s\n' '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"fixture-session","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"permission accepted"}}}}'
      printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"stopReason":"end_turn"}}'
      ;;
    *'"method":"session/cancel"'*)
      printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"stopReason":"cancelled"}}'
      ;;
    *'"method":"session/close"'*)
      if [ "$mode" = "advertised_capabilities" ]; then
        printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{}}'
      else
        printf '%s\n' '{"jsonrpc":"2.0","id":4,"result":{}}'
      fi
      exit 0
      ;;
  esac
done
