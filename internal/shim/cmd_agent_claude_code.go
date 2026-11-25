package shim

import (
	"context"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/agentclaude"
	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
)

// runAgentClaudeCode is `sp agent-claude-code collect`: the Go implementation of the agent-claude-code collector
// (internal/collectors/agentclaude).
func runAgentClaudeCode(ctx context.Context, env Env, args []string) int {
	return agentclaude.Main(ctx, collectorEnv(env), args)
}

// collectorEnv is what a Go collector reads from the process.
func collectorEnv(env Env) rundoc.Env {
	return rundoc.Env{Getenv: env.Getenv, Stderr: env.Stderr, Now: time.Now}
}
