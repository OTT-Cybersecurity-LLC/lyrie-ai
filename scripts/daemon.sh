#!/bin/bash
# Lyrie Agent Daemon — keeps the bot running forever
# Restarts automatically on crash, handles sleep/wake properly

LYRIE_DIR="/Users/apollogroup/.openclaw/workspace/lyrie-agent"
BUN="/Users/apollogroup/.bun/bin/bun"
LOG="/tmp/lyrie-agent.log"
ERRLOG="/tmp/lyrie-agent-error.log"

export HOME="/Users/apollogroup"
export PATH="/Users/apollogroup/.bun/bin:/usr/local/bin:/usr/bin:/bin"

cd "$LYRIE_DIR"

while true; do
    echo "[$(date)] Starting Lyrie Agent..." >> "$LOG"
    
    # Run Lyrie Agent
    "$BUN" run scripts/start-all.ts >> "$LOG" 2>> "$ERRLOG"
    
    EXIT_CODE=$?
    echo "[$(date)] Lyrie Agent exited with code $EXIT_CODE. Restarting in 5 seconds..." >> "$LOG"
    
    # Wait before restart to prevent rapid restart loops
    sleep 5
done
