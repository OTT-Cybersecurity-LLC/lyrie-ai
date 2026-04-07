#!/bin/bash
# Lyrie Agent — One-line installer
# Usage: curl -fsSL https://lyrie.ai/install.sh | bash

set -e

echo "🛡️  Installing Lyrie Agent..."
echo ""

# Check for required tools
command -v git >/dev/null 2>&1 || { echo "❌ git is required but not installed."; exit 1; }
command -v node >/dev/null 2>&1 || { echo "❌ Node.js is required but not installed."; exit 1; }

# Clone the repo
INSTALL_DIR="${HOME}/.lyrie"
if [ -d "$INSTALL_DIR" ]; then
  echo "📁 Lyrie directory already exists at $INSTALL_DIR"
  echo "   Updating..."
  cd "$INSTALL_DIR" && git pull
else
  echo "📥 Cloning Lyrie Agent..."
  git clone https://github.com/lyrie-ai/lyrie-agent.git "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"

# Install dependencies
echo "📦 Installing dependencies..."
if command -v bun >/dev/null 2>&1; then
  bun install
elif command -v pnpm >/dev/null 2>&1; then
  pnpm install
else
  npm install
fi

echo ""
echo "✅ Lyrie Agent installed successfully!"
echo ""
echo "🛡️  Start Lyrie:"
echo "   cd ~/.lyrie && bun start"
echo ""
echo "📡 Connect channels:"
echo "   lyrie config telegram --token YOUR_BOT_TOKEN"
echo "   lyrie config whatsapp"
echo ""
echo "🔒 The AI that protects while it helps."
echo ""
