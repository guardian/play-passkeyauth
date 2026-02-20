#!/bin/bash
# Quick start script for the example application

cd "$(dirname "$0")/.." || exit
echo "Starting Play Passkey Auth example..."
echo "Open http://localhost:9000 in your browser once the server starts"
echo ""
sbt "project example" run
