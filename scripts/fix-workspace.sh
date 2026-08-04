#!/bin/sh
chmod 777 /workspace 2>/dev/null || true
exec /assets/wrapper "$@"
