#!/bin/bash
set -e

# Ensure output directories exist
mkdir -p proto/triage
mkdir -p ml/api

echo "Compiling protobuf for Go..."
if command -v protoc &> /dev/null; then
    protoc --go_out=. --go_opt=paths=source_relative \
           --go-grpc_out=. --go-grpc_opt=paths=source_relative \
           proto/triage.proto
    echo "Go stubs compiled successfully."
else
    echo "Warning: protoc command not found. Skipping Go stub compilation."
fi

echo "Compiling protobuf for Python..."
if python3 -c "import grpc_tools" &> /dev/null; then
    python3 -m grpc_tools.protoc -I. \
            --python_out=. \
            --grpc_python_out=. \
            proto/triage.proto
    echo "Python stubs compiled successfully."
else
    echo "Warning: grpc_tools.protoc not found in Python. Skipping Python stub compilation."
fi
