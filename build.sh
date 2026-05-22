#!/bin/bash

# Exit on any error
set -e

LIB_DIR="lib"
SRC_DIR="src"
OUT_DIR="build/classes"
JAR_NAME="nuclei-scan-plus.jar"

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

echo "[INFO] Finding source files..."
find "$SRC_DIR" -name "*.java" > sources.txt

echo "[INFO] Compiling source files..."
javac -d "$OUT_DIR" -cp "$LIB_DIR/montoya-api.jar:$LIB_DIR/gson.jar" @sources.txt

echo "[INFO] Creating fat JAR..."
rm -rf "build/fat"
mkdir -p "build/fat"

cp -R "$OUT_DIR"/* "build/fat/"

echo "[INFO] Extracting dependencies..."
cd "build/fat"
jar xf "../../lib/montoya-api.jar"
jar xf "../../lib/gson.jar"
cd ../..

jar cvf "$JAR_NAME" -C "build/fat" .

rm -f sources.txt
echo "[INFO] Build successful: $JAR_NAME"
