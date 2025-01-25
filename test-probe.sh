#!/bin/bash

# Test a build of the exporter's probe against a real Fluentbit container

DOCKER_IMAGE_NAME=fluent/fluent-bit:latest
EXPORTER_BIN=fluent-forward-blackbox-exporter

if ! (which curl > /dev/null); then
    echo "ERROR: required CLI tool \`curl\` not found"
    exit 1
fi
if ! (which jq > /dev/null); then
    echo "ERROR: required CLI tool \`jq\` not found - see https://jqlang.github.io/jq/"
    exit 1
fi
if [ ! -f "./${EXPORTER_BIN}" ]; then
    echo "ERROR: no build of the exporter found at ./${EXPORTER_BIN}"
    echo "Build the project with \`make\` then re-run this script"
    exit 1
fi

FB_CTR_ID=$(docker run --rm --detach \
    -p 127.0.0.1:24224:24224 \
    ${DOCKER_IMAGE_NAME} \
    /opt/fluent-bit/bin/fluent-bit \
        -i forward \
        -o stdout -m '*')
FB_CTR_START_CODE=$?
if [ "$FB_CTR_START_CODE" -ne "0" ]; then
    echo "starting fluentbit container failed with exit code $FB_CTR_START_CODE, exiting"
    exit 2    
fi
echo "fluentbit container started: $FB_CTR_ID"
docker logs "$FB_CTR_ID"

# Start the exporter as a background job with `&`` and save its PID from `$!``
./${EXPORTER_BIN} \
    --config.file=./test-fluent-config.yml &
FFBB_PID=$!
echo "${EXPORTER_BIN} started - pid: $FFBB_PID"


FB_IP_ADDR=$(docker inspect "${FB_CTR_ID}" | jq -r '.[0].NetworkSettings.IPAddress')
read -p "Push any key to start probe (to IP address ${FB_IP_ADDR})"
curl -v "http://localhost:9115/probe?target=${FB_IP_ADDR}%3A24224&module=fluent_forward_test&debug=true"
echo ""
read -p "Push any key to kill docker container + processes and quit"

kill "$FFBB_PID"
wait "$FFBB_PID"
docker stop "$FB_CTR_ID"