#!/bin/bash
set -e

APP_SERVICE=ovn-exporter

if command -v systemctl >/dev/null 2>&1 && systemctl --version >/dev/null 2>&1; then
  if systemctl is-active --quiet ${APP_SERVICE}; then
    systemctl stop ${APP_SERVICE}
  fi
  systemctl disable ${APP_SERVICE} || true
fi
