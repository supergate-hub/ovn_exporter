#!/bin/bash
set -e

APP_USER=ovn_exporter
APP_GROUP=ovn_exporter
APP_SERVICE=ovn-exporter

if ! getent group "${APP_GROUP}" >/dev/null; then
  groupadd --system "${APP_GROUP}"
fi

if ! getent passwd "${APP_USER}" >/dev/null; then
  useradd --system -d /var/lib/${APP_SERVICE} -s /usr/sbin/nologin -g "${APP_GROUP}" "${APP_USER}"
fi

mkdir -p /var/lib/${APP_SERVICE}
chown "${APP_USER}:${APP_GROUP}" /var/lib/${APP_SERVICE}

if command -v systemctl >/dev/null 2>&1 && systemctl --version >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl enable ${APP_SERVICE}
  systemctl start ${APP_SERVICE}
fi
