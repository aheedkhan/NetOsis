#!/usr/bin/env python3
"""
Generate ConfigMap/Secret/Deployment/Service manifests for every NexusCorp org
host, from config/topology.json and the site content already generated for the
compose deployment (deploy/org/sites/, deploy/org/tls/).

Nine nearly-identical host definitions is exactly the kind of repetition that
belongs in a generator rather than nine hand-written YAML files that will drift
from each other the first time one of them needs a fix. Site content and TLS
material are read from disk at generation time rather than duplicated, so
editing deploy/org/sites/www01/index.html and re-running this script is the
whole update path — same discipline as deploy/k8s/generate-policies.py.

Usage:
    python3 deploy/k8s/generate-org-hosts.py > deploy/k8s/generated/org-hosts.yaml
"""

from __future__ import annotations

import base64
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
TOPOLOGY = ROOT / "config" / "topology.json"
SITES = ROOT / "deploy" / "org" / "sites"
TLS = ROOT / "deploy" / "org" / "tls"

ZONE_NS = {
    "dmz": "cs-dmz",
    "corp": "cs-corp",
    "datacenter": "cs-datacenter",
}

DMZ_NAMES = {
    "www01": "www.nexuscorp.example",
    "mail01": "mail.nexuscorp.example",
    "vpn01": "vpn.nexuscorp.example",
}


def b64(path: pathlib.Path) -> str:
    return base64.b64encode(path.read_bytes()).decode("ascii")


def indent(text: str, spaces: int) -> str:
    pad = " " * spaces
    return "\n".join(pad + line if line else line for line in text.splitlines())


def site_configmap(host_id: str, ns: str) -> str:
    site_dir = SITES / host_id
    entries = []
    for f in sorted(site_dir.glob("*")):
        if f.is_file():
            entries.append(f"  {f.name}: |\n{indent(f.read_text(encoding='utf-8'), 4)}")
    body = "\n".join(entries)
    return f"""apiVersion: v1
kind: ConfigMap
metadata:
  name: {host_id}-site
  namespace: {ns}
data:
{body}
"""


def tls_secret(host_id: str, ns: str) -> str:
    crt = TLS / f"{host_id}.crt"
    key = TLS / f"{host_id}.key"
    return f"""apiVersion: v1
kind: Secret
metadata:
  name: {host_id}-tls
  namespace: {ns}
type: kubernetes.io/tls
data:
  tls.crt: {b64(crt)}
  tls.key: {b64(key)}
"""


def shared_nginx_configmaps() -> str:
    org_conf = (ROOT / "deploy" / "org" / "edge" / "nginx-org.conf").read_text(encoding="utf-8")
    dmz_tmpl = (ROOT / "deploy" / "org" / "edge" / "nginx-dmz.conf.template").read_text(encoding="utf-8")
    parts = []
    for ns in set(ZONE_NS.values()):
        parts.append(f"""apiVersion: v1
kind: ConfigMap
metadata:
  name: nginx-org-conf
  namespace: {ns}
data:
  default.conf: |
{indent(org_conf, 4)}
""")
    parts.append(f"""apiVersion: v1
kind: ConfigMap
metadata:
  name: nginx-dmz-conf-template
  namespace: cs-dmz
data:
  default.conf.template: |
{indent(dmz_tmpl, 4)}
""")
    return "---\n".join(parts)


def dmz_deployment(host_id: str, ns: str, server_name: str) -> str:
    return f"""apiVersion: apps/v1
kind: Deployment
metadata:
  name: {host_id}
  namespace: {ns}
  labels:
    app: {host_id}
    cybersnare.io/kind: real
spec:
  replicas: 1
  selector:
    matchLabels:
      app: {host_id}
  template:
    metadata:
      labels:
        app: {host_id}
    spec:
      containers:
        - name: nginx
          image: docker.io/library/nginx:alpine
          env:
            - name: CS_HOST
              value: "{host_id}"
            - name: CS_SERVER_NAME
              value: "{server_name}"
            - name: NGINX_ENVSUBST_FILTER
              value: "CS_"
          ports:
            - containerPort: 80
            - containerPort: 443
          volumeMounts:
            - name: site
              mountPath: /usr/share/nginx/html
              readOnly: true
            - name: conf-template
              mountPath: /etc/nginx/templates
              readOnly: true
            - name: tls
              mountPath: /etc/nginx/tls
              readOnly: true
      volumes:
        - name: site
          configMap:
            name: {host_id}-site
        - name: conf-template
          configMap:
            name: nginx-dmz-conf-template
        - name: tls
          secret:
            secretName: {host_id}-tls
            # The nginx template (shared with the compose deployment) expects
            # <host>.crt/<host>.key, but a kubernetes.io/tls Secret's data
            # keys are always tls.crt/tls.key — items: remaps the mounted
            # filenames without touching the shared template.
            items:
              - {{key: tls.crt, path: {host_id}.crt}}
              - {{key: tls.key, path: {host_id}.key}}
---
apiVersion: v1
kind: Service
metadata:
  name: {host_id}
  namespace: {ns}
spec:
  selector:
    app: {host_id}
  ports:
    - name: http
      port: 80
      targetPort: 80
    - name: https
      port: 443
      targetPort: 443
"""


def plain_deployment(host_id: str, ns: str) -> str:
    return f"""apiVersion: apps/v1
kind: Deployment
metadata:
  name: {host_id}
  namespace: {ns}
  labels:
    app: {host_id}
    cybersnare.io/kind: decoy
spec:
  replicas: 1
  selector:
    matchLabels:
      app: {host_id}
  template:
    metadata:
      labels:
        app: {host_id}
    spec:
      containers:
        - name: nginx
          image: docker.io/library/nginx:alpine
          ports:
            - containerPort: 80
          volumeMounts:
            - name: site
              mountPath: /usr/share/nginx/html
              readOnly: true
            - name: conf
              mountPath: /etc/nginx/conf.d
              readOnly: true
      volumes:
        - name: site
          configMap:
            name: {host_id}-site
        - name: conf
          configMap:
            name: nginx-org-conf
---
apiVersion: v1
kind: Service
metadata:
  name: {host_id}
  namespace: {ns}
spec:
  selector:
    app: {host_id}
  ports:
    - name: http
      port: 80
      targetPort: 80
"""


def benign_workstation(ns: str) -> str:
    """wks01 — generates ordinary business traffic so the belief model has a
    benign background to discriminate against, not only attacks."""
    return f"""apiVersion: apps/v1
kind: Deployment
metadata:
  name: wks01
  namespace: {ns}
  labels:
    app: wks01
    cybersnare.io/kind: benign
spec:
  replicas: 1
  selector:
    matchLabels:
      app: wks01
  template:
    metadata:
      labels:
        app: wks01
    spec:
      containers:
        - name: wks01
          image: docker.io/library/alpine:3.20
          command: ["/bin/sh", "-c"]
          args:
            - |
              apk add --no-cache curl >/dev/null 2>&1
              while true; do
                for t in dc01 fs01 erp01; do
                  curl -s -m 3 -o /dev/null "http://$t.cs-corp.svc.cluster.local/" || true
                  sleep $(( (RANDOM % 7) + 3 ))
                done
              done
"""


def generate() -> str:
    topo = json.loads(TOPOLOGY.read_text(encoding="utf-8"))
    hosts = {h["id"]: h for h in topo["hosts"]}

    parts = [
        "# GENERATED — do not hand-edit.\n"
        "# Source: config/topology.json + deploy/org/sites, deploy/org/tls\n"
        "# Generator: deploy/k8s/generate-org-hosts.py\n"
    ]
    parts.append(shared_nginx_configmaps())

    for host_id, name in DMZ_NAMES.items():
        h = hosts[host_id]
        ns = ZONE_NS[h["zone"]]
        parts.append(site_configmap(host_id, ns))
        parts.append(tls_secret(host_id, ns))
        parts.append(dmz_deployment(host_id, ns, name))

    for host_id in ("dc01", "fs01", "erp01"):
        h = hosts[host_id]
        ns = ZONE_NS[h["zone"]]
        parts.append(site_configmap(host_id, ns))
        parts.append(plain_deployment(host_id, ns))

    parts.append(benign_workstation(ZONE_NS["corp"]))

    for host_id in ("db01", "bkp01"):
        h = hosts[host_id]
        ns = ZONE_NS[h["zone"]]
        parts.append(site_configmap(host_id, ns))
        parts.append(plain_deployment(host_id, ns))

    return "---\n".join(parts)


if __name__ == "__main__":
    sys.stdout.write(generate())
