#!/usr/bin/env python3
"""Check node sync status: duplicates, new count, egress IP test"""
import json, urllib.request

API = "http://127.0.0.1:18080"

def get(path):
    return json.loads(urllib.request.urlopen(API + path, timeout=10).read())

nodes = get("/api/nodes")
tags = [n["tag"] for n in nodes]
unique = set(tags)
dupes = [t for t in unique if tags.count(t) > 1]
sources = {}
for n in nodes:
    st = n.get("source_type", "?")
    sources[st] = sources.get(st, 0) + 1

print(f"Total nodes: {len(nodes)}")
print(f"Unique tags: {len(unique)}")
print(f"Duplicates: {len(dupes)}")
for d in dupes[:10]:
    print(f"  DUP: {d} x{tags.count(d)}")
print(f"By source: {sources}")
print(f"\nFirst 5 nodes:")
for n in nodes[:5]:
    print(f"  [{n.get('type')}] {n['tag']} -> {n.get('server')}:{n.get('server_port')}")
