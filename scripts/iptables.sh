#!/bin/bash
set -euo pipefail

echo "🔄 Applying firewall rules..."

### ——————————————————————————————
### 🔧 Define ipsets
### ——————————————————————————————

declare -a ipsets=("blacklist" "allowlist")

for set in "${ipsets[@]}"; do
  if sudo ipset list "$set" &>/dev/null; then
    sudo ipset flush "$set"
  else
    sudo ipset create "$set" hash:ip
  fi
done

# Example usage (manual add):
# ipset add allowlist 198.51.100.55

### ——————————————————————————————
### 🔧 Reset iptables chains
### ——————————————————————————————

# Flush main filter table
sudo iptables -F

# Define and flush necessary chains
declare -a chains=("udp_limit" "allowlist_limit")

for chain in "${chains[@]}"; do
  if sudo iptables -L "$chain" -n &>/dev/null; then
    sudo iptables -F "$chain"
  else
    sudo iptables -N "$chain"
  fi
done

### ——————————————————————————————
### 📦 Main UDP Filtering Logic
### ——————————————————————————————

# 1️ Drop traffic from blacklisted IPs immediately
sudo iptables -A udp_limit -m set --match-set blacklist src -j DROP

# 2️ If in allowlist, go to allowlist_limit
sudo iptables -A udp_limit -m set --match-set allowlist src -j allowlist_limit

# 3️ Drop all others by default (not in allowlist)
sudo iptables -A udp_limit -j DROP

### ——————————————————————————————
### 📦 allowlist_limit chain — Verified clients
### ——————————————————————————————

sudo iptables -A allowlist_limit \
  -m hashlimit \
  --hashlimit-above 750/sec \
  --hashlimit-burst 200 \
  --hashlimit-mode srcip \
  --hashlimit-name allowlist_check \
  -j SET --add-set blacklist src

sudo iptables -A allowlist_limit -j ACCEPT

### ——————————————————————————————
### 🔗 Apply chain to UDP ports 7240–7260
### ——————————————————————————————

sudo iptables -A INPUT -p udp --dport 7240:7260 -j udp_limit

### ——————————————————————————————
### 🌐 NAT Redirect: TCP 80 → 8080
### ——————————————————————————————

# Flush NAT rules
sudo iptables -t nat -F

# External traffic
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080

# Localhost traffic
sudo iptables -t nat -A OUTPUT -p tcp -d 127.0.0.1 --dport 80 -j DNAT --to-destination 127.0.0.1:8080
sudo iptables -t nat -A OUTPUT -p tcp -d 127.0.0.2 --dport 80 -j DNAT --to-destination 127.0.0.2:8080

echo "✅ Firewall with allowlist + blacklist logic applied."
