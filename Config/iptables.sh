#!/bin/bash

### ============================
### RESET & CẤU HÌNH CƠ BẢN
### ============================

# Xóa toàn bộ rule cũ
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Bật IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Chính sách mặc định
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD DROP

### ============================
### NAT RA INTERNET
### ============================

iptables -t nat -A POSTROUTING -s 10.0.1.0/24 -o ens33 -j MASQUERADE  # LAN
iptables -t nat -A POSTROUTING -s 10.0.2.0/24 -o ens33 -j MASQUERADE  # Monitoring
iptables -t nat -A POSTROUTING -s 10.0.3.0/24 -o ens33 -j MASQUERADE  # DMZ

### ============================
### FORWARD: NỘI BỘ → INTERNET
### ============================

iptables -A FORWARD -i ens37 -o ens33 -j ACCEPT  # LAN
iptables -A FORWARD -i ens38 -o ens33 -j ACCEPT  # Monitoring
iptables -A FORWARD -i ens39 -o ens33 -j ACCEPT  # DMZ

iptables -A FORWARD -i ens33 -m state --state ESTABLISHED,RELATED -j ACCEPT  # Cho phản hồi

### ============================
### CHÍNH SÁCH BẢO MẬT
### ============================
# CHO PHÉP DVWA GỬI LOG ĐẾN ELK (Logstash:5044)
iptables -A FORWARD -s 10.0.3.128 -d 10.0.2.100 -p tcp --dport 5044 -j ACCEPT
iptables -A FORWARD -i ens33 -d 10.0.1.0/24 -j DROP  # Chặn Internet → LAN
iptables -A FORWARD -s 10.0.3.0/24 -d 10.0.1.0/24 -j DROP  # DMZ → LAN
iptables -A FORWARD -s 10.0.3.0/24 -d 10.0.2.0/24 -j DROP  # DMZ → Monitoring

### ============================
### CHO PHÉP LIÊN VÙNG HỢP LÝ
### ============================

# Monitoring ↔ DMZ
iptables -A FORWARD -i ens38 -o ens39 -s 10.0.2.0/24 -d 10.0.3.0/24 -j ACCEPT
iptables -A FORWARD -i ens39 -o ens38 -s 10.0.3.0/24 -d 10.0.2.0/24 -m state --state ESTABLISHED,RELATED -j ACCEPT

# LAN ↔ DMZ
iptables -A FORWARD -i ens37 -o ens39 -s 10.0.1.0/24 -d 10.0.3.0/24 -j ACCEPT
iptables -A FORWARD -i ens39 -o ens37 -s 10.0.3.0/24 -d 10.0.1.0/24 -m state --state ESTABLISHED,RELATED -j ACCEPT

### ============================
### TRUY CẬP KIBANA (10.0.2.100:5601)
### ============================

# DNAT từ máy thật đến Kibana
iptables -t nat -A PREROUTING -i ens33 -p tcp --dport 5601 -j DNAT --to-destination 10.0.2.100:5601

# FORWARD Kibana
iptables -A FORWARD -p tcp -d 10.0.2.100 --dport 5601 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -p tcp -s 10.0.2.100 --sport 5601 -m state --state ESTABLISHED,RELATED -j ACCEPT

### ============================
### TRUY CẬP SAMBA (10.0.3.140:445)
### ============================

# DNAT từ máy thật đến máy dịch vụ Samba (cổng 445)
iptables -t nat -A PREROUTING -i ens33 -p tcp --dport 445 -j DNAT --to-destination 10.0.3.140:445

# FORWARD Samba
iptables -A FORWARD -p tcp -d 10.0.3.140 --dport 445 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -p tcp -s 10.0.3.140 --sport 445 -m state --state ESTABLISHED,RELATED -j ACCEPT

### TRUY CẬP WEBSERVER (10.0.3.128:80)
### ============================

iptables -t nat -A PREROUTING -i ens33 -p tcp -j DNAT --to-destination 10.0.3.128
iptables -A FORWARD -p tcp -d 10.0.3.128 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -p tcp -s 10.0.3.128 -m state --state ESTABLISHED,RELATED -j ACCEPT
#SSH
#iptables -t nat -A PREROUTING -i ens33 -p tcp --dport 22 -j DNAT --to-destination 10.0.3.128:22
#iptables -A FORWARD -p tcp -d 10.0.3.128 --dport 22 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
#iptables -A FORWARD -p tcp -s 10.0.3.128 --sport 22 -m state --state ESTABLISHED,RELATED -j ACCEPT

### ============================
### GỬI QUA SURICATA (NFQUEUE)
### ============================

# Đặt sau các rule cho phép để tránh chặn
iptables -D FORWARD -j NFQUEUE --queue-num 0 2>/dev/null
iptables -I FORWARD -j NFQUEUE --queue-num 1

### ============================
### LƯU CẤU HÌNH
### ============================

netfilter-persistent save
