# HỆ THỐNG GIÁM SÁT, PHÁT HIỆN VÀ CẢNH BÁO TẤN CÔNG MẠNG DỰA TRÊN SURICATA & ELK STACK

## 1. Giới thiệu

Hệ thống này được thiết kế nhằm mục tiêu:

- **Giám sát lưu lượng và dịch vụ mạng**
- **Phát hiện hành vi tấn công**
- **Cảnh báo tự động theo thời gian thực**

Thông qua việc tích hợp các công cụ mã nguồn mở: **Suricata**, **Filebeat**, **Metricbeat**, **ELK Stack (Elasticsearch, Logstash, Kibana)**, và **ElastAlert2** cùng một **script Python gửi cảnh báo email** tùy chỉnh.

## 2. Kiến trúc hệ thống

```plaintext
[Attacker] ─► [dmz-web-dvwa]
                │
                ├─ Suricata + Filebeat (log cảnh báo)
                ├─ Metricbeat (giám sát tài nguyên)
                └─ Python (gửi email cảnh báo)
                         │
                         ▼
         [Logstash] ─► [Elasticsearch] ─► [Kibana]
                         │
                         ▼
                  [ElastAlert2]
                         └─► MS Teams webhook
