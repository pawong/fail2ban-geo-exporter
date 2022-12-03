# Fail2Ban Geo Exporter
Prometheus exporter for Fail2Ban with geolocation data. This works for me. Free free to contact me if you have questions.

## Data

### GeoLocation Data
This uses [MaxMind](https://www.maxmind.com/en/home) free city database and their python library ([maxminddb](https://pypi.org/project/maxminddb/)). You can download the database but you will need to sign up for an account.


## Configuration
```yaml
server:
  listen_address: "fail2ban-geo-exporter"
  port: 9192

geo:
  language: "en"
  db: "/f2b-exporter/db/GeoLite2-City.mmdb"

f2b:
  conf_path: "/etc/fail2ban"
  db: "/var/lib/fail2ban/fail2ban.sqlite3"
```
## Docker
I've tested this with a docker-compose on my homelab.

### docker-compose snippet
```yaml
  fail2ban-geo-exporter:
    container_name: fail2ban-geo-exporter
    hostname: fail2ban-geo-exporter
    build: fail2ban-geo-exporter
    user: root
    restart: unless-stopped
    volumes:
      - /etc/fail2ban:/etc/fail2ban:ro
      - /var/lib/fail2ban/fail2ban.sqlite3:/var/lib/fail2ban/fail2ban.sqlite3:ro
      - /home/svc/DATA/fail2ban-geo-exporter/GeoLite2-City.mmdb:/f2b-exporter/db/GeoLite2-City.mmdb:ro
    ports:
      - "9192:9192"
    networks:
      - monitor-net
    labels:
      org.label-schema.group: "monitoring"
```

### Prometheus configuration snippet
```yaml
  - job_name: fail2ban-geo-exporter
    scrape_interval: 4m
    honor_labels: true
    static_configs:
      - targets: ["fail2ban-geo-exporter:9192"]
```

## Grafana Dashboard Example
Example JSON can can be found in `dashboard.json` file.

![grafana dashboard](grafana_db.png")