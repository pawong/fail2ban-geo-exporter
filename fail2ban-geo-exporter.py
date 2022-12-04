import yaml
import sqlite3
from prometheus_client import make_wsgi_app
from prometheus_client.core import GaugeMetricFamily, REGISTRY
from wsgiref.simple_server import make_server
import maxminddb
import logging


# Setup logging values
format_string = "level=%(levelname)s datetime=%(asctime)s %(message)s"
logging.basicConfig(encoding="utf-8", level=logging.DEBUG, format=format_string)


class MaxmindDB:
    def __init__(self, conf):
        self.db = conf["geo"]["db"]
        language = conf["geo"].get("language", None)
        self.language = language if language else "en"  # default to english
        self.reader = maxminddb.open_database(self.db)

    def get_ip_location(self, ip):
        retval = {
            "city": "Not found in the city database",
            "latitude": 0,
            "longitude": 0,
        }
        data = self.reader.get(ip)
        if data:
            city_name = ""
            city = data.get("city", None)
            if city:
                city_name = city["names"].get(self.language, None)
                if not city_name:
                    city_name = city["names"].get("en", "not found")
            retval["city"] = city_name
            retval["latitude"] = data["location"]["latitude"]
            retval["longitude"] = data["location"]["longitude"]
        # logging.info(f"{ip=}, {retval=}")
        return retval


class Jail:
    def __init__(self, name):
        self.name = name
        self.ip_list = []


class F2bCollector:
    def __init__(self, conf):
        self.namespace = "fail2ban"
        self.f2b_connection = sqlite3.connect(conf["f2b"]["db"])
        self.f2b_cursor = self.f2b_connection.cursor()
        self.jails_last_24h = []
        self.jails_all = []
        self.mmdb = MaxmindDB(conf)

    def get_total_banned_ip_count(self):
        banned_ip_count = self.f2b_cursor.execute(
            "SELECT count(*) FROM bips"
        ).fetchone()
        return banned_ip_count[0]

    def get_all_jails(self):
        jails = []

        active_jails = self.f2b_cursor.execute(
            "SELECT name FROM jails WHERE enabled = 1"
        ).fetchall()

        for name in active_jails:
            jail = Jail(name[0])
            jails.append(jail)

        return jails

    def get_last_24h_banned_ips(self):
        self.jails_last_24h = self.get_all_jails()

        for jail in self.jails_last_24h:
            ips = self.f2b_cursor.execute(
                "SELECT ip, timeofban FROM bans where jail = ?",
                [jail.name],
            ).fetchall()
            for ip in ips:
                jail.ip_list.append({"ip": ip[0], "timeofban": str(ip[1])})

    def get_all_banned_ips(self):
        self.jails_all = self.get_all_jails()

        for jail in self.jails_all:
            ips = self.f2b_cursor.execute(
                "SELECT ip, timeofban FROM bips where jail = ?",
                [jail.name],
            ).fetchall()
            for ip in ips:
                jail.ip_list.append({"ip": ip[0], "timeofban": str(ip[1])})

    def assign_location(self, jails):
        for jail in jails:
            for ip in jail.ip_list:
                ip.update(self.mmdb.get_ip_location(ip["ip"]))

    def last_24h_banned_ips_gauge(self):
        extra_labels = ["city", "latitude", "longitude"]
        metric_labels = ["jail", "ip", "timeofban"] + extra_labels
        gauge = GaugeMetricFamily(
            "fail2ban_last_24h_banned_ips",
            "Banned IPs for last 24h with location data.",
            labels=metric_labels,
        )

        for jail in self.jails_last_24h:
            for entry in jail.ip_list:
                values = [jail.name, entry["ip"], entry["timeofban"]] + [
                    str(entry[x]) for x in extra_labels
                ]
                gauge.add_metric(values, 1)

        logging.info(f"last_24h: {gauge}")
        return gauge

    def all_banned_ips_gauge(self):
        extra_labels = ["city", "latitude", "longitude"]
        metric_labels = ["jail", "ip", "timeofban"] + extra_labels
        gauge = GaugeMetricFamily(
            "fail2ban_all_banned_ips",
            "All banned IPs with location data.",
            labels=metric_labels,
        )

        for jail in self.jails_all:
            for entry in jail.ip_list:
                values = [jail.name, entry["ip"], entry["timeofban"]] + [
                    str(entry[x]) for x in extra_labels
                ]
                gauge.add_metric(values, 1)

        logging.info(f"all: {gauge}")
        return gauge

    def total_banned_ips_by_jail_gauge(self):
        gauge = GaugeMetricFamily(
            "fail2ban_total_banned_ips_by_jail",
            "Number of last_24hly banned IPs by jail",
            labels=["jail"],
        )

        for jail in self.jails_last_24h:
            gauge.add_metric([jail.name], len(jail.ip_list))

        logging.info(f"summary: {gauge}")
        return gauge

    def total_count_banned_ips_gauge(self):
        gauge = GaugeMetricFamily(
            "fail2ban_total_count_banned_ips",
            "Total number of banned IPs",
            labels=[],
        )
        gauge.add_metric(labels=[], value=self.get_total_banned_ip_count())

        logging.info(f"summary: {gauge}")
        return gauge

    def collect(self):
        logging.info("Start collect...")
        self.get_last_24h_banned_ips()
        self.assign_location(self.jails_last_24h)

        self.get_all_banned_ips()
        self.assign_location(self.jails_all)

        yield self.total_banned_ips_by_jail_gauge()
        yield self.total_count_banned_ips_gauge()
        yield self.last_24h_banned_ips_gauge()
        yield self.all_banned_ips_gauge()


if __name__ == "__main__":
    logging.info("Start main...")
    with open("conf.yml") as f:
        conf = yaml.load(f, Loader=yaml.FullLoader)

    app = make_wsgi_app()

    logging.info("Start server running...")
    httpd = make_server(conf["server"]["listen_address"], conf["server"]["port"], app)
    REGISTRY.register(F2bCollector(conf))
    httpd.serve_forever()
