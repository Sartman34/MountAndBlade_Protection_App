import sys
import os
import traceback
import time
import random
import string as string_lib
import socket
import threading
import subprocess
import datetime
import pyshark
import ipaddress
import requests
import json
import http.client
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from modules.directories import directories
import modules.admin as admin

# Force getaddrinfo to only return IPv4 results
_original_getaddrinfo = socket.getaddrinfo

def ipv4_only_getaddrinfo(*args, **kwargs):
    return [info for info in _original_getaddrinfo(*args, **kwargs) if info[0] == socket.AF_INET]

socket.getaddrinfo = ipv4_only_getaddrinfo

eval_string = ""

def print_(*string, sep = " ", end = "\n", flush = False):
    if eval_string:
        print("\r" + " " * len(eval_string) + "\r", end = ""),
    print("[{}]".format(datetime.datetime.now().strftime("%H:%M:%S")), *string, sep = sep, end = end, flush = flush)
    directories.log.format(strftime = datetime.datetime.now().strftime("%Y_%m_%d"))
    check_file(directories.log)
    with open(directories.log, "a", encoding="utf-8") as file:
        old_stdout = sys.stdout
        sys.stdout = file
        print("[{}]".format(datetime.datetime.now().strftime("%H:%M:%S")), *string, sep = sep, end = end, flush = flush)
        sys.stdout = old_stdout
    if eval_string:
        print(eval_string, end = "", flush = True)

try:
    if os.name == "nt" and not admin.isUserAdmin():
        admin.runAsAdmin(wait = False)
        sys.exit(0)
except RuntimeError:
    print_("Couldn't start the program as admin.")
        
def check_file(directory):
    try:
        with open(directory, mode = "x", encoding = "utf-8"):
            print_("Created the file: \"{}\".".format(directory.basename()))
    except FileExistsError:
        pass

def clean_file(directory):
    with open(directory, mode = "w", encoding = "utf-8"):
        print_("Cleaned the file: \"{}\".".format(directory.basename()))

def append_new_line(directory, string):
    with open(directory, "r+") as file:
        data = file.read()
        file.write(("" if not data or data[-1] == "\n" else "\n") + string)

def string_bool_meaning(string):
    true_strings = ["1", "true", "yes", "+"]
    return string.lower() in true_strings

def import_error(directory, object_name, line, exception):
    print_("While importing \"{}\", the {} at line {} gave an error: ({}).".format(directory.basename(), object_name, line, exception))

def check_commands(category, not_necessary_commands):
    defined = True
    for key, command in commands[category].items():
        if not command and not key in not_necessary_commands:
            print_("Warning! You need the command [{0}.{1}] defined in order to activate {0}.".format(category, key))
            defined = False
    return defined

def check_configs(category, necessary_configs):
    defined = True
    for config in necessary_configs:
        if not configs[category][config]:
            print_("Warning! You need the config \"{}\" defined in order to activate {}.".format(config, category))
            defined = False
    return defined

def get_random_string(length):
    random_list = []
    for i in range(length):
        random_list.append(random.choice(string_lib.ascii_lowercase + string_lib.digits))
    return "".join(random_list)

def send_message(addr, message):
    server = socket.socket()
    server.connect(addr)
    server.send(message.encode())
    server.close()

base_host = socket.gethostbyname(socket.gethostname())
base_configs = {
    "warband" : {
        "interface" : "Ethernet",
        "host" : base_host,
        "port" : "7240",
    },
    "IP UIDs" : {
        "clean start" : False,
        "randomize" : False,
        "always list" : False,
        "allowlist size" : -1,
        "rule updater delay" : 0,
    },
    "advanced firewall" : {
        "active" : False,
        "header" : "warband",
    },
    "ipset" : {
        "active" : False,
        "name" : "allowlist",
    },
    "google cloud" : {
        "active" : False,
        "project" : "",
        "header" : "warband",
        "priority" : 1000,
        "network" : "default",
    },
    "hetzner" : {
        "active" : False,
        "api" : "",
        "firewall" : "warband",
    },
    "pyshark" : {
        "active" : False,
        "interface" : "Ethernet",
        "filter" : "host {host} && port {port}",
        "host" : base_host,
        "port" : 7240,
    },
    "cloudflare" : {
        "active" : False,
        "hostname" : "warbandmain.taleworlds.com",
        "port" : 80,
        "gateway" : "",
    },
    "dumpcap" : {
        "active" : False,
        "application" : "C:\\Program Files\\Wireshark\\dumpcap",
        "filesize" : 100000,
        "printname" : "stdout",
        "filename" : "mycap",
        "filter" : "host {host} && portrange {port}",
        "show stdout" : False,
    },
    "eval" : {
        "active" : False,
        "header" : "Input: ",
    },
    "ip list transmitter" : {
        "active" : False,
        "mode" : "server",
        "host" : "0.0.0.0",
        "port" : 7010,
    },
}
base_commands = {
    "advanced firewall" : {
        "list" : "",
        "create" : "",
        "delete" : "",
    },
    "ipset" : {
        "list" : "",
        "create" : "",
        "delete" : "",
    },
    "google cloud" : {
        "list" : "",
        "create" : "",
        "delete" : "",
    },
    "hetzner" : {
        "list" : "",
        "set" : "",
    },
    "dumpcap" : {
        "command" : "",
    },
}


def import_configs(directory):
    global configs
    configs = base_configs.copy()
    check_file(directory)
    with open(directory, mode = "r", encoding = "utf-8") as file:
        data = file.read()
    if not data:
        return
    category = None
    raw_configs = data.split("\n")
    for i, config in enumerate(raw_configs, start = 1):
        config = config.split("#")[0].replace("\t", "").strip(" ")
        if not config:
            continue
        if config[0] == "[" and config[-1] == "]":
            category = config[1:-1]
            if not category in configs:
                import_error(directory, "category", i, "The category does not exist.")
                category = None
        elif category:
            config, value = [part.strip(" ") for part in config.split("=")]
            if not config in configs[category]:
                import_error(directory, "config", i, "The config does not exist.")
            if type(configs[category][config]) == bool:
                value = string_bool_meaning(value)
            elif type(configs[category][config]) == int:
                try:
                    value = int(value)
                except exception:
                    import_error(directory, "config", i, exception)
            configs[category][config] = value
        else:
            import_error(directory, "config", i, "A category must be defined.")


def import_commands(directory):
    global commands
    commands = base_commands.copy()
    check_file(directory)
    with open(directory, mode = "r", encoding = "utf-8") as file:
        data = file.read()
    if not data:
        return
    command_tuple = None
    raw_commands = data.split("\n")
    for i, line in enumerate(raw_commands, start = 1):
        line = line.split("#")[0].replace("\t", "").strip(" ")
        if not line:
            continue
        if line[0] == "[" and line[-1] == "]":
            line = line[1:-1]
            if line in ["", "\\"]:
                command_tuple = None
                continue
            parts = line.split(".")
            if not len(parts) == 2:
                import_error(directory, "command", i, "The command defined incorrectly. Syntax: \"[<category>.<command>]\"")
                command_tuple = None
                continue
            category, command = parts
            if not category in commands:
                import_error(directory, "category", i, "The category does not exist.")
                command_tuple = None
                continue
            if not command in commands[category]:
                import_error(directory, "command", i, "The command does not exist.")
                command_tuple = None
                continue
            command_tuple = (category, command)
        elif command_tuple != None:
            category, command = command_tuple
            line = line.replace("\\r", "\r").replace("\\n", "\n")
            commands[category][command] += line
        else:
            import_error(directory, "command", i, "A command must be defined.")


class IP_List():
    def __init__(self, directory, size = None, remote_controlled = False):
        self.directory = directory
        self.size = size
        self.is_remote = remote_controlled
        self.ip_list = list()
        self.lock = threading.Lock()
        
        self._import()

    def set_ip_list(self, ip_list):
        if ip_list == self.ip_list:
            return
        if self.size != None:
            ip_list = ip_list[max(len(ip_list) - self.size, 0):]
        with self.lock:
            self.ip_list = ip_list
            Event_Handler.file_call = True
            with open(self.directory, mode = "w") as file:
                file.write("\n".join([format(ip_address) for ip_address in self.ip_list]))

    def get_ip_list(self):
        with self.lock:
            return self.ip_list.copy()

    def _import(self):
        check_file(self.directory)
        with self.lock:
            with open(self.directory, mode = "r", encoding = "utf-8") as file:
                data = file.read()
        if not data:
            self.set_ip_list(list())
            return
        if configs["IP UIDs"]["clean start"] and not self.is_remote:
            clean_file(self.directory)
            self.set_ip_list(list())
            return
        ip_list = list()
        ip_addresses = data.split("\n")
        for i, ip_address in enumerate(ip_addresses, start = 1):
            try:
                ip_address = ipaddress.ip_address(ip_address.split("#")[0].strip(" ").strip("\t"))
            except ipaddress.AddressValueError as exception:
                import_error(self.directory, "ip address", i, exception)
                continue
            if ip_address in ip_list:
                continue
            ip_list.append(ip_address)
        self.set_ip_list(ip_list)

    def add_ip(self, ip_address):
        if ip_address in self.ip_list:
            return False
        ip_list = self.ip_list.copy()
        ip_list.append(ip_address)
        self.set_ip_list(ip_list)
        ip_list_sync("add%{}%{}".format(self.directory.key, ip_address), "Sending new ip address {} to ip list: {}.".format(ip_address, self.directory.key))
        return True

    def remove_ip(self, ip_address):
        if ip_address not in self.ip_list:
            return False
        ip_list = self.ip_list.copy()
        ip_list.remove(ip_address)
        self.set_ip_list(ip_list)
        ip_list_sync("remove%{}%{}".format(self.directory.key, ip_address), "Removing current ip address {} from ip list: {}.".format(ip_address, self.directory.key))
        return True

    def clear(self):
        self.set_ip_list(list())
        ip_list_sync("clear%{}".format(self.directory.key), "Clearing ip list: {}.".format(self.directory.key))


class IP_UID_Manager():
    def __init__(self, directory):
        self.directory = directory
        self.ip_uids = dict()
        self.uids = set()
        self.ip_datas = dict()
        self.uid_count = 1

    def import_directory(self):
        self.ip_uids.clear()
        check_file(self.directory)
        with open(self.directory, mode = "r", encoding = "utf-8") as file:
            data = file.read()
        if not data:
            return
        if configs["IP UIDs"]["clean start"]:
            clean_file(self.directory)
            return
        lines = data.split("\n")
        for i, line in enumerate(lines, start = 1):
            line = line.split("#")[0].replace("\t", "").replace(" ", "").lower()
            if not line:
                continue
            unique_id, ip_data = line.split(":")
            ip_address_data = ip_data.split(",")
            if not ip_address_data:
                continue
            ip_addresses = list()
            for ip_address in ip_address_data:
                try:
                    ip_address = ipaddress.ip_address(ip_address)
                except ipaddress.AddressValueError as exception:
                    import_error(self.directory, "ip address", i, exception)
                    continue
                ip_addresses.append(ip_address)
            if not ip_addresses:
                continue
            elif len(ip_addresses) == 1:
                ip_address = ip_addresses[0]
                self.ip_uids[ip_address] = unique_id
            else:
                ip_data = IP_Data(unique_id, ip_addresses)
                self.ip_uids[ip_data] = unique_id
            self.uids.add(unique_id)
            if len(ip_addresses) > 1:
                self.ip_datas[unique_id] = ip_addresses
        for i in range(len(self.uids)):
            if not str(self.uid_count) in self.uids:
                break
            self.uid_count += 1
    
    def generate_new_unique_id(self):
        while True:
            if configs["IP UIDs"]["randomize"]:
                unique_id = get_random_string(6)
            else:
                unique_id = str(self.uid_count)
            if unique_id in self.uids:
                self.uid_count += 1
                continue
            self.uids.add(unique_id)
            return unique_id

    def update_unique_id_data(self, unique_id, ip_data):
        self.ip_uids[ip_data] = unique_id
        append_new_line(self.directory, "{} : {}".format(unique_id, ip_data))

    def get_unique_id(self, ip_address):
        if ip_address in self.ip_uids:
            return self.ip_uids[ip_address]
        unique_id = self.generate_new_unique_id()
        self.update_unique_id_data(unique_id, ip_address)
        return unique_id

    def geneate_ip_data_uid(self, ip_address):
        unique_id = self.generate_new_unique_id()
        self.update_unique_id_data(unique_id, ip_address)
        return unique_id


class Event_Handler(FileSystemEventHandler):
    file_call = False
    def __init__(self):
        FileSystemEventHandler.__init__(self)
        
    def on_modified(self, event):
        for directory_key, ip_list in ip_lists.items():
            if event.src_path == ip_list.directory.string():
                if not Event_Handler.file_call:
                    print_("Data change detected on file: {}".format(ip_list.directory.basename()))
                    ip_list._import()
                Event_Handler.file_call = False
                rule_updater.update = True
                break


class Rule():
    def __init__(self):
        self.defined = True

    def list(self):
        return list()

    def create(self, unique_id, ip_address):
        print_("Created rule with unique_id: {}, ip address: {}".format(unique_id, ip_address))

    def delete(self, unique_id):
        print_("Deleted rule with unique_id: {}".format(unique_id))

    def refresh(self):
        pass


class Advanced_Firewall(Rule):
    def __init__(self):
        super().__init__(self)
        if not check_commands("advanced firewall", []):
            self.defined = False

    def list(self):
        kwargs = {
            "port" : configs["warband"]["port"],
        }
        try:
            rules = [rule.strip().split("-")[1] for rule in subprocess.check_output(
                commands["advanced firewall"]["list"].format(**kwargs),
                shell = True,
                stderr = subprocess.PIPE,
            ).decode().split("\r\n")[:-1]]
        except subprocess.CalledProcessError:
            return []
        return rules

    def create(self, unique_id, ip_address):
        kwargs = {
            "header" : configs["advanced firewall"]["header"],
            "unique_id" : unique_id,
            "port" : configs["warband"]["port"],
            "ip_address" : ip_address,
        }
        subprocess.check_call(
            commands["advanced firewall"]["create"].format(**kwargs),
            shell = True,
            stdout = subprocess.PIPE,
            stderr = subprocess.PIPE,
        )
        print_("Created rule with ip address: {}, unique id: {}".format(ip_address, unique_id))

    def delete(self, unique_id):
        kwargs = {
            "header" : configs["advanced firewall"]["header"],
            "unique_id" : unique_id,
        }
        subprocess.check_call(
            commands["advanced firewall"]["delete"].format(**kwargs),
            shell = True,
            stdout = subprocess.PIPE,
            stderr = subprocess.PIPE,
        )
        print_("Deleted rule with unique_id: {}".format(unique_id))

class IPSet(Rule):
    def __init__(self):
        super().__init__()
        self.unique_ids = dict()
        if not check_commands("ipset", []):
            self.defined = False

    def list(self):
        kwargs = {
            "name" : configs["ipset"]["name"],
        }
        data = subprocess.check_output(
            commands["ipset"]["list"].format(**kwargs),
            shell = True,
            stderr = subprocess.PIPE,
        ).decode().splitlines()
        ip_addresses = data[data.index("Members:") + 1:]
        self.unique_ids.clear()
        for ip_address in ip_addresses:
            ip_address = ipaddress.ip_address(ip_address)
            unique_id = ip_uid_manager.get_unique_id(ip_address)
            self.unique_ids[unique_id] = ip_address
        return self.unique_ids.keys()

    def create(self, unique_id, ip_address):
        if unique_id in self.unique_ids:
            return
        kwargs = {
            "name" : configs["ipset"]["name"],
            "ip_address" : ip_address,
        }
        subprocess.check_call(
            commands["ipset"]["create"].format(**kwargs),
            shell = True,
            stdout = subprocess.PIPE,
            stderr = subprocess.PIPE,
        )
        self.unique_ids[unique_id] = ip_address
        print_(f"[IPSet] Added IP {ip_address} with ID '{unique_id}'.")

    def delete(self, unique_id):
        if unique_id not in self.unique_ids:
            return
        ip_address = self.unique_ids[unique_id]
        kwargs = {
            "name" : configs["ipset"]["name"],
            "ip_address" : ip_address,
        }
        subprocess.check_call(
            commands["ipset"]["delete"].format(**kwargs),
            shell = True,
            stdout = subprocess.PIPE,
            stderr = subprocess.PIPE,
        )
        del self.unique_ids[unique_id]
        print_(f"[IPSet] Removed IP {ip_address} with ID '{unique_id}'.")


class IP_Data():
    limit = 100
    def __init__(self, unique_id, ip_addresses = None):
        self.index = 0
        self.unique_id = unique_id
        self.ip_addresses = ip_addresses if ip_addresses else list()
        self.ip_address_type = type(ip_addresses[0]) if ip_addresses else None
        self.update = False
        self.present = False

    def create(self, ip_address):
        if ip_address in self.ip_addresses:
            return "already have"
        if self.ip_address_type and self.ip_address_type != type(ip_address):
            return
        if len(self.ip_addresses) >= type(self).limit:
            return
        if not self.ip_address_type:
            self.ip_address_type = type(ip_address)
        self.ip_addresses.append(ip_address)
        self.update = True
        return "added"

    def delete(self, unique_id):
        new_ip_addresses = self.ip_addresses.copy()
        for ip_address in self.ip_addresses:
            if ip_uid_manager.get_unique_id(ip_address) == unique_id:
                new_ip_addresses.remove(ip_address)
                break
        else:
            return
        self.ip_addresses = new_ip_addresses
        self.update = True
        return ip_address

    def get_unique_id(self):
        return "-".join([self.unique_id, str(self.index)])

    def ip_networks(self):
        ip_networks = list()
        if self.ip_address_type == ipaddress.IPv4Address:
            for ip_address in self.ip_addresses:
                ip_networks.append(ipaddress.IPv4Network(ip_address, strict = False))
        elif self.ip_address_type == ipaddress.IPv6Address:
            for ip_address in self.ip_addresses:
                ip_networks.append(ipaddress.IPv6Network(ip_address, strict = False))
        return ip_networks

class Advanced_Rule(Rule):
    def __init__(self):
        super().__init__(self)
        self.ip_datas = dict()
        for unique_id, ip_addresses in ip_uid_manager.ip_datas.items():
            self.ip_datas[unique_id] = IP_Data(unique_id)
            for ip_address in ip_addresses:
                self.ip_datas[unique_id].create(ip_address)

    def list(self):
        rules = self.list_rules()
        to_be_deleted = list()
        for rule in reversed(rules):
            unique_id, index = rule.split("-")[-2:]
            if unique_id not in self.ip_datas:
                to_be_deleted.append("-".join([unique_id, index]))
                continue
            ip_data = self.ip_datas[unique_id]
            if ip_data.index > int(index):
                to_be_deleted.append("-".join([unique_id, index]))
            elif ip_data.index < int(index):
                if ip_data.present:
                    to_be_deleted.append(ip_data.get_unique_id())
                ip_data.index = int(index)
            ip_data.present = True
        for ip_data_uid in to_be_deleted:
            self.delete_rule(ip_data_uid)
        return list()

    def create(self, unique_id, ip_address):
        for ip_data_uid, ip_data in self.ip_datas.items():
            result = ip_data.create(ip_address)
            if result == "added":
                print_("Added to rule-range ({}) the ip address: {}, unique id: {}".format(ip_data_uid, ip_address, unique_id))
                break
            elif result == "already have":
                break
            else:
                pass
        else:
            ip_data_uid = ip_uid_manager.geneate_ip_data_uid(ip_address)
            ip_data = IP_Data(ip_data_uid)
            ip_data.create(ip_address)
            self.ip_datas[ip_data_uid] = ip_data
            print_("Created new rule-range ({}) with ip address: {}, unique id: {}".format(ip_data_uid, ip_address, unique_id))

    def delete(self, unique_id):
        for ip_data_uid, ip_data in self.ip_datas.items():
            ip_address = ip_data.delete(unique_id)
            if ip_address:
                print_("Deleted from rule-range ({}) the ip address: {}, unique id: {}".format(ip_data_uid, ip_address, unique_id))

    def refresh(self):
        to_be_deleted = list()
        for unique_id, ip_data in self.ip_datas.items():
            if ip_data.present and not ip_data.update:
                continue
            ip_data.update = False
            if ip_data.present:
                to_be_deleted.append(ip_data.get_unique_id())
                ip_data.index = (ip_data.index + 1) % 10
            else:
                ip_data.present = True
            if ip_data.ip_addresses:
                self.create_rule(ip_data)
            ip_uid_manager.update_unique_id_data(unique_id, ",".join([format(ip_address) for ip_address in ip_data.ip_addresses]))
        for ip_data_uid in to_be_deleted:
            self.delete_rule(ip_data_uid)
        self.refresh_rules()

    def list_rules(self):
        return list()

    def create_rule(self, ip_data):
        print_("Created rule-range with unique id: {}".format(ip_data.get_unique_id()))

    def delete_rule(self, unique_id):
        print_("Deleted rule-range with unique_id: {}".format(unique_id))

    def refresh_rules(self):
        pass


class Google_Cloud(Advanced_Rule):
    def __init__(self):
        super().__init__(self)
        if not check_commands("google cloud", []):
            self.defined = False
            return
        if not check_configs("google cloud", ["project"]):
            self.defined = False
            return

    def list_rules(self):
        kwargs = {
            "project" : configs["google cloud"]["project"],
            "header" : configs["google cloud"]["header"],
        }
        return [str(rule).split(" ")[0] for rule in subprocess.check_output(
            commands["google cloud"]["list"].format(**kwargs),
            shell = True,
            stderr = subprocess.PIPE,
        ).decode().split("\n")][1:-1]
        
    def create_rule(self, ip_data):
        kwargs = {
            "project" : configs["google cloud"]["project"],
            "header" : configs["google cloud"]["header"],
            "unique_id" : ip_data.get_unique_id(),
            "priority" : configs["google cloud"]["priority"] + ip_data.index,
            "network" : " --network={}".format(configs["google cloud"]["network"]) if configs["google cloud"]["network"] != "default" else "",
            "port" : configs["warband"]["port"],
            "ip_addresses" : ",".join([ip_network.with_prefixlen for ip_network in ip_data.ip_networks()]),
        }
        subprocess.check_call(
            commands["google cloud"]["create"].format(**kwargs),
            shell = True,
            stdout = subprocess.PIPE,
            stderr = subprocess.PIPE,
        )
        print_("Created rule-range with unique id: {}".format(kwargs["unique_id"]))

    def delete_rule(self, unique_id):
        kwargs = {
            "project" : configs["google cloud"]["project"],
            "header" : configs["google cloud"]["header"],
            "unique_id" : unique_id,
        }
        subprocess.Popen(
            commands["google cloud"]["delete"].format(**kwargs),
            shell = True,
            stdin = subprocess.PIPE,
            stdout = subprocess.PIPE,
            stderr = subprocess.PIPE,
        ).communicate("Y".encode())
        print_("Deleted rule-range with unique_id: {}".format(unique_id))


class Hetzner(Advanced_Rule):
    def __init__(self):
        super().__init__(self)
        if not check_commands("hetzner", []):
            self.defined = False
            return
        if not check_configs("hetzner", ["api"]):
            self.defined = False
            return
        self.firewalls = dict()
        self.rules = dict()

    def list_rules(self):
        self.rules.clear()
        headers = {
            "Authorization": "Bearer {}".format(configs["hetzner"]["api"]),
        }
        for firewall in requests.request("GET", commands["hetzner"]["list"], headers = headers).json()["firewalls"]:
            if not firewall["name"].startswith(configs["hetzner"]["firewall"]):
                continue
            self.firewalls[int(firewall["name"].split("-")[1])] = firewall
            for rule in firewall["rules"]:
                self.rules[rule["description"]] = rule
        if not self.firewalls:
            print_("ERROR! No Hetzner Firewall starting with ({}) is not found.".format(configs["hetzner"]["firewall"]))
            return list()
        return [rule["description"] for unique_id, rule in self.rules.items()]

    def create_rule(self, ip_data):
        unique_id = ip_data.get_unique_id()
        self.rules[unique_id] = {
          "description": unique_id,
          "direction": "in",
          "port": configs["warband"]["port"],
          "protocol": "udp",
          "source_ips": [ip_network.with_netmask for ip_network in ip_data.ip_networks()],
        }
        print_("Created rule-range with unique id: {}".format(unique_id))

    def delete_rule(self, unique_id):
        if unique_id in self.rules:
            self.rules.pop(unique_id)
        print_("Deleted rule-range with unique_id: {}".format(unique_id))
    
    def refresh_rules(self):
        if not self.firewalls:
            return
        print_("Refreshing Firewall...")
        headers = {
            "Authorization": "Bearer {}".format(configs["hetzner"]["api"]),
            "Content-Type": "application/json",
        }
        for i, rules in enumerate(self.get_rules_per_firewall()):
            data = {
                "rules" : rules,
            }
            response = requests.request("POST", commands["hetzner"]["set"].format(firewall_id = self.firewalls[i]["id"]), data = json.dumps(data), headers = headers).json()
            if "actions" not in response:
                print_("Warning! Hetzner response is unexpected: {}".format(response))
                return
            for action in response["actions"]:
                if action["error"]:
                    print_(action["error"])

    def get_rules_per_firewall(self):
        rules_per_firewall = [list() for i in range(len(self.firewalls))]
        for i, rule in enumerate(list(self.rules.values())):
            rules_per_firewall[i % len(self.firewalls)].append(rule)
            if len(rules_per_firewall[i % len(self.firewalls)]) > 5:
                print_("ERROR! Rule limit for firewalls is reached. Try reducing allowlist size.")
        return rules_per_firewall

class Rule_Updater(threading.Thread):
    def __init__(self, rule_list, *args, **kwargs):
        threading.Thread.__init__(self, *args, **kwargs)

        self.rule_list = rule_list
        self.update = False
        self.force = False
        self.ip_list = set()
        self.unique_ids = set()

    def list(self):
        self.unique_ids.clear()
        for rule in self.rule_list:
            self.unique_ids.update(rule.list())
        
    def create(self, unique_id, ip_address):
        for rule in self.rule_list:
            rule.create(unique_id, ip_address)
        self.unique_ids.add(unique_id)
        
    def delete(self, unique_id):
        for rule in self.rule_list:
            rule.delete(unique_id)
        self.unique_ids.remove(unique_id)

    def refresh(self):
        for rule in self.rule_list:
            rule.refresh()

    def run(self):
        while True:
            try:
                if not self.update:
                    time.sleep(1); continue
                self.update = False

                new_ip_list = set(ip_lists[directories.allowlist.key].get_ip_list())\
                    .union(set(ip_lists[directories.currentlist.key].get_ip_list()))\
                    .difference(set(ip_lists[directories.blacklist.key].get_ip_list()))
                
                if not self.force and self.ip_list == new_ip_list:
                    time.sleep(1); continue
                print_("Updating IP List rules{}...".format(" (force: True)" if self.force else ""))
                
                if configs["IP UIDs"]["always list"] or self.force:
                    self.list()
                self.force = False
                
                self.ip_list = new_ip_list
                new_unique_ids = set(ip_uid_manager.get_unique_id(ip_address) for ip_address in self.ip_list)
                old_unique_ids = self.unique_ids.copy()
                difference = old_unique_ids.difference(new_unique_ids)
                for unique_id in difference:
                    self.delete(unique_id)
                for ip_address in self.ip_list:
                    unique_id = ip_uid_manager.get_unique_id(ip_address)
                    if not unique_id in self.unique_ids:
                        self.create(unique_id, ip_address)
                self.refresh()
                configs["IP UIDs"]["clean start"] = False
                print_("Done!")
                if configs["IP UIDs"]["rule updater delay"]:
                    time.sleep(configs["IP UIDs"]["rule updater delay"])
            except:
                print_("rule updater:", traceback.format_exc())
                self.update = True
                self.force = True
                time.sleep(10)


verified_ip_addresses = set()
def pyshark_listener():
    try:
        while configs["IP UIDs"]["clean start"]:
            time.sleep(1)
        capture = pyshark.LiveCapture(
            configs["pyshark"]["interface"],
            bpf_filter = configs["pyshark"]["filter"].format(
                host = configs["pyshark"]["host"],
                port = configs["pyshark"]["port"]
            ),
        )
        print_(
            "Started listening interface: \"{}\", host: {}, port: {}".format(
                configs["pyshark"]["interface"],
                configs["pyshark"]["host"],
                configs["pyshark"]["port"],
            )
        )
        for packet in capture.sniff_continuously():
            source_ip = packet.ip.src
            if source_ip == configs["pyshark"]["host"]: continue
            verified_ip_addresses.add(source_ip)
    except:
        print_("pyshark listener:", traceback.format_exc())

def pyshark_verifier():
    ip_list = ip_lists[directories.allowlist.key]
    try:
        while True:
            time.sleep(1)
            for source_ip in verified_ip_addresses.copy():
                ip_address = ipaddress.ip_address(source_ip)
                if ip_list.add_ip(ip_address):
                    print_("Verified new ip address: {}".format(ip_address))
            verified_ip_addresses.clear()
    except:
        print_("pyshark verifier:", traceback.format_exc())

def cloudflare_communicator():
    while True:
        try:
            route = bool(configs["cloudflare"]["gateway"])
            host = socket.gethostbyname(configs["cloudflare"]["hostname"])
            port = configs["pyshark"]["port"]
            keys = None
            if route:
                subprocess.check_call(
                    "route add {} {}".format(host, configs["cloudflare"]["gateway"]),
                    shell = True,
                    stdout = subprocess.PIPE,
                )
            # Reuse the same connection for keep-alive
            conn = http.client.HTTPConnection(configs["cloudflare"]["hostname"], configs["cloudflare"]["port"], timeout=5)

            # Step 1: Forward ping request
            ping_path = f"/handlerservers.ashx?type=ping&keys"
            if keys:
                ping_path += f"={keys}"
            if port != 7240:
                ping_path += f"&port={port}"
            ping_path += "&hidden=false"

            conn.putrequest("GET", ping_path)
            conn.putheader("Host", "www.w3.org")
            conn.putheader("User-Agent", "curl/7.65.3")
            conn.putheader("Accept", "*/*")
            conn.putheader("Accept-Encoding", "deflate, gzip, br")
            conn.endheaders()

            rand_value = conn.getresponse().read().decode().strip()

            # Step 2: Immediately send confirmping
            confirm_path = "/handlerservers.ashx?type=confirmping"
            if port:
                confirm_path += f"&port={port}"
            confirm_path += f"&rand={rand_value}&hidden=false"
            conn.putrequest("GET", confirm_path)
            conn.putheader("Host", "www.w3.org")
            conn.putheader("User-Agent", "curl/7.65.3")
            conn.putheader("Accept", "*/*")
            conn.putheader("Accept-Encoding", "deflate, gzip, br")
            conn.endheaders()

            resp = conn.getresponse().read().decode().strip()
            print_(
                "Pinged host: {} ({}), port: {}, gateway: {}, response: {}".format(
                    configs["cloudflare"]["hostname"],
                    host,
                    configs["pyshark"]["port"],
                    configs["cloudflare"]["gateway"] if route else "On-link",
                    resp,
                )
            )
            if route:
                subprocess.check_call(
                    "route delete {}".format(host),
                    shell = True,
                    stdout = subprocess.PIPE,
                )
            time.sleep(300)
        except:
            print_("cloudflare communicator:", traceback.format_exc())
            time.sleep(10)

def dumpcap_logger():
    if not check_commands("dumpcap", []):
        return
    try:
        while True:
            # Build parameters
            kwargs = {
                "application" : configs["dumpcap"]["application"],
                "filesize" : configs["dumpcap"]["filesize"],
                "printname" : configs["dumpcap"]["printname"],
                "write" : directories.pcap.format(filename = configs["dumpcap"]["filename"]),
                "interface" : configs["warband"]["interface"],
                "filter" : configs["dumpcap"]["filter"].format(host = configs["warband"]["host"], port = configs["warband"]["port"]),
            }
            parameters = [parameter.format(**kwargs) for parameter in commands["dumpcap"]["command"].split(" ")]

            # Set output
            stdout = None if configs["dumpcap"]["show stdout"] else subprocess.PIPE
            stderr = None if configs["dumpcap"]["show stdout"] else subprocess.PIPE

            # Platform-aware startup
            if os.name == "nt":
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                subprocess.Popen(parameters, startupinfo=startupinfo, stdout=stdout, stderr=stderr).wait()
            else:
                subprocess.Popen(parameters, stdout=stdout, stderr=stderr).wait()
    except:
        print_("dumpcap logger:", traceback.format_exc())

def eval_tool():
    import msvcrt
    
    def append_eval_string(string):
        global eval_string
        
        eval_string += string
        print(string, end = "", flush = True)
        
    def clear_eval_string():
        global eval_string

        print("\r" + " " * len(eval_string) + "\r", end = "")
        eval_string = ""
        append_eval_string(configs["eval"]["header"])

    def pop_eval_string():
        global eval_string

        if len(eval_string) > len(configs["eval"]["header"]):
            print("\r" + " " * len(eval_string) + "\r", end = "")
            eval_string = eval_string[:-1]
            print(eval_string, end = "", flush = True)

    def clear_screen():
        os.system("cls")
        clear_eval_string()

    def eval_eval_string():
        global eval_string

        eval_command = eval_string[len(configs["eval"]["header"]):]
        if eval_command in ["clear", "cls"]:
            clear_screen()
            return
        print_(eval_string)
        clear_eval_string()
        try:
            response = eval(eval_command)
        except SyntaxError:
            response = exec(eval_command)
        if response:
            print_("Response: {}".format(response))
        else:
            print_("Command executed.")

    while True:
        try:
            clear_eval_string()
            print_("Started eval tool.")
            while True:
                if msvcrt.kbhit():
                    char = msvcrt.getwch()
                    if char == "\r":
                        eval_eval_string()
                    elif char == "\b":
                        pop_eval_string()
                    elif char == chr(27):
                        clear_screen()
                    else:
                        append_eval_string(char)
        except:
            print_("eval tool:", traceback.format_exc())

def ip_list_server():
    def log(addr, log):
        print_("IP Server {}: {}".format(addr, log))
        
    while True:
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            print_("Listening on host: {host}, port: {port}".format(host = configs["ip list transmitter"]["host"], port = configs["ip list transmitter"]["port"]))
            server.bind((configs["ip list transmitter"]["host"], configs["ip list transmitter"]["port"]))
            server.listen(5)
            while True:
                client, addr = server.accept()
                message = client.recv(1024).decode()
                client.close()
                message = message.split("%")
                print_("Received new ip list message: {}".format(message))
                while (message):
                    param = message.pop(0)
                    directory_key = message.pop(0)
                    ip_list = ip_lists[directory_key]
                    if param in ["add", "remove"]:
                        ip_addresses = message.pop(0).split("&")
                    if param == "add":
                        for ip_address in ip_addresses:
                            ip_address = ipaddress.ip_address(ip_address)
                            if ip_list.add_ip(ip_address):
                                log(addr, "Added new ip address {} to ip list {}.".format(ip_address, directory_key))
                    elif param == "remove":
                        for ip_address in ip_addresses:
                            ip_address = ipaddress.ip_address(ip_address)
                            if ip_list.remove_ip(ip_address):
                                log(addr, "Removed current ip address {}, from ip list {}.".format(ip_address, directory_key))
                    elif param == "clear":
                        ip_list.clear()
                        log(addr, "Cleared ip list {}.".format(directory_key))
        except:
            print_("ip list server:", traceback.format_exc())

def ip_list_sync(message, log = None):
    if configs["ip list transmitter"]["active"] and configs["ip list transmitter"]["mode"] == "client":
        try:
            addr = (configs["ip list transmitter"]["host"], configs["ip list transmitter"]["port"])
            if log: print_("IP Sync {}: {}".format(addr, log))
            send_message(addr, message)
        except:
            print_("ip list sync:", traceback.format_exc())

try:
    print_("Loading...")
    import_configs(directories.configs)
    import_commands(directories.commands)

    if configs["IP UIDs"]["clean start"]:
        print_("Initaiting a clean start.")
    
    ip_lists = {
        directories.allowlist.key: IP_List(directories.allowlist, size = configs["IP UIDs"]["allowlist size"]),
        directories.blacklist.key: IP_List(directories.blacklist),
        directories.currentlist.key: IP_List(directories.currentlist, remote_controlled = configs["ip list transmitter"]["active"] and configs["ip list transmitter"]["mode"] == "server")
    }

    time.sleep(1)

    ip_uid_manager = IP_UID_Manager(directories.ip_uids)
    ip_uid_manager.import_directory()

    rule_list = list()
    if configs["advanced firewall"]["active"]:
        rule = Advanced_Firewall()
        if rule.defined:
            rule_list.append(rule)

    if configs["ipset"]["active"]:
        rule = IPSet()
        if rule.defined:
            rule_list.append(rule)

    if configs["google cloud"]["active"]:
        rule = Google_Cloud()
        if rule.defined:
            rule_list.append(rule)

    if configs["hetzner"]["active"]:
        rule = Hetzner()
        if rule.defined:
            rule_list.append(rule)

    if configs["pyshark"]["active"]:
        threading.Thread(target = pyshark_listener).start()
        threading.Thread(target = pyshark_verifier).start()

    if configs["cloudflare"]["active"]:
        threading.Thread(target = cloudflare_communicator).start()
        time.sleep(1)

    if configs["dumpcap"]["active"]:
        threading.Thread(target = dumpcap_logger).start()
        time.sleep(1)

    if configs["ip list transmitter"]["active"] and configs["ip list transmitter"]["mode"] == "server":
        threading.Thread(target = ip_list_server).start()
        time.sleep(1)

    rule_updater = Rule_Updater(rule_list)
    rule_updater.update = True
    rule_updater.force = True
    rule_updater.start()

    observer = Observer()
    observer.schedule(Event_Handler(), directories.data.string())
    observer.start()

    time.sleep(1)

    if configs["eval"]["active"]:
        time.sleep(1)
        threading.Thread(target = eval_tool).start()
except:
    print_(traceback.format_exc())
    input()
