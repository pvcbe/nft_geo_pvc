#!/usr/bin/env python3
"""
2024 pvc_be
GNU GENERAL PUBLIC LICENSE Version 3

nft_geo_pvc v0.9.0
https://github.com/pvcbe/nft_geo_pvc

generate a nft set from continent, country, region, city or asn from free https://db-ip.com/ databases
free db-ip.com databases are automatically downloaded by the script
all geo ip's will be added in one ipv4 set and one ipv6 set

example:
   ./nft_geo_pvc.py --country be
	    generate a set with default name: geo_set_ipv4 and geo_set_ipv6,
        saved in file /etc/geo_nft/geo_set.nft
        wich are usable in your own firewall rules
   ./nft_geo_pvc.py --country be --apply
	    generate AND apply a set with default name: geo_set_ipv4 and geo_set_ipv6,
        saved in file /etc/geo_nft/geo_set.nft
   ./nft_geo_pvc.py --country nl --set-name unwanted --apply
	    generate and apply a set with name: unwanted_ipv4 and unwanted_ipv6
        saved in file /etc/geo_nft/unwanted.nft
        wich are usable in your own firewall rules

   more examples at https://github.com/pvcbe/nft_geo_pvc/tree/main/example
"""
import argparse
import csv
import ipaddress
import time
import gzip
import sys
import subprocess
import datetime
import json
from pathlib import Path
import socket
try:
    import requests
except ImportError:
    print("i need the requests library to operate, please install with: pip3 install requests")
    sys.exit(1)


basepath = '/etc/geo_nft'
nft_path = '/usr/sbin/nft'


def pprint(text, quiet=False, error=False):
    if error is True:
        print(text, file=sys.stderr)
    else:
        if not quiet:
            print(text)


def find_one(search, search_list):
    return [s for s in search_list if s == search]


def asnfind(asn, asn_org, asn_filter_list):
    return [a for a in asn_filter_list if a == asn or a == asn_org]


def ip_validate_and_add_to_set(start_ip, stop_ip, ipv4, ipv6):
    try:
        ipaddress.IPv4Address(start_ip)
        ipaddress.IPv4Address(stop_ip)
        ipv4.add(start_ip + "-" + stop_ip)
    except ipaddress.AddressValueError:
        try:
            ipaddress.IPv6Address(start_ip)
            ipaddress.IPv6Address(stop_ip)
            ipv6.add(start_ip + "-" + stop_ip)
        except ipaddress.AddressValueError:
            pprint(f"WARNING: not an ip: {start_ip}  -  {stop_ip}", error=True)


def download(ap, db_country, db_city, db_asn):
    url = 'https://download.db-ip.com/free/'

    download_directory = Path(ap.database_path)
    if not download_directory.is_dir():
        download_directory.mkdir()

    for database_file_name in [db_country, db_city, db_asn]:
        database_file_target = Path(ap.database_path, database_file_name)
        if not database_file_target.is_file():
            try:
                r = requests.get(url + database_file_name + '.gz', stream=True)
                if r.status_code == 200:
                    pprint(f"downloading {database_file_name}", quiet=ap.quiet)
                    with database_file_target.open('wb') as target:
                        with gzip.GzipFile(fileobj=r.raw) as gz:
                            target.write(gz.read())
                else:
                    pprint(f"ERROR: while downloading {database_file_name}", error=True)
            except requests.exceptions.ConnectionError as e:
                pprint(f"ERROR: while downloading {database_file_name}", error=True)


def cleanup_downloads(ap, db_country, db_city, db_asn):
    glob = Path(ap.database_path).glob('dbip-*.csv')
    # don't delete files if there are only 3 left, this is to ensure there is a working db when downloads fail
    if len(list(glob)) <= 3:
        return
    for dpip_database in glob:
        if dpip_database.match(db_country) or dpip_database.match(db_city) or dpip_database.match(db_asn):
            continue
        dpip_database.unlink()

def get_valid_database_path(ap, db_name):
    # create glob patern
    db = db_name.replace(ap.datum, '*')

    glob_dbs = []
    for db_file in Path(ap.database_path).glob(db):
      glob_dbs.append(db_file)

    # sort found db's by modify time
    glob_dbs.sort(key=lambda k:k.stat().st_mtime)

    # last element is the newest, return it
    return_db = glob_dbs.pop()
    #pprint(f"selected db {return_db}")
    return return_db

def get_family_table(set_name):
    # detect under wich family and table the sets are loaded
    r = subprocess.run([nft_path, '--json', '--terse', 'list', 'sets'], capture_output=True)
    if r.returncode == 0:
        try:
            j = json.loads(r.stdout.decode())
            for el in j['nftables']:
                if 'set' in el:
                    if set_name == el['set']['name']:
                        return el['set']['family'], el['set']['table']
        except json.decoder.JSONDecodeError:
            pprint("ERROR: can't decode json set information", error=True)
    return None, None


def apply_sets(ap, family, table):
    # atomic update sets
    nft_update_file = Path(f"/var/lib/geo_nft_update_{ap.set_name}.nft")
    with nft_update_file.open('w') as geo_nft:
        date_string = datetime.datetime.now().isoformat()
        geo_nft.write(f"""# generated with pvc_geo_nft script on {date_string}

flush set {family} {table} {ap.set_name}_ipv4;
flush set {family} {table} {ap.set_name}_ipv6;
table {family} {table} """)
        geo_nft.write("{\n")
        geo_nft.write(f"""    include "{ap.target_file}";\n""")
        geo_nft.write("}\n")
    r = subprocess.run([nft_path, '-f', nft_update_file], capture_output=True)
    nft_update_file.unlink()
    if r.returncode == 0:
        pprint("sets applied", quiet=ap.quiet)
    else:
        pprint(
            f"error while activating set: \nvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv\n",
            error=True)
        pprint(r.stderr.decode(), error=True)

def split_arg_list(source_list):
    final_list = []
    for list_item in source_list:
      final_list += [element for element in list_item.split(",")]
    return final_list

def generate_sets(ap, db_country, db_city, db_asn):
    ipv4_set = set()
    ipv6_set = set()

    # custom ip's
    custom_ips_list = split_arg_list(ap.custom_ips)
    if custom_ips_list:
        for custom_ip in custom_ips_list:
            if '-' in custom_ip:
                try:
                    splited_custom_ip_start, splited_custom_ip_stop = custom_ip.split('-')
                    ip_validate_and_add_to_set(splited_custom_ip_start, splited_custom_ip_stop, ipv4_set, ipv6_set)
                except ValueError:
                    pprint(f"ERROR: invalid ip or range {custom_ip}")
            else:
                # value's added to set needs to be a string
                try:
                    ipv4_set.add(str(ipaddress.IPv4Network(custom_ip, strict=False)))
                except:
                    try:
                        ipv6_set.add(str(ipaddress.IPv6Network(custom_ip, strict=False)))
                    except:
                        try:
                            for ip in socket.getaddrinfo(custom_ip, 0):
                                if ip[1] is socket.SocketKind.SOCK_RAW and ip[0] is socket.AddressFamily.AF_INET:
                                    ipv4_set.add(str(ipaddress.IPv4Address(ip[4][0])))
                                if ip[1] is socket.SocketKind.SOCK_RAW and ip[0] is socket.AddressFamily.AF_INET6:
                                    ipv6_set.add(str(ipaddress.IPv6Address(ip[4][0])))
                        except socket.gaierror:
                            pprint(f"WARNING: host {custom_ip} not an ip address and not resolvable via dns",
                               error=True)

    # asn
    asn_filter_list = split_arg_list(ap.asn)
    if asn_filter_list:
        db = get_valid_database_path(ap, db_asn)
        if db.is_file():
            hit_asn = {}
            for asn in asn_filter_list:
                hit_asn[asn] = 0

            csv_reader = csv.reader(db.open())
            for line in csv_reader:
                if len(line) > 2:
                    start = line[0]
                    stop = line[1]
                    asn = line[2].lower()
                    as_org = line[3].lower()
                    af = asnfind(asn, as_org, asn_filter_list)
                    if af:
                        if asn in hit_asn:
                          hit_asn[asn] += 1
                        elif as_org in hit_asn:
                          hit_asn[as_org] += 1
                        ip_validate_and_add_to_set(start, stop, ipv4_set, ipv6_set)
            for a, hit in hit_asn.items():
                if hit == 0:
                    pprint(f"WARNING: no hit found for AS: {a}", error=True)
        else:
            pprint(f"ERROR: asn database {db} missing", error=True)


    # country
    country_filter_list = split_arg_list(ap.country)
    if country_filter_list:
        db = get_valid_database_path(ap, db_country)
        if db.is_file():
            hit_country = {}
            for c in country_filter_list:
                hit_country[c] = 0
            csv_reader = csv.reader(db.open())
            for line in csv_reader:
                if len(line) > 2:
                    start = line[0]
                    stop = line[1]
                    line_country = line[2].lower()
                    if find_one(line_country, country_filter_list):
                        hit_country[line_country] += 1
                        ip_validate_and_add_to_set(start, stop, ipv4_set, ipv6_set)
            for c, hit in hit_country.items():
                if hit == 0:
                    pprint(f"WARNING: no hit found for country: {c}", error=True)
        else:
            pprint(f"ERROR: country database {db} missing",  error=True)


    # continent, region, city
    continent_filter_list = split_arg_list(ap.continent)
    region_filter_list = split_arg_list(ap.region)
    city_filter_list = split_arg_list(ap.city)
    if continent_filter_list or region_filter_list or city_filter_list:
        db = get_valid_database_path(ap, db_city)
        if db.is_file():
            pprint("NOTICE: searching for continent, region or city data will take some time", quiet=ap.quiet)
            hits = {
                "continent": {},
                "region": {},
                "city": {},
            }
            for continent in continent_filter_list:
                hits["continent"][continent] = 0
            for region in region_filter_list:
                hits["region"][region] = 0
            for city in city_filter_list:
                hits["city"][city] = 0

            csv_reader = csv.reader(db.open())
            for line in csv_reader:
                if len(line) > 2:
                    start = line[0]
                    stop = line[1]
                    continent = line[2].lower()
                    region = line[4].lower()
                    city = line[5].lower()
                    if find_one(continent, continent_filter_list):
                        hits["continent"][continent] += 1
                        ip_validate_and_add_to_set(start, stop, ipv4_set, ipv6_set)
                    if find_one(region, region_filter_list):
                        hits["region"][region] += 1
                        ip_validate_and_add_to_set(start, stop, ipv4_set, ipv6_set)
                    if find_one(city, city_filter_list):
                        hits["city"][city] += 1
                        ip_validate_and_add_to_set(start, stop, ipv4_set, ipv6_set)
            for locality, hits_list in hits.items():
                for sub_locality, hits in hits_list.items():
                  if hits == 0:
                    pprint(f"WARNING: no hit found for {locality}: {sub_locality}", error=True)
        else:
            pprint(f"ERROR city database {db} missing", error=True)

    return sorted(list(ipv4_set)), sorted(list(ipv6_set))


def write_set(ap, ipv4, ipv6):
    with open(ap.target_file, "w") as geo_nft:
        date_string = datetime.datetime.now().isoformat()
        geo_nft.write(f"""# generated with pvc_geo_nft script on {date_string}
# used geo ip databases from https://db-ip.com with Creative Commons Attribution 4.0 International License

""")
        geo_nft.write("""
# load new sets
set %set_name%_ipv4 {
    type ipv4_addr
    flags interval
    auto-merge""".replace("%set_name%", ap.set_name))
        if ipv4:
            geo_nft.write("""
    elements = {
\t""")
            geo_nft.write(",\n\t".join(ipv4))
            geo_nft.write("""
    }""")
        geo_nft.write("""
  }

set %set_name%_ipv6 {
    type ipv6_addr
    flags interval
    auto-merge""".replace("%set_name%", ap.set_name))
        if ipv6:
            geo_nft.write("""
    elements = {
\t""")
            geo_nft.write(",\n\t".join(ipv6))
            geo_nft.write("""
     }""")
        geo_nft.write("""
}""")


def query_line(query_ips, line):
    line_start_ip = line[0]
    line_end_ip = line[1]
    try:
        start_ip = ipaddress.IPv4Address(line_start_ip)
        end_ip = ipaddress.IPv4Address(line_end_ip)
    except:
        try:
            start_ip = ipaddress.IPv6Address(line_start_ip)
            end_ip = ipaddress.IPv6Address(line_end_ip)
        except:
            return

    for query_ip in query_ips:
        if type(query_ip) is type(start_ip):
            if start_ip <= query_ip <= end_ip:
                return query_ip
    return None


def query_host(ap, db_country, db_city, db_asn):
    query_ips = set()
    try:
        query_ips.add(ipaddress.IPv4Address(ap.query_host))
    except ipaddress.AddressValueError:
        try:
            query_ips.add(ipaddress.IPv6Address(ap.query_host))
        except ipaddress.AddressValueError:
            try:
                for ip in socket.getaddrinfo(ap.query_host, 0):
                    if ip[1] is socket.SocketKind.SOCK_RAW and ip[0] is socket.AddressFamily.AF_INET:
                        query_ips.add(ipaddress.IPv4Address(ip[4][0]))
                    if ip[1] is socket.SocketKind.SOCK_RAW and ip[0] is socket.AddressFamily.AF_INET6:
                        query_ips.add(ipaddress.IPv6Address(ip[4][0]))
            except socket.gaierror:
                pprint(f"sorry, query host {ap.query_host} not an ip address and not resolvable via dns", error=True)
                return
    print("query host resolving resulted in the following ip's:")
    match = {}
    for ip in query_ips:
        print(f"- {ip}")
        match[ip] = {
            "country": set(),
            "asn": set(),
            "as_name": set(),
            "city": set(),
            "continent": set(),
            "region": set()
        }

    print("searching databases, the csv databases are not search optimized so this can take a while...")
    for database in [(db_country, "country"), (db_city, "city"), (db_asn, "asn")]:
    #for db in [(db_country, "country"), (db_asn, "asn")]:
        database_name = database[1]
        csv_file = Path(ap.database_path, database[0])
        if csv_file.is_file():
            csv_reader = csv.reader(csv_file.open())
            for line in csv_reader:
                if len(line) > 2:
                    ip = query_line(query_ips, line)
                    if ip:
                        if database_name == "country":
                            match[ip][database_name].add(line[2])
                        elif database_name == "asn":
                            match[ip][database_name].add(line[2])
                            match[ip]["as_name"].add(line[3])
                        elif database_name == "city":
                            match[ip][database_name].add(line[5])
                            match[ip]["continent"].add(line[2])
                            match[ip]["region"].add(line[4])
    print("\ngeoip info:")
    for ip, value in match.items():
        print(f"\n- {ip}")
        for item, info in value.items():
            print("  -", item.ljust(10), "-" if not list(info) else "; ".join(list(info)) )

def detect_nftables():
    try:
        r = subprocess.run([nft_path, '--version'], capture_output=True)
        if r.returncode == 0:
            return True
    except FileNotFoundError:
        return False


def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description=__doc__)
    parser.add_argument('-a', '--asn',
                        nargs='+',
                        type=str.lower,
                        default=[],
                        help='wich autonomous system numbers or names should the set contain, exact match, case insensitive')
    parser.add_argument('--continent',
                        nargs='+',
                        type=str.lower,
                        default=[],
                        help='wich continent should the set contain, use 2 letter iso continent code, case insensitive')
    parser.add_argument('-c', '--country',
                        nargs='+',
                        type=str.lower,
                        default=[],
                        help='wich countries should the set contain, use 2 letter iso country code, case insensitive')
    parser.add_argument('--region',
                        nargs='+',
                        type=str.lower,
                        default=[],
                        help='wich regions should the set contain, exact match, case insensitive')
    parser.add_argument('--city',
                        nargs='+',
                        type=str.lower,
                        default=[],
                        help='wich cities should the set contain, exact match, case insensitive')
    parser.add_argument('--custom-ips',
                        nargs='+',
                        type=str.lower,
                        default=[],
                        help='add extra ip, range, subnet or hostname from this list, working dns needed for hostnames\n'
                             'nft_geo_pvc.py --custom-ips 1.1.1.1 www.google.com 192.168.1.0/24 2a00:1450:4001:111::-2a00:1450:4001:666::')
    parser.add_argument('--set-name',
                        default='geo_set',
                        help='what should be the nftables set name, saved set wil be located under /etc/geo_nft/<set-name>.nft')
    parser.add_argument('--database-path',
                        default='/var/lib/dbip',
                        help='where to store the downloaded db\'s (default /var/lib/dbip)')
    parser.add_argument('--query-host',
                        help='search for a match in the db-ip databases, print the information and exit')
    parser.add_argument('--apply',
                        action='store_true',
                        default=False,
                        help='apply the set after generation')
    parser.add_argument('-q', '--quiet',
                        action='store_true',
                        default=False,
                        help='make the script quiet')
    ap = parser.parse_args()

    ap.datum = time.strftime("%Y-%m")
    db_country = f"dbip-country-lite-{ap.datum}.csv"
    db_city = f"dbip-city-lite-{ap.datum}.csv"
    db_asn = f"dbip-asn-lite-{ap.datum}.csv"

    download(ap, db_country, db_city, db_asn)
    cleanup_downloads(ap, db_country, db_city, db_asn)
    if not detect_nftables():
        print("nftables binary not found or in path, i cannot work without it exiting")
        sys.exit()

    if ap.query_host:
        print(f"searching the databases for: {ap.query_host}")
        query_host(ap, db_country, db_city, db_asn)
        sys.exit()
    elif ap.continent == [] and ap.region == [] and ap.country == [] and ap.city == [] and ap.asn == [] and ap.custom_ips == []:
        parser.print_help()
        pprint("\n\nno continent, country, region, city, asn or custom ip's specified\n"
               "exiting", error=True)
        sys.exit()

    bp = Path(basepath)
    bp.mkdir(exist_ok=True)

    ap.target_file = bp / f"{ap.set_name}.nft"
    pprint(f"""generating {ap.target_file} with set name {ap.set_name}_ipv4 and {ap.set_name}_ipv6 for:
    * custom ip's:       {'-' if not ap.custom_ips else ', '.join(ap.custom_ips)}
    * autonomous system: {'-' if not ap.asn else ', '.join(ap.asn)}
    * continents:        {'-' if not ap.continent else ', '.join(ap.continent)}
    * countries:         {'-' if not ap.country else ', '.join(ap.country)}
    * regions:           {'-' if not ap.region else ', '.join(ap.region)}
    * cities:            {'-' if not ap.city else ', '.join(ap.city)}""",
           quiet=ap.quiet)

    ipv4, ipv6 = generate_sets(ap, db_country, db_city, db_asn)

    if not ipv4:
        pprint("WARNING: ipv4 set is empty", error=True)
    if not ipv6:
        pprint("WARNING: ipv6 set is empty", error=True)

    # even if the sets are empty, write the config so that nftables includes still work
    write_set(ap, ipv4, ipv6)

    if ap.apply is True:
        family, table = get_family_table(f"{ap.set_name}_ipv4")
        if family and table:
            apply_sets(ap, family, table)
        else:
            pprint('set not detected in live configuration, set is saved but not applied!', error=True)

    pprint('done', quiet=ap.quiet)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("exited by KeyboardInterrupt")

