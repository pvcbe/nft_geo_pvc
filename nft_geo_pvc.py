#!/usr/bin/env python3
"""
2024 pvc_be

downloads and generate a nft set from country, city or asn from free https://db-ip.com/ databases
all filters will be added in one ipv4 set and one ipv6.  set table and name is selectable

example:
   ./nft-geo.py --country be
	generate a sets with default name: geo_set_ipv4 and geo_set_ipv6,
        stored in file /etc/geo_set.nft
        the sets are now usable in your own firewall rules under the "raw" table
   ./nft-geo.py --country be --apply
	generate and apply a sets with default name: geo_set_ipv4 and geo_set_ipv6,
        stored in file /etc/geo_set.nft
        the sets are now usable in your own firewall rules under the "raw" table
   ./nft-geo.py --country nl --set-prefix unwanted --nft-table filter --apply
	generate and apply a sets with name: unwanted_ipv4 and unwanted_ipv6
        stored in file /etc/unwanted.nft
        wich are usable in your own firewall rules under the "filter" table
"""
# license gpl3

import argparse
import requests
import csv
import ipaddress
import time
import gzip
import sys
import subprocess
import datetime
from pathlib import Path


def pprint(text, quiet=False, error=False):
    if error is True:
        print(text, file=sys.stderr)
    else:
        if not quiet:
            print(text)


def find_one(search, search_list):
    return [s for s in search_list if s == search]


def asnfind(asn, asn_org, asns):
    return [a for a in asns if a == asn or a == asn_org]


def ip_validate(start, stop, ipv4, ipv6):
    try:
        ipaddress.IPv4Address(start)
        ipaddress.IPv4Address(stop)
        ipv4.add(start + "-" + stop)
    except ipaddress.AddressValueError:
        try:
            ipaddress.IPv6Address(start)
            ipaddress.IPv6Address(stop)
            ipv6.add(start + "-" + stop)
        except ipaddress.AddressValueError:
            pprint(f"not an ip: {start}  -  {stop}", ap.quiet, error=True)


def download(ap, db_country, db_city, db_asn):
    directory = Path(ap.database_path)
    if not directory.is_dir():
        directory.mkdir()

    url = 'https://download.db-ip.com/free/'

    for f in [db_country, db_city, db_asn]:
        p = Path(ap.database_path, f)
        if not p.is_file():
            try:
                r = requests.get(url + f + '.gz', stream=True)
                if r.status_code == 200:
                    pprint(f"downloading {f}", quiet=ap.quiet)
                    with p.open('wb') as target:
                        with gzip.GzipFile(fileobj=r.raw) as gz:
                            target.write(gz.read())
                else:
                    pprint(f"error while downloading {f}", error=True)
            except requests.exceptions.ConnectionError as e:
                pprint(f"error while downloading {f}", error=True)


def cleanup_downloads(ap, db_country, db_city, db_asn):
    glob = Path(ap.database_path).glob('dbip-*.csv')
    for file in glob:
        if file.match(db_country) or file.match(db_city) or file.match(db_asn):
            continue
        file.unlink()

def flush_sets(ap):
    # flush existing sets
    for ip_family in "ipv4 ipv6".split():
        # detect if set exists
        r = subprocess.run(['nft', '--terse', 'list', 'set', 'inet', ap.nft_table, ap.set_prefix + '_' + ip_family],
                           capture_output=True)
        if r.returncode == 0:
            pprint('flusing existing set ' + ap.set_prefix + '_' + ip_family, quiet=ap.quiet)
            # if set exists flush it
            r = subprocess.run(['nft', 'flush', 'set', 'inet', ap.nft_table, ap.set_prefix + '_' + ip_family],
                               capture_output=True)
            """
            if r.returncode != 0:
                pprint(
                    f"error while flushing set: \nvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv\n",
                    error=True)
                pprint(r.stderr.decode(), error=True)
            """


def generate_sets(ap, db_country, db_city, db_asn):
  ipv4_set = set()
  ipv6_set = set()

  # countries
  if ap.country:
    db = Path(ap.database_path, db_country)
    if db.is_file():
      csv_reader = csv.reader(db.open())
      for line in csv_reader:
        if len(line) > 2:
          start = line[0]
          stop = line[1]
          country = line[2].lower()
          if find_one(country, ap.country):
            ip_validate(start, stop, ipv4_set, ipv6_set)
    else:
      pprint(f"country database {db} missing", quiet=ap.quiet, error=True)

  # city
  if ap.city:
    db = Path(ap.database_path, db_city)
    if db.is_file():
      csv_reader = csv.reader(db.open())
      for line in csv_reader:
        if len(line) > 2:
          start = line[0]
          stop = line[1]
          city = line[5].lower()
          if find_one(city, ap.city):
            ip_validate(start, stop, ipv4_set, ipv6_set)
    else:
      pprint(f"city database {db} missing", quiet=ap.quiet, error=True)

  # asn's
  if ap.asn:
    db = Path(ap.database_path, db_asn)
    if db.is_file():
      csv_reader = csv.reader(db.open())
      for line in csv_reader:
        if len(line) > 2:
          start = line[0]
          stop = line[1]
          asn = line[2].lower()
          as_org = line[3].lower()
          af = asnfind(asn, as_org, ap.asn)
          if af:
            ip_validate(start, stop, ipv4_set, ipv6_set)
    else:
      pprint(f"asn database {db} missing", quiet=ap.quiet, error=True)

  return sorted(list(ipv4_set)) , sorted(list(ipv6_set))

def write_set(ap, ipv4, ipv6):
    with open(ap.target_file, "w") as geo_nft:
        date_string = datetime.datetime.now().isoformat()
        geo_nft.write(f"""# generated with pvc_geo_nft script on {date_string}
# used geo ip databases from https://db-ip.com with Creative Commons Attribution 4.0 International License

""")
        geo_nft.write("""
# load new sets
table inet %set_table% {
  set %set_prefix%_ipv4 {
    type ipv4_addr
    flags interval
    auto-merge""".replace("%set_prefix%", ap.set_prefix).replace("%set_table%", ap.nft_table))
        if ipv4:
            geo_nft.write("""
    elements = {
\t""")
            geo_nft.write(",\n\t".join(ipv4))
            geo_nft.write("""
    }""")
        geo_nft.write("""
  }

  set %set_prefix%_ipv6 {
    type ipv6_addr
    flags interval
    auto-merge""".replace("%set_prefix%", ap.set_prefix))
        if ipv6:
            geo_nft.write("""
    elements = {
\t""")
            geo_nft.write(",\n\t".join(ipv6))
            geo_nft.write("""
    }""")
        geo_nft.write("""
  }
}""")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description=__doc__)
    parser.add_argument('-a', '--asn',
                        nargs='+',
                        type=str.lower,
                        default=[],
                        help='wich autonomous system numbers or names should the set contain, exact match, case insensitive')
    parser.add_argument('-c', '--country',
                        nargs='+',
                        type=str.lower,
                        default=[],
                        help='wich countries should the set contain, use 2 letter iso country code, case insensitive')
    parser.add_argument('--city',
                        nargs='+',
                        type=str.lower,
                        default=[],
                        help='wich cities should the set contain, exact match, case insensitive')
    parser.add_argument('--set-prefix',
                        default='geo_set',
                        help='what should be the nftables set prefix name')
    #parser.add_argument('-t', '--target-file',
    #                    default='/etc/geo_set.nft',
    #                    help='where to save the generated set')
    parser.add_argument('--nft-table',
                        default='raw',
                        help='the table name used in the nft set\'s, default is raw')
    parser.add_argument('--database-path',
                        default='/var/lib/dbip',
                        help='where to store the downloaded db\'s')
    parser.add_argument('--apply',
                        action='store_true',
                        default=False,
                        help='apply the set after generation')
    parser.add_argument('-q', '--quiet',
                        action='store_true',
                        default=False,
                        help='make the script quiet')
    ap = parser.parse_args()

    if ap.country == [] and ap.city == [] and ap.asn == []:
        parser.print_help()
        pprint("\n\nno country, city or asn specified", error=True)
        sys.exit()

    datum = time.strftime("%Y-%m")
    db_country = f"dbip-country-lite-{datum}.csv"
    db_city = f"dbip-city-lite-{datum}.csv"
    db_asn = f"dbip-asn-lite-{datum}.csv"

    download(ap, db_country, db_city, db_asn)
    cleanup_downloads(ap, db_country, db_city, db_asn)

    ap.target_file = f"/etc/{ap.set_prefix}.nft"
    pprint(f"""generating {ap.target_file} with set prefix {ap.set_prefix} for:
- autonomous system: {', '.join(ap.asn)}
- countries:         {', '.join(ap.country)}
- cities:            {', '.join(ap.city)}""", quiet=ap.quiet)

    ipv4, ipv6 = generate_sets(ap, db_country, db_city, db_asn)

    if not ipv4:
        pprint("WARNING: ipv4 set is empty", error=True)
    if not ipv6:
        pprint("WARNING: ipv6 set is empty", error=True)

    write_set(ap, ipv4, ipv6)

    if ap.apply is True:
        flush_sets(ap)

        r = subprocess.run(['nft', '-f', ap.target_file], capture_output=True)
        if r.returncode != 0:
            pprint(
                f"error while apply of nft set: \nvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv\n",
                error=True)
            pprint(r.stderr.decode(), error=True)
        else:
            pprint('applied', quiet=ap.quiet)

    pprint('done', quiet=ap.quiet)
