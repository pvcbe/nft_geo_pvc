script to generate nftables sets from geoip data: ASN, country and city

features:
- create a *COMBINED* nftables set from:
  - as number
  - as name
  - country
  - city
- auto download free db-ip.com databases, with cleanup of old files
- update the geo set without flushing nftables (atomic update)
- custom set name possible
- custom table name possible
- low memory consumption, only selected data (country, asn, city) is loaded


# install

    # the script needs python requests to function
    pip3 install requests
    wget https://raw.githubusercontent.com/pvcbe/nft_geo_pvc/refs/heads/main/nft_geo_pvc.py \
      -O /usr/local/bin/nft_geo_pvc.py
    chmod +x /usr/local/bin/nft_geo_pvc.py 
    

# use 

## step 1: generate list
generate a set that contains:
- all ip's from Belgium AND 
- all ip's from cloudflare (as 13335) AND
- all ip's from hetzner

         nft_geo_pvc.py --country be --asn 13335 "Hetzner Online GmbH"
    
         downloading dbip-country-lite-2024-12.csv
         downloading dbip-city-lite-2024-12.csv
         downloading dbip-asn-lite-2024-12.csv
         generating /etc/geo_set.nft with set prefix geo_set for:
         - autonomous system: 13335, hetzner online gmbh
         - countries:         be
         - cities:
         done

now we have a combined nftables set in */etc/geo_set.nft* 

## step 2: use geo set
we can now use this file in our main firewall script [/etc/nftables]
the default set names are *geo_set_ipv4* and *geo_set_ipv6*

    flush ruleset

    # load generated set from file
    include "/etc/geo_set.nft"

    table inet raw {
      # drop as early as possible
      chain PREROUTING {
            type filter hook prerouting priority -300;
    
            # eth1 is the public interface
            iifname eth1 ip saddr @geo_set_ipv4 accept;
            iifname eth1 ip6 saddr @geo_set_ipv6 accept;
            # log and drop all other traffic that is not in the geo_set_*
            iifname eth1 log prefix "fw:geo:drop " counter drop;
      }
    }
   

## step 3: (optional) update geo ip set
As an example we add the city of Himeji to the set.  
The following command generates, saves AND applies a new set without reloading the firewall.
Only the geo_set_* will be updated, no changes are applied to the main nftables configuration.
Can be uses in a cronjob or triggerd manually.

    nft_geo_pvc.py --country be --asn 13335 "Hetzner Online GmbH" --city himeji --apply

    generating /etc/geo_set.nft with set prefix geo_set for:
    - autonomous system: 13335, hetzner online gmbh
    - countries:         be
    - cities:            himeji
    applied
    done

# philosofie
generate a named nft set with the option of combining different sources (country, city, asn) 
and using the set in your nftables script.  
updating of the sets can happen atomic  without reloading the firewall. (without interruption or resetting the counters)



# update geo ip sets
it is recommended to run the nft_geo_pvc.py script monthly as the free db-ip.com databases are updated monthly

