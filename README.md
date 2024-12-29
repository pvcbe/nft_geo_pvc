## Introduction
script to generate nftables sets from geoip data: continent, region, country, city or asn

## features
* create a *COMBINED* nftables set from selected data (possible, not mandatory):
  * continent (use 2 letter [iso](https://en.wikipedia.org/wiki/ISO_3166-1) continent code)
  * region
  * country (use 2 letter [iso](https://en.wikipedia.org/wiki/ISO_3166-1) country code)
  * city
  * [AS number](https://en.wikipedia.org/wiki/Autonomous_system_%28Internet%29) (isp unique number)
  * AS name (isp unique name)

* uses the free db-ip.com lite csv databases (https://db-ip.com/db/lite.php)
* auto download db-ip.com databases, with cleanup of old databases
* update the geo set without flushing nftables (atomic update)
* low memory consumption, only selected data is generated and loaded
* custom set name possible (default names are geo_set_ipv4 and geo_set_ipv6)
* query host/ip for 
* detects if continent, region, country, city or ASn returned no data (helpfull for typo detection)
* warns for empty sets 

## install

    # the script needs python requests to function
    pip3 install requests
    wget https://raw.githubusercontent.com/pvcbe/nft_geo_pvc/refs/heads/main/nft_geo_pvc.py \
      -O /usr/local/bin/nft_geo_pvc.py
    chmod +x /usr/local/bin/nft_geo_pvc.py 

if you want to **remove** te script:

    rm /usr/local/bin/nft_geo_pvc.py
 
## use 

### step 1: generate list
generate a set that contains:
* all ip's from Belgium, use country code be

         nft_geo_pvc.py --country be
    
         generating /etc/geo_nft/geo_set.nft with set name geo_set for:
         * autonomous system: -
         * continents:        -
         * regions:           -
         * countries:         be
         * cities:            -
         done

now we have a geo nftables set in */etc/geo_nft/geo_set.nft* 

### step 2: use geo set
we can now use this set file in our example firewall script */etc/nftables.conf*
the default set names are *geo_set_ipv4* and *geo_set_ipv6*

    flush ruleset

    table inet filter {
      # load generated set from file
      include "/etc/geo_nft/geo_set.nft"

      chain input {
            type filter hook input priority 0;
    
            # eth0 is the public interface, geo_set_ipv4 and geo_set_ipv6 are the default names.
            iifname eth0 ip saddr @geo_set_ipv4 accept;
            iifname eth0 ip6 saddr @geo_set_ipv6 accept;
            # log and drop all other traffic that is not in the geo_set_*
            iifname eth0 log prefix "fw:geo:drop " counter drop;
      }
    }
   

### step 3: (optional) update geo ip set
As an example we add the ASn of Hetzner AND city of Himeji to the set.  
The following command generates, saves (under /etc/geo_nft/) AND applies a new set without reloading the firewall.
Only the geo_set_* will be updated, no changes are applied to the running nftables configuration.  
nftables state and counters are thus preserved.  
Can be uses in a cronjob or triggerd manually.

    nft_geo_pvc.py --country be --asn "Hetzner Online GmbH" --city himeji --apply

    generating /etc/geo_nft/geo_set.nft with set name geo_set for:
    * autonomous system: hetzner online gmbh
    * continents:        -
    * regions:           -
    * countries:         be
    * cities:            himeji
    sets applied
    done


## philosofie
generate a named nft set with the option of combining different selection criteria: continent, region, country, city, ASn 
and using the set in your nftables script.  
updating of the sets can happen atomic without reloading the firewall. (without interruption or resetting the counters)


## notes
* using the continent, region or city selector is slow, this is not a bug.  
  The script needs to loop all lines in a big csv database to get this data.
  Country and ASn data are faster because the database is smaller
* AS information can be found:
  * running
  
        nft_geo_pvc.py --query-host <host or ip>

  * searching by name or number at https://bgp.tools/ 
  * searching with a known ip https://db-ip.com/
* it is recommended to run script at least monthly, as the free db-ip.com databases are updated monthly

