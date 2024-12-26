this wil allow all traffic from Japan and drop all other traffic

# step 1: generate geo set

    nft_geo_pvc.py --country jp

# step 2: firewall configuration

/etc/nftables.conf

    #!/usr/sbin/nft -f

    flush ruleset

    # include the generated set from file
    include "/etc/geo_set.nft"

    table inet raw {
      # drop as early as possible
      chain PREROUTING {
            type filter hook prerouting priority -300;

            # eth1 is the public interface
            iifname eth1 ip saddr @geo_set_ipv4 accept;
            iifname eth1 ip6 saddr @geo_set_ipv6 accept;
            # log and drop all other traffic that is not in the geo_set_*
            iifname eth1 log prefix "fw:geo:drop ";
            iifname eth1 counter drop;
      }
    }


now activate the nftables configuration

    nft -f /etc/nftables.conf

watch the syslog for geo ip dropped traffic

    tail -F /var/log/syslog | grep "fw:geo:"

# optional: update list
updating the geo ip set is possible without reloading te firewall

    nft_geo_pvc.py --country jp --apply

it is recommended to do this at least monthly, as the free db-ip.com databases are updated monthly 

succes!