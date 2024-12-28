this wil allow all traffic but drop traffic originating from The netherlands

# step 1: generate geo set

    nft_geo_pvc.py --country nl

# step 2: firewall configuration

/etc/nftables.conf

    #!/usr/sbin/nft -f
    
    flush ruleset

    table inet raw {
        # load generated set from file
        include "/etc/geo_set.nft"

        # drop as early as possible
        chain PREROUTING {
            type filter hook prerouting priority -300;
            # eth0 is the public interface
            # log and drop traffic that is in the geo_set_*
            iifname eth0 ip saddr @geo_set_ipv4 log prefix "fw:geo:drop ";
            iifname eth0 ip saddr @geo_set_ipv4 drop;
            iifname eth0 ip6 saddr @geo_set_ipv6 log prefix "fw:geo:drop ";
            iifname eth0 ip6 saddr @geo_set_ipv6 drop;
        }
    }

now activate the nftables configuration

    nft -f /etc/nftables.conf

watch the syslog for geo ip dropped traffic

    tail -F /var/log/syslog | grep "fw:geo:"

# optional: update list
updating the geo ip set is possible without reloading te firewall

    nft_geo_pvc.py --country nl --apply

it is recommended to do this at least monthly, as the free db-ip.com databases are updated monthly 

succes!