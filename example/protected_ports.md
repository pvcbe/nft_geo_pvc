in this example the firewall will only accept traffic from cloudflare (as13335) to ports 80 and 443
other traffic to 80 and 443 is not allowed

# step 1: generate geo set

    ./nft_geo_pvc.py --asn 13335

# step 2: firewall configuration


    #!/usr/sbin/nft -f

    flush ruleset

    # load generated set from file
    include "/etc/geo_set.nft"

    table inet raw {

        # drop as early as possible
        chain PREROUTING {
        type filter hook prerouting priority -300;
        
	    # eth1 is the public interface
        define protected_ports = { 80, 443 }

        # allow traffic to the protected ports from ip's in the sets
        iifname eth1 ip saddr @geo_set_ipv4 tcp dport $protected_ports accept;
        iifname eth1 ip6 saddr @geo_set_ipv6 tcp dport $protected_ports accept;
        # log and drop all other traffic that is not in geo_set_ipv4 or geo_set_ipv6
        iifname eth1 tcp dport $protected_ports log prefix "fw:geo:drop ";
        iifname eth1 tcp dport $protected_ports counter drop;
      }
    }
   
now activate the nftables configuration

    nft -f /etc/nftables.conf

watch the syslog for geo ip dropped traffic

    tail -F /var/log/syslog | grep "fw:geo:"

# optional: update list
updating the geo ip set is possible without reloading te firewall

    ./nft_geo_pvc.py --asn 13335 --apply

it is recommended to do this at least monthly, as the free db-ip.com databases are updated monthly 

succes!