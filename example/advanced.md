in this example the firewall will only accept traffic from belgium to ports 80 and 443
and rate limit all traffic from The netherlands
other traffic is accepted

# step 1: generate geo set

    # generate the allow list with the default prefix: geo_set_ipv4 and geo_set_ipv6
    nft_geo_pvc.py --country be
    # this will create a set with prefix ratelimit (generates ratelimit_ipv4 and ratelimit_ipv6) for dutch ip's
    # in the "filter" table and save the set in /etc/geo_nft/ratelimit.nft
    nft_geo_pvc.py --set-prefix ratelimit --country nl

# step 2: firewall configuration


    #!/usr/sbin/nft -f
    # eth0 is the public interface

    flush ruleset

    table inet filter {
        # load generated set from file
        include "/etc/geo_nft/ratelimit.nft";
    
        chain input {
            type filter hook input priority 0;
            iifname eth0 ip saddr @ratelimit_ipv4 limit rate over 10/second log prefix "fw:ratelimit " counter drop;
            iifname eth0 ip6 saddr @ratelimit_ipv6 limit rate over 10/second log prefix "fw:ratelimit " counter drop;
        }
    }

    table inet raw {
        # load generated set from file
        include "/etc/geo_nft/geo_set.nft";

        # drop as early as possible
        chain PREROUTING {
            type filter hook prerouting priority -300;

            define protected_ports = { 80, 443 }

            # allow traffic to the protected ports from ip's in the sets
            iifname eth0 ip saddr @geo_set_ipv4 tcp dport $protected_ports accept;
            iifname eth0 ip6 saddr @geo_set_ipv6 tcp dport $protected_ports accept;
            # log and drop all other traffic that is not in the geo_set_*
            iifname eth0 tcp dport $protected_ports log prefix "fw:geo:drop " counter drop;        
        }
    }

   
now activate the nftables configuration

    nft -f /etc/nftables.conf

watch the syslog for geo ip dropped traffic

    tail -F /var/log/syslog | grep "fw:geo:"

succes!