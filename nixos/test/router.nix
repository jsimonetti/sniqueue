let
  wan = "eth2";
  lan = "eth1";
  router_wanip = "192.168.8.1";
  router_lanip = "10.10.1.1";

  sniqueue = ./sniqueue;
  list = ./mylist.sample;
in { config, pkgs, ... }: {
  boot.kernel.sysctl = { "net.ipv4.conf.all.forwarding" = true; };

  systemd.services.sniqueue = {
    wantedBy = [ "multi-user.target" ]; 
    after = [ "network.target" ];
    script = ''
      ${sniqueue} -queue 100 -mark 100 -debug -list ${list}
    '';
  };

  environment.systemPackages = [ pkgs.conntrack-tools ];

  networking.interfaces.${wan} = {
    useDHCP = false;
    ipv4.addresses = [{
      address = router_wanip;
      prefixLength = 24;
    }];
  };
  networking.interfaces.${lan} = {
    useDHCP = false;
    ipv4.addresses = [{
      address = router_lanip;
      prefixLength = 24;
    }];
  };
  networking.firewall.enable = false;
  networking.nftables.enable = true;
  networking.nftables.ruleset = ''
    table inet filter {
      flowtable f {
        hook ingress priority 0; devices = { ${wan}, ${lan} };
      }

      set blocklist4 {
        type ipv4_addr
        timeout 10s
      }

      set blocklist6 {
        type ipv6_addr
        timeout 5m
      }

      chain output {
        type filter hook output priority 0; policy accept;
      }

      chain input {
        type filter hook input priority 0; policy drop;
        iifname "${lan}" accept
        iifname "${wan}" ct state { established, related } accept
        iifname "${wan}" drop
      }

      chain sniqueue {
        type filter hook forward priority -2; policy accept;
        ip daddr @blocklist4 tcp dport 443 reject
        ip daddr @blocklist4 udp dport 443 reject
        ip6 daddr @blocklist6 tcp dport 443 reject
        ip6 daddr @blocklist6 udp dport 443 reject

        ct mark 101 accept comment "Accept known good SNI not yet offloaded"
        ct mark 100 reject comment "Reject known bad SNI"
        tcp dport 443 ct mark set 102 comment "Mark all unjudged packets"
        udp dport 443 ct mark set 102 comment "Mark all unjudged packets"
        meta mark set ct mark
        tcp dport 443 ct original packets <20 queue num 100 bypass
        udp dport 443 ct original packets <20 queue num 100 bypass
      }

      chain sniqueue_block {
        type filter hook forward priority -1; policy accept;
        ip protocol { tcp, udp } meta mark 100 add @blocklist4 { ip daddr }
        ip6 nexthdr { tcp, udp } meta mark 100 add @blocklist6 { ip6 daddr }
        ct mark set meta mark
        ct mark 102 accept comment "Accept packets without verdict"
        ct mark 100 reject comment "Reject known bad"
        ct mark 101 flow offload @f comment "Offload known good SNI"
      }

      chain forward {
        type filter hook forward priority 0; policy drop;
        ct mark != 102 flow offload @f comment "Offload packets not sent to SNIqueue"

        iifname "${lan}" oifname "${wan}" accept
        iifname "${wan}" oifname "${lan}" ct state established,related accept
      }
    }

    table ip nat {
      chain prerouting {
        type nat hook output priority 0; policy accept;
      }

      # Setup NAT masquerading on the wan interface
      chain postrouting {
        type nat hook postrouting priority 0; policy accept;
        oifname "${wan}" masquerade
      }
    }
  '';
}
