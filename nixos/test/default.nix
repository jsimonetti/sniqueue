let
  pkgs = import <nixos> { };
  server_ip = "192.168.8.2";
  router_wanip = "192.168.8.1";
  router_lanip = "10.10.1.1";
  client_ip = "10.10.1.10";
in
pkgs.nixosTest ({
  system = "x86_64-linux";
  nodes = {
    router = {
      virtualisation.vlans = [ 1 2 ];
      imports = [ ./router.nix ];
    };
    server = { config, pkgs, ... }: {
      virtualisation.vlans = [ 2 ];
      networking.firewall.enable = false;
      networking.interfaces.eth1.useDHCP = false;
      networking.interfaces.eth1.ipv4.addresses = [{
        address = server_ip;
        prefixLength = 24;
      }];
      services.nginx.enable = true;
      services.nginx.package = pkgs.nginxQuic;
      services.nginx.virtualHosts."dns.google" = {
        addSSL = true;
        default = true;
        http3 = true;
        sslCertificate = ./nginx-selfsigned.crt;
        sslCertificateKey = ./nginx-selfsigned.key;
      };
    };
    client = { config, pkgs, nodes, ... }: {
      virtualisation.vlans = [ 1 ];
      networking.interfaces.eth1.useDHCP = false;
      networking.interfaces.eth1.ipv4.addresses = [{
        address = client_ip;
        prefixLength = 24;
      }];
      networking.defaultGateway = router_lanip;
    };
  };
  testScript = ''
    router.start()
    server.start()
    client.start()

    router.wait_for_unit("network.target")
    server.wait_for_unit("network.target")
    server.wait_for_unit("nginx.service")

    # Test input/output firewall
    #print(router.succeed("systemctl status -l nftables.service"))
    router.wait_for_unit("nftables.service")
    router.succeed("ping -c 1 ${server_ip} >&2")
    server.fail("ping -W 2 -c 1 ${router_wanip} >&2")

    # Test ICMP.
    client.wait_for_unit("network.target")
    router.succeed("ping -c 1 ${client_ip} >&2")
    client.succeed("ping -c 1 ${router_lanip} >&2")

    # Test NAT
    client.succeed("ping -c 1 ${server_ip} >&2")

    # Test no SNI is not blocked
    client.succeed("curl --connect-timeout 2 --fail -k https://${server_ip}/ >&2")

    # Test SNIqueue blocks dns.google
    #print(router.succeed("systemctl status -l sniqueue.service"))
    router.wait_for_unit("sniqueue.service")
    client.fail("curl --connect-timeout 1 --fail -k --resolve dns.google:443:${server_ip} https://dns.google/ >&2")
    router.succeed("nft list set inet filter blocklist4 >&2")

    # Test destination is added to blocklist
    client.sleep(2)
    client.fail("curl --connect-timeout 2 --fail -k https://${server_ip}/ >&2")

    # Test destination is remove from blocklist
    client.sleep(8)
    client.succeed("curl --connect-timeout 2 --fail -k https://${server_ip}/ >&2")
    router.succeed("conntrack -L >&2")
  '';
})
