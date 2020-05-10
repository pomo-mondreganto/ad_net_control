# ad_net_control
A tool for network management during an AD CTF

-   `net_control.py` file is for backward compatibility with single-host VPN setup

-   `team_vpn_server_control.py` is the setup for team routers

-   `vulnbox_vpn_server_control.py` is the setup for vulnbox routers

-   `wg_control.py` is the setup for Wireguard routers.


## OpenVPN control
All scripts assume that team N's interface is named `teamN`, vuln N's is named `vulnN`. Refer to the
[OVPNGen](https://github.com/pomo-mondreganto/OVPNGen) project for the compatible OpenVPN configuration generation.


## Wireguard control

For Wireguard configuration generation see the [wggen](https://github.com/pomo-mondreganto/wggen) project.
