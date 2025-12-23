import eel
import ipaddress
import eel.browsers

eel.init("web")

@eel.expose
def process_text(ip, mask, ip1, mask1, ip2, mask2,
                 routing_protocol="", router_id="", ip_multicast=False,
                 telephony_enabled=False, dn_list=None,
                 enable_ssh=False, hostname="", enable_secret="", console_password="", vty_password="",
                 dhcp_network="", dhcp_mask="", dhcp_gateway="", dhcp_dns=""):

    if dn_list is None:
        dn_list = []

    # === Перевірка IP та масок ===
    if not all([ip, mask, ip1, mask1, ip2, mask2]):
        return "❌ Error: Будь ласка, заповніть усі поля IP та маски."

    for value in [ip, mask, ip1, mask1, ip2, mask2]:
        if len(value) < 7:
            return f"❌ Error: '{value}' занадто коротке."
        if len(value) > 18:
            return f"❌ Error: '{value}' занадто довге."
        if " " in value:
            return f"❌ Error: '{value}' містить пробіли."
        if not all(c.isalnum() or c in ".:/" for c in value):
            return f"❌ Error: '{value}' містить недопустимі символи."

    try:
        ipaddress.ip_address(ip)
        ipaddress.ip_address(ip1)
        ipaddress.ip_address(ip2)
        ipaddress.ip_network(f"0.0.0.0/{mask}")
        ipaddress.ip_network(f"0.0.0.0/{mask1}")
        ipaddress.ip_network(f"0.0.0.0/{mask2}")
    except ValueError:
        return "❌ Error: Неправильний формат IP-адреси або маски."

    # === Генерація базової конфігурації ===
    cfg = []
    cfg.append("en")
    cfg.append("conf t")
    cfg.append(f"hostname {hostname if hostname else 'R1'}")

    # Інтерфейси
    cfg.append("interface gi0/0")
    cfg.append(f" ip address {ip} {mask}")
    cfg.append(" exit")

    cfg.append("interface gi0/1")
    cfg.append(f" ip address {ip1} {mask1}")
    cfg.append(" exit")

    cfg.append("interface gi0/2")
    cfg.append(f" ip address {ip2} {mask2}")
    cfg.append(" no shutdown")
    cfg.append(" exit")

    # === Multicast ===
    if ip_multicast:
        cfg.append("ip multicast-routing")
        for i in range(3):
            cfg.append(f"interface gi0/{i}")
            cfg.append(" ip pim sparse-dense-mode")

    # === Routing Protocol ===
    proto = routing_protocol.upper().strip()
    if proto == "OSPF":
        if not router_id:
            return "❌ Error: Для OSPF потрібно вказати Router ID."
        cfg.append("!")
        cfg.append("router ospf 1")
        cfg.append(f" router-id {router_id}")
        cfg.append(f" network {ip} {mask} area 0")
        cfg.append(f" network {ip1} {mask1} area 0")
        cfg.append(f" network {ip2} {mask2} area 0")
        cfg.append(" exit")
    elif proto == "RIP":
        cfg.append("!")
        cfg.append("router rip")
        cfg.append(" version 2")
        cfg.append(f" network {ip}")
        cfg.append(f" network {ip1}")
        cfg.append(f" network {ip2}")
        cfg.append(" no auto-summary")
        cfg.append(" exit")
    elif proto == "EIGRP":
        cfg.append("!")
        cfg.append("router eigrp 100")
        cfg.append(f" network {ip}")
        cfg.append(f" network {ip1}")
        cfg.append(f" network {ip2}")
        cfg.append(" no auto-summary")
        cfg.append(" exit")
    elif proto == "BGP":
        cfg.append("!")
        cfg.append("router bgp 65000")
        cfg.append(" bgp log-neighbor-changes")
        cfg.append(" neighbor 1.1.1.2 remote-as 65001")
        cfg.append(" exit")
    elif proto == "IS-IS":
        cfg.append("!")
        cfg.append("router isis")
        cfg.append(" net 49.0001.0000.0000.0001.00")
        cfg.append(" is-type level-2-only")
        cfg.append(" exit")
    else:
        cfg.append("! No routing protocol selected")

    # === Telephony Service ===
    if telephony_enabled:
        cfg.append("!")
        cfg.append("telephony-service")
        cfg.append(" max-ephones 3")
        cfg.append(" max-dn 3")
        cfg.append(" ip source-address 10.0.0.1 port 2000")
        cfg.append(" auto assign 1 to 3")
        cfg.append(" exit")
        for idx, dn in enumerate(dn_list, start=1):
            if dn.get("number"):
                cfg.append(f"ephone-dn {idx}")
                cfg.append(f" number {dn['number']}")
                cfg.append(" exit")
            if dn.get("user"):
                cfg.append(f"ephone {idx}")
                cfg.append(f" username {dn['user']}")
                cfg.append(" exit")

    # === Security Configuration ===
    if enable_secret or console_password or vty_password or enable_ssh:
        cfg.append("!")
        if enable_secret:
            cfg.append(f"enable secret {enable_secret}")
        if console_password:
            cfg.append("line console 0")
            cfg.append(f" password {console_password}")
            cfg.append(" login")
            cfg.append(" exit")
        if vty_password:
            cfg.append("line vty 0 4")
            cfg.append(f" password {vty_password}")
            cfg.append(" login")
            cfg.append(" exit")
        if enable_ssh:
            cfg.append("ip domain-name cisco.local")
            cfg.append("crypto key generate rsa modulus 1024")
            cfg.append("ip ssh version 2")

    # === DHCP Server Configuration ===
    if dhcp_network and dhcp_mask:
        cfg.append("!")
        cfg.append("ip dhcp excluded-address 10.0.0.1 10.0.0.10")
        cfg.append("ip dhcp pool LAN")
        cfg.append(f" network {dhcp_network} {dhcp_mask}")
        if dhcp_gateway:
            cfg.append(f" default-router {dhcp_gateway}")
        if dhcp_dns:
            cfg.append(f" dns-server {dhcp_dns}")
        cfg.append(" exit")

    return "\n".join(cfg)

eel.start("home.html", size=(800, 600), mode="edge")
