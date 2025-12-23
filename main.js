
let selectedRouter = null;

// Показати поле Router ID тільки для OSPF
document.querySelectorAll('input[name="routing-protocol"]').forEach(radio => {
  radio.addEventListener('change', () => {
    const ospfOptions = document.getElementById("ospf-options");
    ospfOptions.classList.toggle("hidden", radio.value !== "OSPF");
  });
});

// Відправка даних у Python
async function sendToPython() {
  // === Step 1-3: IP та Routing ===
  const g00_ip = document.getElementById("g00-ip-Input").value.trim();
  const g00_mask = document.getElementById("g00-mask-Input").value.trim();
  const g01_ip = document.getElementById("g01-ip-Input").value.trim();
  const g01_mask = document.getElementById("g01-mask-Input").value.trim();
  const g02_ip = document.getElementById("g02-ip-Input").value.trim();
  const g02_mask = document.getElementById("g02-mask-Input").value.trim();

  const routingProtocol = document.querySelector('input[name="routing-protocol"]:checked')?.value || "";
  const routerId = document.getElementById("router-id").value.trim();
  const ipMulticast = document.getElementById("multicast-checkbox").checked;

  // === Step 4: Telephony Service ===
  const telephonyEnabled = document.getElementById("telephony-checkbox").checked;
  const dnList = [
    { number: document.getElementById("dn1-number").value.trim(), user: document.getElementById("dn1-user").value.trim() },
    { number: document.getElementById("dn2-number").value.trim(), user: document.getElementById("dn2-user").value.trim() },
    { number: document.getElementById("dn3-number").value.trim(), user: document.getElementById("dn3-user").value.trim() }
  ];

  // === Step 5: Security Configuration ===
  const enableSSH = document.getElementById("ssh").checked;
  const hostname = document.querySelector('input[placeholder="Router"]').value.trim();
  const enableSecret = document.querySelector('input[placeholder="type"]').value.trim();
  const consolePassword = document.querySelectorAll('input[placeholder="******"]')[0].value.trim();
  const vtyPassword = document.querySelectorAll('input[placeholder="******"]')[1].value.trim();

  // === Step 6: DHCP Server ===
  const dhcpNetwork = document.getElementById("dhcp-network").value.trim();
  const dhcpMask = document.getElementById("dhcp-mask").value.trim();
  const dhcpGateway = document.getElementById("dhcp-gateway").value.trim();
  const dhcpDns = document.getElementById("dhcp-dns").value.trim();

  try {
    const res = await eel.process_text(
      g00_ip, g00_mask, g01_ip, g01_mask, g02_ip, g02_mask,
      routingProtocol, routerId, ipMulticast,
      telephonyEnabled, dnList,
      enableSSH, hostname, enableSecret, consolePassword, vtyPassword,
      dhcpNetwork, dhcpMask, dhcpGateway, dhcpDns
    )();

    const response = document.getElementById("response");
    response.innerText = res;
    response.style.color = res.startsWith("❌") ? "#c0392b" : "#1e272e";
  } catch (err) {
    console.error(err);
  }
}
