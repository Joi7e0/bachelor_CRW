import unittest
import sys
import os

# Додаємо шлях до основного коду
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Імпортуємо функцію для тестування
# Оскільки ваш код використовує eel, нам потрібно створити мок
# Або винести логіку в окремий модуль

# Для тестування створимо мок-версію без eel
def process_text_mock(ip, mask, ip1, mask1, ip2, mask2,
                     routing_protocol="", router_id="", ip_multicast=False,
                     telephony_enabled=False, dn_list=None,
                     enable_ssh=False, hostname="", enable_secret="", 
                     console_password="", vty_password="",
                     dhcp_network="", dhcp_mask="", dhcp_gateway="", 
                     dhcp_dns=""):
    
    """Мок-функція для тестування логіки без eel"""
    
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

    return "\n".join(cfg)


# ========== ОКРЕМІ ФУНКЦІЇ ДЛЯ ТЕСТУВАННЯ ==========

def validate_ip_address(ip):
    """Перевірка коректності IP-адреси"""
    import re
    pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    match = re.match(pattern, ip)
    if not match:
        return False
    
    for group in match.groups():
        if int(group) > 255:
            return False
    return True

def validate_subnet_mask(mask):
    """Перевірка коректності маски підмережі"""
    valid_masks = ["255.255.255.0", "255.255.0.0", "255.0.0.0", 
                   "255.255.255.128", "255.255.255.192", "255.255.255.224",
                   "255.255.255.240", "255.255.255.248", "255.255.255.252"]
    return mask in valid_masks or mask.isdigit() and 0 <= int(mask) <= 32

def generate_interface_config(interface_name, ip, mask):
    """Генерація конфігурації для одного інтерфейсу"""
    if not validate_ip_address(ip):
        raise ValueError(f"Некоректна IP-адреса: {ip}")
    
    if not validate_subnet_mask(mask):
        raise ValueError(f"Некоректна маска: {mask}")
    
    return [
        f"interface {interface_name}",
        f" ip address {ip} {mask}",
        " no shutdown",
        " exit"
    ]

def generate_ospf_config(router_id, interfaces):
    """Генерація OSPF конфігурації"""
    if not router_id or not validate_ip_address(router_id):
        raise ValueError("Некоректний Router ID")
    
    config = ["!", "router ospf 1", f" router-id {router_id}"]
    
    for interface in interfaces:
        ip = interface['ip']
        mask = interface['mask']
        # Конвертуємо маску у wildcard для OSPF
        if "." in mask:
            # Якщо маска в dotted decimal
            wildcard = ".".join(str(255 - int(x)) for x in mask.split("."))
        else:
            # Якщо маска в prefix notation
            prefix = int(mask)
            wildcard = ".".join(str(255 - int(x)) for x in 
                              ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask.split("."))
        
        config.append(f" network {ip} {wildcard} area 0")
    
    config.append(" exit")
    return config


# ========== UNIT-ТЕСТИ ==========

class TestConfigGenerator(unittest.TestCase):
    """Тести для генератора конфігурацій маршрутизатора"""
    
    def setUp(self):
        """Підготовка тестових даних"""
        self.valid_ip = "192.168.1.1"
        self.valid_mask = "255.255.255.0"
        self.valid_router_id = "1.1.1.1"
    
    # ===== Тести валідації IP-адрес =====
    
    def test_validate_ip_correct(self):
        """Тестування коректних IP-адрес"""
        self.assertTrue(validate_ip_address("192.168.1.1"))
        self.assertTrue(validate_ip_address("10.0.0.1"))
        self.assertTrue(validate_ip_address("172.16.0.1"))
        self.assertTrue(validate_ip_address("8.8.8.8"))
    
    def test_validate_ip_incorrect(self):
        """Тестування некоректних IP-адрес"""
        self.assertFalse(validate_ip_address("192.168.1.300"))
        self.assertFalse(validate_ip_address("192.168.1"))
        self.assertFalse(validate_ip_address("192.168.1.1.1"))
        self.assertFalse(validate_ip_address("192.168.1.-1"))
        self.assertFalse(validate_ip_address("abc.def.ghi.jkl"))
        self.assertFalse(validate_ip_address(""))
        self.assertFalse(validate_ip_address("192.168.1.1 "))
    
    def test_validate_ip_edge_cases(self):
        """Тестування граничних значень"""
        self.assertTrue(validate_ip_address("0.0.0.0"))  # Default route
        self.assertTrue(validate_ip_address("255.255.255.255"))  # Broadcast
        self.assertFalse(validate_ip_address("256.0.0.1"))  > 255
        self.assertFalse(validate_ip_address("192.168.1.256"))
    
    # ===== Тести валідації масок =====
    
    def test_validate_mask_correct(self):
        """Тестування коректних масок"""
        self.assertTrue(validate_subnet_mask("255.255.255.0"))
        self.assertTrue(validate_subnet_mask("255.255.0.0"))
        self.assertTrue(validate_subnet_mask("255.0.0.0"))
        self.assertTrue(validate_subnet_mask("24"))  # Prefix notation
        self.assertTrue(validate_subnet_mask("16"))
        self.assertTrue(validate_subnet_mask("8"))
    
    def test_validate_mask_incorrect(self):
        """Тестування некоректних масок"""
        self.assertFalse(validate_subnet_mask("255.255.255.300"))
        self.assertFalse(validate_subnet_mask("255.255.255"))
        self.assertFalse(validate_subnet_mask("33"))  > 32
        self.assertFalse(validate_subnet_mask("-1"))
        self.assertFalse(validate_subnet_mask("abc"))
        self.assertFalse(validate_subnet_mask("255.255.255.0.0"))
    
    # ===== Тести генерації конфігурації інтерфейсів =====
    
    def test_generate_interface_config_valid(self):
        """Тестування генерації конфігурації для валідних даних"""
        config = generate_interface_config("GigabitEthernet0/0", "192.168.1.1", "255.255.255.0")
        
        self.assertEqual(len(config), 4)
        self.assertIn("interface GigabitEthernet0/0", config[0])
        self.assertIn("ip address 192.168.1.1 255.255.255.0", config[1])
        self.assertIn("no shutdown", config[2])
        self.assertIn("exit", config[3])
    
    def test_generate_interface_config_invalid_ip(self):
        """Тестування з некоректною IP-адресою"""
        with self.assertRaises(ValueError) as context:
            generate_interface_config("Gi0/0", "192.168.1.300", "255.255.255.0")
        self.assertIn("Некоректна IP-адреса", str(context.exception))
    
    def test_generate_interface_config_invalid_mask(self):
        """Тестування з некоректною маскою"""
        with self.assertRaises(ValueError) as context:
            generate_interface_config("Gi0/0", "192.168.1.1", "255.255.255.300")
        self.assertIn("Некоректна маска", str(context.exception))
    
    # ===== Тести генерації OSPF конфігурації =====
    
    def test_generate_ospf_config_valid(self):
        """Тестування генерації OSPF конфігурації"""
        interfaces = [
            {"ip": "192.168.1.1", "mask": "255.255.255.0"},
            {"ip": "10.0.0.1", "mask": "255.0.0.0"}
        ]
        
        config = generate_ospf_config("1.1.1.1", interfaces)
        
        self.assertIn("router ospf 1", config)
        self.assertIn("router-id 1.1.1.1", config)
        # Перевіряємо наявність network команд
        network_commands = [c for c in config if c.startswith(" network")]
        self.assertEqual(len(network_commands), 2)
    
    def test_generate_ospf_config_invalid_router_id(self):
        """Тестування з некоректним Router ID"""
        with self.assertRaises(ValueError) as context:
            generate_ospf_config("", [{"ip": "192.168.1.1", "mask": "255.255.255.0"}])
        self.assertIn("Некоректний Router ID", str(context.exception))
        
        with self.assertRaises(ValueError) as context:
            generate_ospf_config("300.300.300.300", [])
        self.assertIn("Некоректний Router ID", str(context.exception))
    
    def test_generate_ospf_config_empty_interfaces(self):
        """Тестування з порожнім списком інтерфейсів"""
        config = generate_ospf_config("2.2.2.2", [])
        self.assertIn("router-id 2.2.2.2", config)
        # Не повинно бути network команд
        network_commands = [c for c in config if c.startswith(" network")]
        self.assertEqual(len(network_commands), 0)
    
    # ===== Тести основної функції process_text_mock =====
    
    def test_process_text_valid_data(self):
        """Тестування основної функції з валідними даними"""
        result = process_text_mock(
            ip="192.168.1.1", mask="255.255.255.0",
            ip1="10.0.0.1", mask1="255.0.0.0",
            ip2="172.16.0.1", mask2="255.255.0.0",
            routing_protocol="OSPF",
            router_id="1.1.1.1"
        )
        
        # Перевіряємо, що результат не є помилкою
        self.assertFalse(result.startswith("❌ Error"))
        # Перевіряємо наявність ключових команд
        self.assertIn("interface gi0/0", result)
        self.assertIn("router ospf 1", result)
        self.assertIn("router-id 1.1.1.1", result)
    
    def test_process_text_missing_required_fields(self):
        """Тестування з відсутніми обов'язковими полями"""
        result = process_text_mock(
            ip="", mask="255.255.255.0",
            ip1="10.0.0.1", mask1="255.0.0.0",
            ip2="172.16.0.1", mask2="255.255.0.0"
        )
        
        self.assertIn("❌ Error: Будь ласка, заповніть усі поля", result)
    
    def test_process_text_ospf_without_router_id(self):
        """Тестування OSPF без Router ID"""
        result = process_text_mock(
            ip="192.168.1.1", mask="255.255.255.0",
            ip1="10.0.0.1", mask1="255.0.0.0",
            ip2="172.16.0.1", mask2="255.255.0.0",
            routing_protocol="OSPF",
            router_id=""  # Відсутній Router ID
        )
        
        self.assertIn("❌ Error: Для OSPF потрібно вказати Router ID", result)
    
    def test_process_text_short_input(self):
        """Тестування занадто коротких вхідних даних"""
        result = process_text_mock(
            ip="1.1.1", mask="255",  # Занадто короткі
            ip1="10.0.0.1", mask1="255.0.0.0",
            ip2="172.16.0.1", mask2="255.255.0.0"
        )
        
        self.assertIn("❌ Error: '1.1.1' занадто коротке", result)
    
    def test_process_text_long_input(self):
        """Тестування занадто довгих вхідних даних"""
        result = process_text_mock(
            ip="192.168.1.1", mask="255.255.255.0",
            ip1="10.0.0.1", mask1="255.0.0.0",
            ip2="172.16.0.1", mask2="255.255.255.255.255"  # Занадто довге
        )
        
        self.assertIn("❌ Error: '255.255.255.255.255' занадто довге", result)
    
    def test_process_text_with_spaces(self):
        """Тестування вводу з пробілами"""
        result = process_text_mock(
            ip="192.168.1.1", mask="255.255.255.0",
            ip1="10.0.0.1", mask1="255.0.0.0",
            ip2="172.16.0.1", mask2="255.255. 0.0"  # Пробіл у масці
        )
        
        self.assertIn("❌ Error: '255.255. 0.0' містить пробіли", result)
    
    def test_process_text_invalid_characters(self):
        """Тестування недопустимих символів"""
        result = process_text_mock(
            ip="192.168.1.1", mask="255.255.255.0",
            ip1="10.0.0.1", mask1="255.0.0.0",
            ip2="172.16.0.1", mask2="255.255.255.0$"  # Недопустимий символ
        )
        
        self.assertIn("❌ Error: '255.255.255.0$' містить недопустимі символи", result)
    
    def test_process_text_different_protocols(self):
        """Тестування різних протоколів маршрутизації"""
        protocols = ["RIP", "EIGRP", "OSPF", "BGP", "IS-IS"]
        
        for protocol in protocols:
            with self.subTest(protocol=protocol):
                result = process_text_mock(
                    ip="192.168.1.1", mask="255.255.255.0",
                    ip1="10.0.0.1", mask1="255.0.0.0",
                    ip2="172.16.0.1", mask2="255.255.0.0",
                    routing_protocol=protocol,
                    router_id="1.1.1.1" if protocol == "OSPF" else ""
                )
                
                if protocol == "OSPF":
                    # Для OSPF потрібен router_id
                    if not protocol == "OSPF":
                        self.assertIn("router " + protocol.lower(), result.lower())
                else:
                    # Для інших протоколів
                    self.assertFalse(result.startswith("❌ Error"))

# ========== ДОПОМІЖНІ ФУНКЦІЇ ==========

def run_tests():
    """Запуск всіх тестів"""
    # Створюємо тест-сьют
    suite = unittest.TestLoader().loadTestsFromTestCase(TestConfigGenerator)
    
    # Запускаємо тести з детальним виводом
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Виводимо статистику
    print("\n" + "="*60)
    print("РЕЗУЛЬТАТИ ТЕСТУВАННЯ")
    print("="*60)
    print(f"Всього тестів: {result.testsRun}")
    print(f"Успішних: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Невдалих: {len(result.failures)}")
    print(f"Помилок: {len(result.errors)}")
    
    if result.failures:
        print("\nНЕВДАЛІ ТЕСТИ:")
        for test, traceback in result.failures:
            print(f"  {test}: {str(traceback).split(':')[0]}")
    
    if result.errors:
        print("\nПОМИЛКИ:")
        for test, traceback in result.errors:
            print(f"  {test}: {str(traceback).split(':')[0]}")
    
    return result.wasSuccessful()

if __name__ == "__main__":
    # Додаємо ipaddress для тестування
    import ipaddress
    
    # Запускаємо тести
    success = run_tests()
    
    # Повертаємо код виходу для CI/CD
    sys.exit(0 if success else 1)