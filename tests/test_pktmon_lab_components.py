"""Lab components are taken from `pktmon list` by name; other adapters are never added."""
from integrityguard import pktmon_capture as pc

LIST = """Сетевые адаптеры:   ИД МАС-адрес        Имя
   4 F4-7B-09-9B-60-C1 Bluetooth Device (Personal Area Network)
   7 D8-BB-C1-8A-4E-9C Intel(R) Ethernet Controller (3) I225-V
 220 00-15-5D-00-7E-06 IG-Victim
 208 00-15-5D-00-7E-05 IG-Attacker
 106 00-15-5D-00-7E-04 vEthernet (IG-Lab)
 108 00-15-5D-E7-35-AE vEthernet (Default Switch)
"""


def test_lab_components_are_found_by_name():
    args = pc.lab_component_args(LIST)
    assert args == ["--comp", "220", "--comp", "208", "--comp", "106"]


def test_default_switch_and_host_adapters_are_not_added():
    args = pc.lab_component_args(LIST)
    assert "108" not in args and "7" not in args and "4" not in args


def test_no_lab_components_gives_empty_list():
    assert pc.lab_component_args("   7 D8-BB Intel(R) Ethernet\n") == []
