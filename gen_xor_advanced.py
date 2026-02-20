def xor_data(data, key):
    return [ord(data[i]) ^ ord(key[i % len(key)]) for i in range(len(data))]

key = "vM_dEtEcTiOn_KeY_2024"
strings = [
    "WDAGUtilityAccount",
    "SANDBOX",
    "DESKTOP-",
    "VMWARE",
    "VIRTUAL",
    "USER",
    "ADMIN",
    "System32",
    "\\\\.\\VBoxGuest",
    "\\\\.\\VBoxPipe",
    "vmtoolsd.exe",
    "vboxservice.exe",
    "joeboxserver.exe",
    "joeboxcontrol.exe",
    "procmon.exe",
    "wireshark.exe"
]

for s in strings:
    print(f"{s}: {xor_data(s, key)}")
