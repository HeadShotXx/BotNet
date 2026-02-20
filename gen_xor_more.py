def xor_data(data, key):
    return [ord(data[i]) ^ ord(key[i % len(key)]) for i in range(len(data))]

key = "vM_dEtEcTiOn_KeY_2024"
strings = [
    "C:\\Windows\\System32",
    "HARDWARE\\DESCRIPTION\\System\\BIOS",
    "BIOSVendor",
    "SystemManufacturer",
    "SYSTEM\\CurrentControlSet\\Control\\Thermal"
]

for s in strings:
    print(f"{s}: {xor_data(s, key)}")
