"""
Hardware MAC Address OUI (Organizationally Unique Identifier) Vendor Database.
Enables instant hardware vendor identification without external web requests.
"""

from typing import Optional

# Comprehensive database of common MAC OUI prefixes (uppercase, no colons)
OUI_DATABASE = {
    # Apple
    "000393": "Apple Inc.", "000502": "Apple Inc.", "000A27": "Apple Inc.", "000A95": "Apple Inc.",
    "000D93": "Apple Inc.", "0010FA": "Apple Inc.", "001124": "Apple Inc.", "001451": "Apple Inc.",
    "0016CB": "Apple Inc.", "0017F2": "Apple Inc.", "0019E3": "Apple Inc.", "001B63": "Apple Inc.",
    "001C42": "Parallels / Apple", "001D4F": "Apple Inc.", "001E52": "Apple Inc.", "001F5B": "Apple Inc.",
    "001FF3": "Apple Inc.", "0021E9": "Apple Inc.", "002241": "Apple Inc.", "002312": "Apple Inc.",
    "002332": "Apple Inc.", "00236C": "Apple Inc.", "002436": "Apple Inc.", "002500": "Apple Inc.",
    "00254B": "Apple Inc.", "002608": "Apple Inc.", "00264A": "Apple Inc.", "0026B0": "Apple Inc.",
    "0026BB": "Apple Inc.", "040C56": "Apple Inc.", "041552": "Apple Inc.", "041E64": "Apple Inc.",
    "042665": "Apple Inc.", "04489A": "Apple Inc.", "045453": "Apple Inc.", "04DB56": "Apple Inc.",
    "04E536": "Apple Inc.", "080007": "Apple Inc.", "087045": "Apple Inc.", "087402": "Apple Inc.",
    "08E689": "Apple Inc.", "0C3021": "Apple Inc.", "0C4DE9": "Apple Inc.", "0C74C2": "Apple Inc.",
    "101C0C": "Apple Inc.", "1040F3": "Apple Inc.", "1093E9": "Apple Inc.", "109ADD": "Apple Inc.",
    "14109F": "Apple Inc.", "14205E": "Apple Inc.", "147DDA": "Apple Inc.", "186590": "Apple Inc.",
    "18AF61": "Apple Inc.", "18EE69": "Apple Inc.", "1C1A6B": "Apple Inc.", "207D74": "Apple Inc.",
    "24A074": "Apple Inc.", "280B5C": "Apple Inc.", "286A81": "Apple Inc.", "28CFE9": "Apple Inc.",
    "2CBE08": "Apple Inc.", "3035AD": "Apple Inc.", "3408BC": "Apple Inc.", "34159E": "Apple Inc.",
    "38484C": "Apple Inc.", "38CA84": "Apple Inc.", "3C0754": "Apple Inc.", "3C15C2": "Apple Inc.",
    "406C8F": "Apple Inc.", "442A60": "Apple Inc.", "444C0C": "Apple Inc.", "48437C": "Apple Inc.",
    "4C3275": "Apple Inc.", "50BC96": "Apple Inc.", "542696": "Apple Inc.", "5855CA": "Apple Inc.",
    "5C969D": "Apple Inc.", "600308": "Apple Inc.", "60334B": "Apple Inc.", "6476BA": "Apple Inc.",
    "68A86D": "Apple Inc.", "6C4008": "Apple Inc.", "701124": "Apple Inc.", "70DEE2": "Apple Inc.",
    "748D08": "Apple Inc.", "7831C1": "Apple Inc.", "7C04D0": "Apple Inc.", "80006E": "Apple Inc.",
    "843835": "Apple Inc.", "88665A": "Apple Inc.", "8C8590": "Apple Inc.", "9027E4": "Apple Inc.",
    "949426": "Apple Inc.", "9801A7": "Apple Inc.", "9C207B": "Apple Inc.", "A03B0F": "Apple Inc.",
    "A483E7": "Apple Inc.", "A8667F": "Apple Inc.", "AC1F74": "Apple Inc.", "ACBC32": "Apple Inc.",
    "B065BD": "Apple Inc.", "B418D1": "Apple Inc.", "B817C2": "Apple Inc.", "BC52B7": "Apple Inc.",
    "C09A4D": "Apple Inc.", "C48466": "Apple Inc.", "C869CD": "Apple Inc.", "CC29F5": "Apple Inc.",
    "D0034B": "Apple Inc.", "D4619D": "Apple Inc.", "D8004D": "Apple Inc.", "DC2B61": "Apple Inc.",
    "E0ACCB": "Apple Inc.", "E48B7F": "Apple Inc.", "E8040B": "Apple Inc.", "EC3586": "Apple Inc.",
    "F01898": "Apple Inc.", "F40F24": "Apple Inc.", "F86214": "Apple Inc.", "FC1803": "Apple Inc.",

    # TP-Link
    "000A3A": "TP-Link", "001478": "TP-Link", "0019E0": "TP-Link", "002127": "TP-Link",
    "0023CD": "TP-Link", "002586": "TP-Link", "0471A7": "TP-Link", "147590": "TP-Link",
    "18A6F7": "TP-Link", "1C3BF3": "TP-Link", "208756": "TP-Link", "24A580": "TP-Link",
    "30B5C2": "TP-Link", "349672": "TP-Link", "3C46D8": "TP-Link", "40169F": "TP-Link",
    "50C7BF": "TP-Link", "54AF97": "TP-Link", "60A44C": "TP-Link", "647002": "TP-Link",
    "704F57": "TP-Link", "7405A5": "TP-Link", "7C8BCA": "TP-Link", "8416F9": "TP-Link",
    "90F652": "TP-Link", "984827": "TP-Link", "A0F3C1": "TP-Link", "AC84C6": "TP-Link",
    "B0487A": "TP-Link", "B09575": "TP-Link", "C025E9": "TP-Link", "C04A00": "TP-Link",
    "D41AD1": "TP-Link", "D46E0E": "TP-Link", "D84732": "TP-Link", "DC396F": "TP-Link",
    "E4C32A": "TP-Link", "E848B8": "TP-Link", "EC086B": "TP-Link", "F4EC38": "TP-Link",

    # Raspberry Pi
    "B827EB": "Raspberry Pi Foundation",
    "DC2632": "Raspberry Pi Trading",
    "E45F01": "Raspberry Pi Trading",
    "28CDC1": "Raspberry Pi Trading",
    "D83ADD": "Raspberry Pi Trading",

    # Espressif (ESP8266 / ESP32 IoT devices)
    "18FE34": "Espressif Inc.", "240AC4": "Espressif Inc.", "2462AB": "Espressif Inc.",
    "246F28": "Espressif Inc.", "24B2DE": "Espressif Inc.", "2C3AE8": "Espressif Inc.",
    "30AEA4": "Espressif Inc.", "3C6105": "Espressif Inc.", "3C71BF": "Espressif Inc.",
    "40F520": "Espressif Inc.", "441793": "Espressif Inc.", "483FDA": "Espressif Inc.",
    "485519": "Espressif Inc.", "4C11AE": "Espressif Inc.", "5443B2": "Espressif Inc.",
    "5C0272": "Espressif Inc.", "600194": "Espressif Inc.", "68C63A": "Espressif Inc.",
    "70039F": "Espressif Inc.", "7C87CE": "Espressif Inc.", "7CDF64": "Espressif Inc.",
    "840D8E": "Espressif Inc.", "84F3EB": "Espressif Inc.", "8C4B14": "Espressif Inc.",
    "8C64A2": "Espressif Inc.", "94B97E": "Espressif Inc.", "A020A6": "Espressif Inc.",
    "A4CF12": "Espressif Inc.", "AC67B2": "Espressif Inc.", "B4E62D": "Espressif Inc.",
    "BCDD28": "Espressif Inc.", "C44F33": "Espressif Inc.", "C82E18": "Espressif Inc.",
    "CC50E3": "Espressif Inc.", "D8A01D": "Espressif Inc.", "DC4F22": "Espressif Inc.",
    "E09806": "Espressif Inc.", "E831CD": "Espressif Inc.", "EC94CB": "Espressif Inc.",

    # Intel
    "0002B3": "Intel Corporation", "000347": "Intel Corporation", "000423": "Intel Corporation",
    "0007E9": "Intel Corporation", "000E0C": "Intel Corporation", "000E35": "Intel Corporation",
    "001302": "Intel Corporation", "0013E8": "Intel Corporation", "001500": "Intel Corporation",
    "001B21": "Intel Corporation", "001C23": "Intel Corporation", "001E64": "Intel Corporation",
    "001F3B": "Intel Corporation", "00215C": "Intel Corporation", "00216A": "Intel Corporation",
    "0024D7": "Intel Corporation", "00270E": "Intel Corporation", "081196": "Intel Corporation",
    "0C8BFD": "Intel Corporation", "144F8A": "Intel Corporation", "3413E8": "Intel Corporation",
    "484520": "Intel Corporation", "48F17F": "Intel Corporation", "5891CF": "Intel Corporation",
    "6805CA": "Intel Corporation", "7C5CF8": "Intel Corporation", "8086F2": "Intel Corporation",
    "887873": "Intel Corporation", "8C1645": "Intel Corporation", "A434D9": "Intel Corporation",
    "A44CC8": "Intel Corporation", "AC7289": "Intel Corporation", "B49691": "Intel Corporation",
    "C80AA9": "Intel Corporation", "DC5360": "Intel Corporation", "F01898": "Intel Corporation",

    # Cisco Systems
    "00000C": "Cisco Systems", "000142": "Cisco Systems", "000143": "Cisco Systems",
    "000163": "Cisco Systems", "000164": "Cisco Systems", "000196": "Cisco Systems",
    "000197": "Cisco Systems", "0001C7": "Cisco Systems", "0001C9": "Cisco Systems",
    "000216": "Cisco Systems", "000217": "Cisco Systems", "00024A": "Cisco Systems",
    "00024B": "Cisco Systems", "00027D": "Cisco Systems", "00027E": "Cisco Systems",
    "0002B9": "Cisco Systems", "0002BA": "Cisco Systems", "0002FC": "Cisco Systems",
    "0002FD": "Cisco Systems", "000331": "Cisco Systems", "000332": "Cisco Systems",
    "00044D": "Cisco Systems", "00049F": "Cisco Systems", "000531": "Cisco Systems",
    "00055E": "Cisco Systems", "000573": "Cisco Systems", "00059A": "Cisco Systems",
    "000628": "Cisco Systems", "000652": "Cisco Systems", "00070E": "Cisco Systems",

    # Netgear
    "00095B": "Netgear", "000FB5": "Netgear", "00146C": "Netgear", "00184D": "Netgear",
    "001B2F": "Netgear", "001E2A": "Netgear", "001F33": "Netgear", "00223F": "Netgear",
    "0024B2": "Netgear", "0026F2": "Netgear", "04A151": "Netgear", "08BD43": "Netgear",
    "100C6B": "Netgear", "10DA43": "Netgear", "1459C0": "Netgear", "200C4A": "Netgear",
    "20E52A": "Netgear", "28C68E": "Netgear", "2C3033": "Netgear", "30469A": "Netgear",
    "4494FC": "Netgear", "6CCE85": "Netgear", "841B5E": "Netgear", "8C3BAD": "Netgear",
    "9C3DCF": "Netgear", "A00460": "Netgear", "A42B8C": "Netgear", "B03956": "Netgear",
    "B07F35": "Netgear", "C0FFD4": "Netgear", "C40415": "Netgear", "E0469A": "Netgear",

    # Asus (ASUSTeK)
    "000C6E": "ASUSTeK Computer", "000E08": "ASUSTeK Computer", "0011D8": "ASUSTeK Computer",
    "0013D4": "ASUSTeK Computer", "0015F2": "ASUSTeK Computer", "001731": "ASUSTeK Computer",
    "0018F3": "ASUSTeK Computer", "001A92": "ASUSTeK Computer", "001BFC": "ASUSTeK Computer",
    "001D60": "ASUSTeK Computer", "001E8C": "ASUSTeK Computer", "002215": "ASUSTeK Computer",
    "002354": "ASUSTeK Computer", "00248C": "ASUSTeK Computer", "002618": "ASUSTeK Computer",
    "049226": "ASUSTeK Computer", "08606E": "ASUSTeK Computer", "086266": "ASUSTeK Computer",
    "107B44": "ASUSTeK Computer", "14DD89": "ASUSTeK Computer", "1C872C": "ASUSTeK Computer",
    "2C4D54": "ASUSTeK Computer", "305A3A": "ASUSTeK Computer", "38D547": "ASUSTeK Computer",
    "40167E": "ASUSTeK Computer", "50465D": "ASUSTeK Computer", "54A050": "ASUSTeK Computer",
    "60A44C": "ASUSTeK Computer", "704D7B": "ASUSTeK Computer", "AC9E17": "ASUSTeK Computer",

    # Ubiquiti Networks
    "00156D": "Ubiquiti Inc.", "002722": "Ubiquiti Inc.", "0418D6": "Ubiquiti Inc.",
    "18E829": "Ubiquiti Inc.", "24A43C": "Ubiquiti Inc.", "44D9E7": "Ubiquiti Inc.",
    "68D79A": "Ubiquiti Inc.", "7483C2": "Ubiquiti Inc.", "788A20": "Ubiquiti Inc.",
    "802AA8": "Ubiquiti Inc.", "B4FBE4": "Ubiquiti Inc.", "DC9FDB": "Ubiquiti Inc.",
    "E063DA": "Ubiquiti Inc.", "F09FC2": "Ubiquiti Inc.", "F492BF": "Ubiquiti Inc.",

    # Google
    "001A11": "Google Inc.", "3C5AB4": "Google Inc.", "546009": "Google Inc.",
    "703EAC": "Google Inc.", "A47733": "Google Inc.", "D4F547": "Google Inc.",
    "F88FCA": "Google Inc.", "F8A963": "Google Inc.",

    # Amazon
    "00FC8B": "Amazon Technologies", "18742E": "Amazon Technologies", "34D270": "Amazon Technologies",
    "38F73D": "Amazon Technologies", "44650D": "Amazon Technologies", "50F5DA": "Amazon Technologies",
    "6854FD": "Amazon Technologies", "747548": "Amazon Technologies", "AC63BE": "Amazon Technologies",
    "F0272D": "Amazon Technologies", "FC65DE": "Amazon Technologies",

    # Samsung
    "0000F0": "Samsung Electronics", "000278": "Samsung Electronics", "0007AB": "Samsung Electronics",
    "000D4B": "Samsung Electronics", "001247": "Samsung Electronics", "001599": "Samsung Electronics",
    "001632": "Samsung Electronics", "00166C": "Samsung Electronics", "0017D5": "Samsung Electronics",
    "001A8A": "Samsung Electronics", "001C43": "Samsung Electronics", "001D25": "Samsung Electronics",
    "002119": "Samsung Electronics", "002339": "Samsung Electronics", "002454": "Samsung Electronics",
    "00265D": "Samsung Electronics", "08373D": "Samsung Electronics", "08D42B": "Samsung Electronics",
    "107719": "Samsung Electronics", "1432D1": "Samsung Electronics", "1867B0": "Samsung Electronics",
    "1C66AA": "Samsung Electronics", "244B03": "Samsung Electronics", "2C4401": "Samsung Electronics",
    "30CDA7": "Samsung Electronics", "34C059": "Samsung Electronics", "4040A7": "Samsung Electronics",
    "508569": "Samsung Electronics", "549B12": "Samsung Electronics", "60AF6D": "Samsung Electronics",
    "78471D": "Samsung Electronics", "8425DB": "Samsung Electronics", "946372": "Samsung Electronics",
    "9C0298": "Samsung Electronics", "A00798": "Samsung Electronics", "B407F9": "Samsung Electronics",
    "C4576E": "Samsung Electronics", "CC07AB": "Samsung Electronics", "E47CF9": "Samsung Electronics",

    # Microsoft
    "0003FF": "Microsoft Corporation", "000D3A": "Microsoft Corporation", "00125A": "Microsoft Corporation",
    "00155D": "Microsoft Hyper-V",    "0017FA": "Microsoft Corporation", "001D60": "Microsoft Corporation",
    "002248": "Microsoft Corporation", "0025AE": "Microsoft Corporation", "0050F2": "Microsoft Corporation",
    "281878": "Microsoft Corporation", "7C1E52": "Microsoft Corporation", "DCB4C4": "Microsoft Corporation",

    # Realtek
    "00E04C": "Realtek Semiconductor", "525400": "QEMU / KVM Virtual NIC",

    # VMware
    "000569": "VMware, Inc.", "000C29": "VMware, Inc.", "001C14": "VMware, Inc.", "005056": "VMware, Inc.",

    # Dell
    "00065B": "Dell Inc.", "000874": "Dell Inc.", "000BDB": "Dell Inc.", "000D56": "Dell Inc.",
    "001143": "Dell Inc.", "001372": "Dell Inc.", "001422": "Dell Inc.", "0015C5": "Dell Inc.",
    "0016F0": "Dell Inc.", "00188B": "Dell Inc.", "0019B9": "Dell Inc.", "001A6B": "Dell Inc.",
    "001C23": "Dell Inc.", "001D09": "Dell Inc.", "001E4F": "Dell Inc.", "00219B": "Dell Inc.",
    "002219": "Dell Inc.", "0023AE": "Dell Inc.", "0024E8": "Dell Inc.", "002564": "Dell Inc.",
    "180373": "Dell Inc.", "24B6FD": "Dell Inc.", "3417EB": "Dell Inc.", "44A842": "Dell Inc.",
    "5CF9DD": "Dell Inc.", "70B5E8": "Dell Inc.", "847BEB": "Dell Inc.", "90B11C": "Dell Inc.",
    "B82A72": "Dell Inc.", "BC305B": "Dell Inc.", "D481D7": "Dell Inc.", "F01FAF": "Dell Inc.",

    # HP / Hewlett-Packard
    "0001E6": "Hewlett-Packard", "0001E7": "Hewlett-Packard", "0002A5": "Hewlett-Packard",
    "000802": "Hewlett-Packard", "000BCD": "Hewlett-Packard", "000E7F": "Hewlett-Packard",
    "000F20": "Hewlett-Packard", "00110A": "Hewlett-Packard", "001279": "Hewlett-Packard",
    "001321": "Hewlett-Packard", "001438": "Hewlett-Packard", "001560": "Hewlett-Packard",
    "001635": "Hewlett-Packard", "001708": "Hewlett-Packard", "0018FE": "Hewlett-Packard",
    "0019BB": "Hewlett-Packard", "001A4B": "Hewlett-Packard", "001B78": "Hewlett-Packard",
    "001C2E": "Hewlett-Packard", "001D42": "Hewlett-Packard", "001E0B": "Hewlett-Packard",
    "001F29": "Hewlett-Packard", "00215A": "Hewlett-Packard", "002264": "Hewlett-Packard",
    "00237D": "Hewlett-Packard", "002481": "Hewlett-Packard", "0025B3": "Hewlett-Packard",
    "002655": "Hewlett-Packard", "101F74": "Hewlett-Packard", "28924A": "Hewlett-Packard",
    "3CD92B": "Hewlett-Packard", "40A8F0": "Hewlett-Packard", "705A0F": "Hewlett-Packard",

    # Synology & QNAP
    "001132": "Synology Inc.", "00089B": "QNAP Systems", "245EBE": "QNAP Systems",

    # Xiaomi
    "04CF8C": "Xiaomi Communications", "0C1DAF": "Xiaomi Communications", "14F65A": "Xiaomi Communications",
    "18F0E4": "Xiaomi Communications", "286C07": "Xiaomi Communications", "3480B3": "Xiaomi Communications",
    "50642B": "Xiaomi Communications", "640980": "Xiaomi Communications", "7451BA": "Xiaomi Communications",
    "7802F8": "Xiaomi Communications", "8CBEBE": "Xiaomi Communications", "ACF7F3": "Xiaomi Communications",

    # Tuya (Smart Home / Smart Plugs)
    "102C6B": "Tuya Smart Inc.", "10D561": "Tuya Smart Inc.", "508A06": "Tuya Smart Inc.",
    "68572D": "Tuya Smart Inc.", "708976": "Tuya Smart Inc.", "7CE9D3": "Tuya Smart Inc.",
    "A09208": "Tuya Smart Inc.", "BC33AC": "Tuya Smart Inc.", "D4D2D6": "Tuya Smart Inc.",

    # MikroTik
    "000C42": "MikroTik", "488F5A": "MikroTik", "64D154": "MikroTik", "B869F4": "MikroTik",
    "CC2DE0": "MikroTik", "D4CA6D": "MikroTik", "E48D8C": "MikroTik",

    # Huawei
    "001882": "Huawei Technologies", "001E10": "Huawei Technologies", "00259E": "Huawei Technologies",
    "00464B": "Huawei Technologies", "04257B": "Huawei Technologies", "0819A6": "Huawei Technologies",
    "0C96BF": "Huawei Technologies", "101B54": "Huawei Technologies", "104780": "Huawei Technologies",
    "14B968": "Huawei Technologies", "2008ED": "Huawei Technologies", "20F41B": "Huawei Technologies",
    "308730": "Huawei Technologies", "4846FB": "Huawei Technologies", "7054F5": "Huawei Technologies",

    # Sony / PlayStation
    "00041F": "Sony Interactive Entertainment", "001315": "Sony Interactive Entertainment",
    "0015C1": "Sony Interactive Entertainment", "0019C5": "Sony Interactive Entertainment",
    "001D0D": "Sony Interactive Entertainment", "00248D": "Sony Interactive Entertainment",
    "709E29": "Sony Interactive Entertainment", "A8E2C1": "Sony Interactive Entertainment",
    "F8461C": "Sony Interactive Entertainment", "FC0F4B": "Sony Interactive Entertainment",

    # Nintendo
    "0009BF": "Nintendo Co., Ltd.", "001656": "Nintendo Co., Ltd.", "0017AB": "Nintendo Co., Ltd.",
    "00191D": "Nintendo Co., Ltd.", "001B7A": "Nintendo Co., Ltd.", "001BEA": "Nintendo Co., Ltd.",
    "001F32": "Nintendo Co., Ltd.", "002147": "Nintendo Co., Ltd.", "00224C": "Nintendo Co., Ltd.",
    "0022D7": "Nintendo Co., Ltd.", "002444": "Nintendo Co., Ltd.", "0025A0": "Nintendo Co., Ltd.",
    "002659": "Nintendo Co., Ltd.", "70480F": "Nintendo Co., Ltd.", "98B6E9": "Nintendo Co., Ltd.",

    # Roku
    "080581": "Roku, Inc.", "20F543": "Roku, Inc.", "84EA99": "Roku, Inc.",
    "AC3A7A": "Roku, Inc.", "B0A737": "Roku, Inc.", "D83134": "Roku, Inc.",

    # Philips Lighting (Hue)
    "001788": "Signify Netherlands B.V. (Philips Hue)",
    "ECB5FA": "Signify Netherlands B.V. (Philips Hue)",
}


def lookup_vendor(mac_address: Optional[str]) -> str:
    """
    Look up the hardware manufacturer from a MAC address string.
    Accepts formats: '00:11:22:33:44:55', '00-11-22-33-44-55', '001122334455'.
    """
    if not mac_address:
        return "Unknown Vendor"

    clean_mac = mac_address.replace(":", "").replace("-", "").replace(".", "").upper()
    if len(clean_mac) < 6:
        return "Unknown Vendor"

    prefix = clean_mac[:6]
    return OUI_DATABASE.get(prefix, "Unknown Vendor")
