from Crypto.Util.number import bytes_to_long
import binascii

# Hex values extracted from the user's key file (trimmed for simplicity)
modulus_hex = "00:da:ba:fa:99:b7:62:b6:13:45:de:d0:be:a8:a6:bf:07:dc:35:66:c8:e0:77:e6:31:bf:bf:4a:d9:5a:f1:49:b8:70:b8:d6:3b:ab:8a:8d:18:64:df:f6:71:8a:6b:bf:16:75:73:ad:72:e5:2d:0e:64:03:2a:e7:60:7a:16:a3:b6:ae:ee:6a:b2:76:10:ea:01:2e:f2:b5:a0:84:11:3b:3a:9d:a2:7e:f1:8e:3e:ab:60:55:0d:62:92:5f:35:59:ef:12:82:45:81:08:36:5e:99:88:81:c4:87:d2:48:b9:92:dc:d8:d9:62:10:f3:1f:b3:23:e4:6f:df:21:e6:60:73:eb:0e:51:93:dd:d5:95:7f:11:7b:f8:9c:60:18:bf:6e:5f:e8:e6:be:b0:b2:a4:4b:98:12:b5:f7:de:19:8f:4d:f1:b2:4a:73:65:47:c4:07:bf:7f:f9:8e:60:57:b9:ff:6f:bd:f5:15:51:2f:4b:37:f5:98:25:3b:df:18:3f:69:9e:3c:07:45:f6:51:12:9c:31:4d:67:26:83:33:63:1b:02:80:8d:a5:46:d2:8e:43:c1:a7:95:f3:37:7a:7a:28:40:f7:78:a6:e0:b9:29:ac:a0:7b:85:37:36:91:22:37:25:97:55:c1:0f:5a:99:54:da:d0:4e:93:63:76:5e:20:2b:52:ee:10:ce:c9:7d:f9:ba:6f:8f:a5:4e:00:2c:3b:b8:d7:7b:8c:d0:6a:f3:f0:53:bc:24:22:b9:fa:64:43:ce:cd:9a:0c:b3:07:ef:7a:0b:da:00:1f:1d:7a:b4:f6:71:49:b7:ad:73:cc:33:3d:87:b7:0a:11:de:97:aa:22:26:8d:7b:6b:79:34:e9:89:f8:29:93:c8:8c:81:86:ef:e8:15:95:f4:a6:6b:9d:0f:56:84:83:fd:ca:8a:d8:78:2a:f9:2c:e0:7b:84:18:a2:72:9e:64:a4:ad:a2:14:5e:7f:1c:b8:6e:fb:52:7d:e3:65:76:5f:d4:f8:e0:df:20:60:e6:26:cc:18:35:40:00:e5:5b:c4:fa:d0:65:3d:43:d4:33:2f:10:14:90:92:e2:fb:bf:77:44:05:22:b9:7a:4f:86:e7:e1:f3:e8:97:a8:a9:c1:91:05:86:24:b9:ec:c6:bf:18:c8:d4:a8:ab:a2:e0:9c:ca:c3:bd:fe:fa:fd:85:e6:9a:b8:7b:c0:16:eb:bc:bc:00:57:29:ee:b8:6b:73:ab:a9:69:af:ec:a3:e6:19:44:1a:6c:62:03:23:85:49:6b:62:e9:5a:7c:38:2d:ad:60:1d:88:8a:39:f1:60:0a:a5:f8:6d:a2:b0:d0:44:b9:af:7c:59:c0:95:7f:7b".replace(":", "")
public_exponent = 65537  # Standard e
private_exponent_hex = "00:a9:a1:02:41:fd:d7:7e:ce:d9:8b:e0:25:4c:53:ec:a8:62:dd:c3:35:9b:e7:40:4d:6a:a0:26:a3:04:05:46:1f:d4:c3:73:d9:58:c2:9d:83:c2:8f:71:e7:41:eb:27:89:7a:52:d8:bb:d7:01:a7:3c:66:bc:7a:2d:f6:e0:e1:dc:06:33:fd:e9:22:e9:21:21:03:d0:d4:8c:84:7f:7c:88:8b:c1:7e:63:44:e6:53:2f:e5:25:f9:40:fc:b7:3a:64:ce:dc:da:9c:23:cb:4e:78:11:46:5a:2c:df:26:e9:4b:fd:1b:eb:12:43:84:d9:1b:ab:85:38:41:3a:60:18:83:2d:52:b0:6f:55:45:93:a7:b4:de:88:c2:75:40:1c:0d:b4:31:c1:e9:36:cd:83:de:e0:33:fa:8d:1c:e0:83:a3:76:02:c7:fc:50:1a:64:eb:81:56:f5:29:b6:8b:b2:42:67:dd:50:59:54:d9:b1:a2:d7:43:43:f4:f7:a2:2d:63:72:84:a9:3b:57:b8:2e:0f:95:a8:aa:8b:52:8a:a2:9c:4a:c7:79:92:28:a7:98:0e:f1:fb:4e:ae:0d:63:5d:a3:24:27:07:99:9b:83:dd:ce:f3:b2:77:70:87:4f:ec:d2:09:c4:20:8c:15:a5:34:6e:7b:37:bb:08:50:c5:76:5e:5b:14:88:f2:bd:72:3b:53:74:27:5c:c0:08:c3:19:93:6d:30:d3:0e:a0:94:2c:fe:ea:d4:28:18:6e:e4:94:2e:ee:ee:a3:16:13:eb:9f:22:c3:2c:0f:63:20:a1:e8:6c:20:26:50:96:d8:0a:3b:6e:62:d2:9b:df:4f:67:2e:14:c8:28:eb:63:1e:2d:47:76:1d:59:ef:b5:b2:ba:bb:31:3a:a1:64:98:65:e9:e8:27:6a:ff:2d:3e:de:74:7f:30:ab:b3:69:58:3e:5e:a7:df:d7:86:64:b0:ad:9c:97:d8:82:89:bc:47:aa:97:6a:63:9d:a6:00:0a:cc:3a:34:f2:04:dc:3c:49:df:74:ca:34:a7:f9:82:06:c7:61:43:ff:d7:53:53:1c:dc:78:fe:9e:dd:25:7f:6c:de:b2:eb:2f:65:cf:3d:81:54:58:1b:64:42:02:c5:60:f7:5f:47:04:2c:10:cc:2a:12:84:27:78:58:c5:75:6c:50:bc:1e:d4:29:91:f6:71:af:1e:87:7e:03:8c:38:1e:ca:0c:25:d1:39:d9:3a:35:b4:7b:40:cb:e5:65:37:7f:9d:01:e9:c6:8b:df:b9:d6:12:55:fe:c8:85:63:4e:98:f6:30:87:f0:56:3c:95:88:94:25:3f:83:3d:3f:0a:74:92:fd:6d:49".replace(":", "")
prime1_hex = "00:f5:6f:18:d1:e5:b4:77:38:4e:1f:45:00:20:78:dc:bc:a6:06:d4:8e:3b:f9:bc:3e:0c:d5:1d:44:15:ac:5b:83:61:32:d9:ef:55:39:d2:4f:57:f4:8b:92:04:af:62:88:82:28:ce:f8:55:ae:b0:1b:5d:0e:e6:cf:09:e7:69:89:df:2e:88:4f:91:f4:28:c3:be:2c:be:d1:0b:a2:92:40:b1:73:38:2d:01:dd:7b:9a:b0:c0:4b:7c:15:bf:4b:88:e3:e1:7b:c8:05:70:a2:a6:e1:f3:4d:ae:fa:75:a6:0f:74:f1:f4:11:3b:1c:e1:d6:40:df:93:ea:a6:7f:d2:ee:b0:4c:11:56:56:50:c0:ce:19:a7:bf:33:ab:89:0a:7d:4e:68:a3:cf:59:38:7b:1f:53:74:27:6c:ba:a0:01:93:d9:03:b7:39:74:d6:c8:16:c9:c0:5f:59:82:96:b1:51:f2:d6:3b:0d:37:23:02:19:7b:9c:74:37:d0:d9:7a:03:2a:b7:1b:33:34:8c:30:9d:80:7e:4f:af:93:2b:4a:9d:f4:46:5b:ed:50:4c:74:65:a9:e9:d7:a2:c2:de:8c:e2:36:c9:e9:ed:8b:76:10:a4:2d:37:86:79:39:71:33:42:24:78:e5:00:85:83:fc:9e:6a:f3:ba:71:6e:95:d8:ad".replace(":", "")
prime2_hex = "00:e4:25:95:9d:01:f8:34:d9:88:43:a7:8d:c0:f3:e1:07:98:35:f7:d8:27:bd:fa:15:ad:05:1f:65:79:73:6d:7c:a6:b1:dd:59:ab:05:ae:3e:11:69:81:30:12:06:43:6f:37:32:ff:70:2c:ae:7c:98:f5:de:c4:f7:40:39:40:da:16:f0:0a:21:e7:8b:07:62:6f:c2:df:41:05:08:20:b3:b7:a0:3a:c3:b2:43:9a:c0:9f:8c:47:a0:8f:06:d3:92:3a:0a:a2:cc:2c:85:d6:5d:ba:21:7d:a5:81:8b:30:08:38:16:50:2b:0b:8a:6e:50:f3:09:bd:6e:24:13:2e:74:32:ac:5c:a9:33:50:a2:b6:17:69:72:44:1c:bc:44:7f:f0:64:20:6b:61:9a:40:7e:49:14:7b:81:02:2b:fe:66:67:b0:d2:9d:d6:cc:c9:5e:19:4a:01:5f:df:59:31:d5:a3:5a:a9:d9:37:ff:55:5e:22:f1:87:54:7c:07:e4:e5:fc:28:ae:e2:60:8f:f9:d8:94:10:23:59:82:df:7e:c2:93:05:ae:9a:3b:d9:51:4e:fd:eb:d5:26:82:6b:7f:b6:38:42:8f:12:48:4d:4e:12:5f:4b:30:45:48:29:de:4d:9e:24:d6:31:21:99:2e:9d:0a:77:8f:37:d9:bf:75:c7".replace(":", "")

# Convert hex strings to integers
modulus = int(modulus_hex, 16)
private_exponent = int(private_exponent_hex, 16)
prime1 = int(prime1_hex, 16)
prime2 = int(prime2_hex, 16)

# Compute n from p and q to verify
n_from_pq = prime1 * prime2

print(modulus)
print("\n")
print(public_exponent)
print("\n")
print(private_exponent)
print("\n")
print(prime1)
print("\n")
print(prime2)
print("\n")
print(n_from_pq),
print("\n")
print(modulus == n_from_pq)
