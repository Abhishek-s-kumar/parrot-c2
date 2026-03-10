line = "1525879831.015811\tCUmrqr4svHuSXJy5z7\t192.168.100.103\t51524\t65.127.233.163\t23\ttcp\t-\t2.999051\t0\t0\tS0\t-\t-\t0\tS\t3\t180\t0\t0\t(empty)\tMalicious\tPartOfAHorizontalPortScan"
parts = line.strip().split('\t')
print(f"Len: {len(parts)}")
for i, p in enumerate(parts):
    print(f"{i}: {p}")
