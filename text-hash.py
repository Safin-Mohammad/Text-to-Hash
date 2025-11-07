import hashlib
import os

RED = "\033[0;31m"
GREEN = "\033[0;32m"
BLUE = "\033[1;34m"

os.system("clear")

a = """
     _____         _     _        
    |_   _|       | |   | |       
      | | _____  _| |_  | |_ ___  
      | |/ _ \ \/ / __| | __/ _ \ 
      | |  __/>  <| |_  | || (_) |
      \_/\___/_/\_\\__|  \__\___/ 
	                                """
b = """
        _   _   ___   _____ _   _ 
       | | | | / _ \ /  ___| | | |
       | |_| |/ /_\ \\ `--.| |_| |
       |  _  ||  _  | `--. \  _  |
       | | | || | | |/\__/ / | | |
       \_| |_/\_| |_/\____/\_| |_/
"""
def banner():
	print("_"*67)
	print(a)
	print(b)
	print("\ncreated by SAFIN MOHAMMAD")
	print("_"*67)
banner()
i = 1
print("""
[1] I want to convert single word into hash
[2] I want to convert hash from a txt file
""")
optn = input("[+] choose any one : ")
if optn == "1":
	hash = input("[+] Enter passwd to secure by hashing algorithom : ").encode()
	print("""
[1] md5
[2] sha1
[3] sha224
[4] sha256
[5] sha384
[6] sha512
[7] sha3_224
[8] sha3_256
[9] sha3_384
[10] sha3_512
[11] blake2b
[12] blake2s
""")
	htype = input("[+] What kind of hssh you want to convert : ")
	if htype == "1":
		h = hashlib.md5()
		h.update(hash)
		print(h.hexdigest())
	elif htype == "2":
		h = hashlib.sha1()
		h.update(hash)
		print(h.hexdigest())		
	elif htype == "3":
		h = hashlib.sha224()
		h.update(hash)
		print(h.hexdigest())		
	elif htype == "4":
		h = hashlib.sha256()
		h.update(hash)
		print(h.hexdigest())		
	elif htype == "5":
		h = hashlib.sha384()
		h.update(hash)
		print(h.hexdigest())		
	elif htype == "6":
		h = hashlib.sha512()
		h.update(hash)
		print(h.hexdigest())		
	elif htype == "7":pp
		h = hashlib.sha3_224()
		h.update(hash)
		print(h.hexdigest())		
	elif htype == "8":
		h = hashlib.sha3_256()
		h.update(hash)
		print(h.hexdigest())
	elif htype == "9":
		h = hashlib.sha3_384()
		h.update(hash)
		print(h.hexdigest())
	elif htype == "10":
		h = hashlib.sha3_512()
		h.update(hash)
		print(h.hexdigest())
	elif htype == "11":
		h = hashlib.blake2b()
		h.update(hash)
		print(h.hexdigest())
	elif htype == "12":
		h = hashlib.blake2s()
		h.update(hash)
		print(h.hexdigest())
	else:
		print("[-] Invalid hash type ")
		exit()	
elif optn == "2":
	try:
		f = input("[+] Enter your terget txt file : ")
		file = open(f,"r",errors="replace").read()
	except FileNotFoundError:
		print("[-] File not found ! ")
		exit()	
	print("""
[1] md5
[2] sha1
[3] sha224
[4] sha256
[5] sha384
[6] sha512
[7] sha3_224
[8] sha3_256
[9] sha3_384
[10] sha3_512
[11] blake2b
[12] blake2s
	""")	
	htype = input("[+] What kind of hssh you want to convert : ")
	if htype == "1":
		for line in file:
			password = line.strip()
			hashed_password = hashlib.md5(password.encode()).hexdigest()
			print(hashed_password)
			i = i + 1
		print("[+]",i - 1, "lines converted into hash")
		print("[+] copy and save on a new txt file")	
	elif htype == "2":
		for line in file:
			password = line.strip()
			hashed_password = hashlib.sha1(password.encode()).hexdigest()
			print(hashed_password)
			i = i + 1
		print("[+]",i - 1, "lines converted into hash")
		print("[+] copy and save on a new txt file")		
	elif htype == "3":
		for line in file:
			password = line.strip()
			hashed_password = hashlib.sha224(password.encode()).hexdigest()
			print(hashed_password)
			i = i + 1
		print("[+]",i - 1, "lines converted into hash")
		print("[+] copy and save on a new txt file")		
	elif htype == "4":
		for line in file:
			password = line.strip()
			hashed_password = hashlib.sha256(password.encode()).hexdigest()
			print(hashed_password)
			i = i + 1
		print("[+]",i - 1, "lines converted into hash")
		print("[+] copy and save on a new txt file")	
	elif htype == "5":
		for line in file:
			password = line.strip()
			hashed_password = hashlib.sha384(password.encode()).hexdigest()
			print(hashed_password)
			i = i + 1
		print("[+]",i - 1, "lines converted into hash")
		print("[+] copy and save on a new txt file")		
	elif htype == "6":
		for line in file:
			password = line.strip()
			hashed_password = hashlib.sha512(password.encode()).hexdigest()
			print(hashed_password)
			i = i + 1
		print("[+]",i - 1, "lines converted into hash")
		print("[+] copy and save on a new txt file")	
	elif htype == "7":
		for line in file:
			password = line.strip()
			hashed_password = hashlib.sha3_224(password.encode()).hexdigest()
			print(hashed_password)
			i = i + 1
		print("[+]",i - 1, "lines converted into hash")
		print("[+] copy and save on a new txt file")	
	elif htype == "8":
		for line in file:
			password = line.strip()
			hashed_password = hashlib.sha3_256(password.encode()).hexdigest()
			print(hashed_password)
			i = i + 1
		print("[+]",i - 1, "lines converted into hash")
		print("[+] copy and save on a new txt file")	
	elif htype == "9":
		for line in file:
			password = line.strip()
			hashed_password = hashlib.sha3_384(password.encode()).hexdigest()
			print(hashed_password)
			i = i + 1
		print("[+]",i - 1, "lines converted into hash")
		print("[+] copy and save on a new txt file")	
	elif htype == "10":
		for line in file:
			password = line.strip()
			hashed_password = hashlib.sha3_512(password.encode()).hexdigest()
			print(hashed_password)
			i = i + 1
		print("[+]",i - 1, "lines converted into hash")
		print("[+] copy and save on a new txt file")	
	elif htype == "11":
		for line in file:
			password = line.strip()
			hashed_password = hashlib.blake2b(password.encode()).hexdigest()
			print(hashed_password)
			i = i + 1
		print("[+]",i - 1, "lines converted into hash")
		print("[+] copy and save on a new txt file")	
	elif htype == "12":
		for line in file:
			password = line.strip()
			hashed_password = hashlib.blake2s(password.encode()).hexdigest()
			print(hashed_password)
			i = i + 1
		print("[+]",i - 1, "lines converted into hash")
		print("[+] copy and save on a new txt file")			
	else:
		print("[-] Invalid hash type ")
		exit()		
else:
	print("[-] Invalid choice ! ")
