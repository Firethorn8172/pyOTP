import hashlib, random, secrets, time, string, getpass
charset = string.ascii_letters + string.digits

def runOTP(pskHash):
	#Verify PSK has been hashed
	if len(pskHash) != 128:
		print("OTP error: PSK is not a valid SHA512 hash.")
	for char in pskHash.lower():
		if not char in string.hexdigits:
			print("OTP error: PSK is not a valid SHA512 hash.")
			return -1
	
	#Setup time variable
	t = int(time.time()) // 30
	
	#Display first code immediately so no startup delay
	random.seed(hashLoop(pskHash, int(time.time()) // 30))
	while random.random() < random.random():
		None
	while random.random() > random.random():
		None
	print("OTP: " + str(int(random.random() * 900000) + 100000) + " - ", end="\r")
	
	#Finish sync with countdown
	for i in range(30 - (int(time.time()) % 30), 1, -1):
			print("\u001b[14C" + str(i) + "   ", end="\r")
			time.sleep(0.96)
	print("\u001b[14C1   ", end="\r")
	t += 1
	while t > int(time.time()) // 30:
		None
	
	while True:
		#Seed with hashed-together time and PSK
		random.seed(hashLoop(pskHash, t))
		
		#Purge a random number of randoms for grins, giggles, and extra chaos
		while random.random() < random.random():
			None
		while random.random() > random.random():
			None
		
		#Print OTP
		print("OTP: " + str(int(random.random() * 900000) + 100000) + " - ", end="\r")
		
		#Wait most of the 30s and print slightly-too-fast countdown (helps correct errors)
		for i in range(30, 0, -1):
			print("\u001b[14C" + str(i) + "   ", end="\r")
			time.sleep(0.96)
		
		#Increment t and wait for time() to catch up to ensure synchronization (repeat if needed for error correction)
		t += 1
		while t > int(time.time()) // 30:
			None
		while t < int(time.time()) // 30:
			t += 1
			while t > int(time.time()) // 30:
				None

def verifyOTP(pskHash, otp):
	#Verify OTP got inputted correctly
	try:
		otp = int(otp)
	except:
		print("OTP error: OTP is not an integer")
		return False
	
	#Verify PSK has been hashed
	if len(pskHash) != 128:
		print("OTP error: PSK is not a valid SHA512 hash.")
	for char in pskHash.lower():
		if not char in string.hexdigits:
			print("OTP error: PSK is not a valid SHA512 hash.")
			return False
	
	#Do the OTP setup for the current time, no syncing, no loop-and-print
	random.seed(hashLoop(pskHash, int(time.time()) // 30))
	while random.random() < random.random():
		None
	while random.random() > random.random():
		None
	
	#Return whether OTP is valid
	return ((int(random.random() * 900000) + 100000) == otp)
	
def hashLoop(pwHash, now):
	#TLDR does some BS to get a hash
	
	#Seed at time over 30 and pick a random number of loops
	random.seed(now)
	loops = int(random.random() * 100) + 10
	
	#Make initial hashes
	timeHash = hashlib.sha512(str(now).encode("ascii")).hexdigest()
	pwHash = hashlib.sha512(pwHash.encode("ascii") + timeHash.encode("ascii")).hexdigest()
	
	#Torment those poor numbers for a while (now with 20% more RNG), then return hash
	for i in range(loops):
		if int(random.random() * 10) < 3:
			pwHash = hashlib.sha512(pwHash.encode("ascii") + timeHash.encode("ascii")).hexdigest()
		else:
			pwHash = hashlib.sha512(pwHash.encode("ascii")).hexdigest()
	
	return pwHash

def main():
	print("Select function:\n1) Generate PSK and run\n2) Run OTP from PSK\n3) Verify OTP")
	inp = int(input())
	if inp == 1:
		psk = ""
		for i in range(30):
			psk += secrets.choice(charset)
		print(psk)
		psk = hashlib.sha512(psk.encode("ascii")).hexdigest()
		runOTP(psk)
	elif inp == 2:
		runOTP(hashlib.sha512(getpass.getpass("PSK: ").encode("ascii")).hexdigest())
	elif inp == 3:
		print("-1 for OTP to exit")
		pskHash = hashlib.sha512(getpass.getpass("PSK: ").encode("ascii")).hexdigest()
		while True:
			otp = int(input("OTP Code: "))
			if str(otp) == "-1":
				break
			elif verifyOTP(pskHash, otp):
				print("OTP Valid")
			else:
				print("OTP Invalid")
	else:
		print("Invalid option.")

if __name__ == "__main__":
	main()
