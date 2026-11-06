import getpass, pyaes, pbkdf2, json, multiprocessing, secrets, os, base64, hashlib, string, otpv2

def main():
	#Load JSON data
	try:
		with open("/home/" + getpass.getuser() + "/.pyotpdata.json") as f:
			data = json.loads(f.read())
	except:
		os.system("touch /home/" + getpass.getuser() + "/.pyotpdata.json")
		with open("/home/" + getpass.getuser() + "/.pyotpdata.json", "w") as f:
			f.write('{"names": [], "psks": [], "salts": [], "ivs": [], "mp": "", "mpiv": 0, "mpsalt": ""}')
			data = json.loads('{"names": [], "psks": [], "salts": [], "ivs": [], "mp": "", "mpiv": 0, "mpsalt": ""}')
	charset = string.ascii_letters + string.digits
	
	if data["mp"] == "":
		print("PyOTP - First Time Setup\n")
		
		#Get MP twice and verify entries are the same
		password = ""
		verPassword = " "
		while True:
			password = getpass.getpass(prompt="Password: ")
			verPassword = getpass.getpass(prompt="Confirm Password: ")
			if secrets.compare_digest(password, verPassword):
				break
			print("\nPasswords don't match, please try again:")
		
		#Store MP data (but NOT the MP itself), encoding to base64 as needed
		#Also encrypt and store a confirmation to tell whether the MP is correct later
		data["mpsalt"] = base64.b64encode(secrets.token_bytes(16)).decode()
		data["mpiv"] = secrets.randbits(256)
		key = pbkdf2.PBKDF2(password, base64.b64decode(data["mpsalt"].encode())).read(32)
		aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(data["mpiv"]))
		data["mp"] = base64.b64encode(aes.encrypt("MP is correct")).decode()
		
		#Save setup immediately, confirm creation of a MP, then continue into the main program
		with open("/home/" + getpass.getuser() + "/.pyotpdata.json", "w") as f:
			f.write(json.dumps(data))
		
		print("Master password created.")
		input()
	else:
		print("PyOTP\n")
		
		#Get MP and test until confirmation message decrypts successfully
		while True:
			password = getpass.getpass(prompt="Password: ")
			key = pbkdf2.PBKDF2(password, base64.b64decode(data["mpsalt"].encode())).read(32)
			aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(data["mpiv"]))
			if aes.decrypt(base64.b64decode(data["mp"].encode())) == "MP is correct".encode():
				break
			else:
				print("\nWrong password, please try again.")
	
	#Main menu loop
	while True:
		os.system("clear")
		print("1. Add OTP\n2. Remove OTP\n3. List OTPs\n4. Access OTP\n5. Generate Random OTP\n6. Reveal PSK\n7. Save to Disk\n8. Save and Exit")
		inp = int(input())
		os.system("clear")
		if inp == 1:
			#Add OTP
			
			#Append a new IV and salt
			data["salts"].append(base64.b64encode(secrets.token_bytes(16)).decode())
			data["ivs"].append(secrets.randbits(256))
			
			#Encrypt PSK and store
			key = pbkdf2.PBKDF2(password, base64.b64decode(data["salts"][len(data["salts"]) - 1].encode())).read(32)
			aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(data["ivs"][len(data["ivs"]) - 1]))
			data["psks"].append(base64.b64encode(aes.encrypt(getpass.getpass(prompt="PSK: "))).decode())
			
			#Add a name
			print("OTP Name: ",end="")
			data["names"].append(str(input()))
			print("\nOTP added auccessfully.")
		elif inp == 2:
			#Delete OTP
			
			print("Index of OTP to delete or -1 to cancel: ", end="")
			inp = int(input())
			if inp == -1:
				print("\nCancelled.")
			elif inp < 0 or inp >= len(data["names"]):
				print("\nInvalid index.")
			else:
				print("\nAre you sure you want to delete " + data["names"][inp] + "?")
				print("Type \"yes\" to delete, anything else to cancel.")
				if input() == "yes":
					#Remove all 4 elements of an OTP entry and confirm removal
					data["names"].pop(inp)
					data["ivs"].pop(inp)
					data["salts"].pop(inp)
					data["psks"].pop(inp)
					print("\nDeletion successful.")
				else:
					print("\nCancelled.")
		elif inp == 3:
			#Lists all OTPs and their indexes
			
			for i in range(0, len(data["names"])):
				print(str(i) + ". " + data["names"][i])
		elif inp == 4:
			#Access OTP
			
			print("Index of OTP: ", end="")
			inp = int(input())
			if inp < 0 or inp >= len(data["names"]):
				print("\nInvalid index.")
			else:
				#Set up OTP process, ensuring plaintext PSK is not stored
				key = pbkdf2.PBKDF2(password, base64.b64decode(data["salts"][inp].encode())).read(32)
				aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(data["ivs"][inp]))
				otpProc = multiprocessing.Process(target=otpv2.runOTP, args=(hashlib.sha512(aes.decrypt(base64.b64decode(data["psks"][inp].encode())).decode().encode("ascii")).hexdigest(),))
				
				#Print header and start process
				print("Accessing OTP for " + data["names"][inp] + " (press ENTER to exit).\n")
				otpProc.start()
				input()
				while otpProc.is_alive():
					otpProc.terminate()
				otpProc.close()
				print("\nViewer exited successfully.")
		elif inp == 5:
			#Add random OTP
			
			#Generate new PSK and report it to user
			psk = ""
			for i in range(30):
				psk += secrets.choice(charset)
			print("Your PSK is " + psk)
			print("This can be used to access your OTPs, so only share it with people and programs you trust.")
			
			#Append a new IV and salt
			data["salts"].append(base64.b64encode(secrets.token_bytes(16)).decode())
			data["ivs"].append(secrets.randbits(256))
			
			#Encrypt PSK and store
			key = pbkdf2.PBKDF2(password, base64.b64decode(data["salts"][len(data["salts"]) - 1].encode())).read(32)
			aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(data["ivs"][len(data["ivs"]) - 1]))
			data["psks"].append(base64.b64encode(aes.encrypt(psk)).decode())
			
			#Overwrite psk variable since it's no longer needed
			#(not sure if it actually deletes the old value but worth a shot)
			psk = secrets.randbits(256)
			
			#Add a name
			print("\nOTP Name: ",end="")
			data["names"].append(str(input()))
			print("\nRandom OTP added auccessfully.")
		elif inp == 6:
			#Reveal PSK
			
			print("Index of OTP: ", end="")
			inp = int(input())
			if inp < 0 or inp >= len(data["names"]):
				print("\nInvalid index.")
			else:
				#Decrypt PSK and show to user
				key = pbkdf2.PBKDF2(password, base64.b64decode(data["salts"][inp].encode())).read(32)
				aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(data["ivs"][inp]))
				print("The PSK for " + data["names"][inp] + " is " + aes.decrypt(base64.b64decode(data["psks"][inp].encode())).decode())
				print("This can be used to access your OTPs, so only share it with people and programs you trust.")
		elif inp == 7:
			with open("/home/" + getpass.getuser() + "/.pyotpdata.json", "w") as f:
				f.write(json.dumps(data))
			print("Data saved to disk.")
		elif inp == 8:
			#Exit
			
			break
		else:
			print("\nInvalid option.")
		input()
	
	#Store data
	with open("/home/" + getpass.getuser() + "/.pyotpdata.json", "w") as f:
		f.write(json.dumps(data))
	
	#Overwrite all variables with random integers
	#(no clue if this actually helps security, but it surely can't hurt)
	password = secrets.randbits(256)
	verPassword = secrets.randbits(256)
	key = secrets.randbits(256)
	aes = secrets.randbits(256)
	inp = secrets.randbits(256)
	data = secrets.randbits(256)
	otpProc = secrets.randbits(256)
	psk = secrets.randbits(256)
	
	#Clear screen and print exit message
	os.system("clear")
	print("Data saved to disk.\nPyOTP exited successfully.")

if __name__ == "__main__":
	main()
