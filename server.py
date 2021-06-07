import socketserver
import socket, os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from binascii import unhexlify, hexlify
from secret import FLAG, MSG
import base64
import os

key = os.urandom(16)
iv = os.urandom(16)


def encrypt_data(data):
	pt = pad(data.encode(),16,style='pkcs7')
	cipher = AES.new(key, AES.MODE_CBC,iv)
	enc = cipher.encrypt(pt)
	return enc.hex()

def decrypt_data(encryptedParams):
	assert len(encryptedParams) >= 32
	IV = encryptedParams[:32]
	data = encryptedParams[32:]
	cipher = AES.new(key, AES.MODE_CBC,unhexlify(IV))
	paddedParams = cipher.decrypt( unhexlify(data))
	pt = unpad(paddedParams,16,style='pkcs7')
	return pt

def send_msg(s, msg):
	enc = msg.encode()
	s.send(enc)

def main(s):
	wlcm_msg = "Welcome to practice for Padding Oracle Attack\n"
	send_msg(s, wlcm_msg)
	msg = base64.b64encode(MSG.encode()).decode()
	send_msg(s, "Guest ciphertext: " + encrypt_data(msg)+'\n')
	IV = hexlify(iv).decode()
	send_msg(s, "IV : "+IV+"\n")
	while True:
		#任意の暗号文を復号できる
		send_msg(s, 'What ciphertext do you want to decrypt? (hex): ')
		ct = s.recv(4096).decode().strip()
		try:
			check = decrypt_data(ct)
			send_msg(s, "check you can login\n")
		except Exception as e:
			send_msg(s, str(e) + '\n')
			continue

		try:
			pt = base64.b64decode(check).decode()
			if pt[:25] == MSG[:25]:
				send_msg(s, "You can login!\n")
				if pt[25:] == "admin":
					#ここに来たい
					clear_msg = "OK! You are admin! Here is flag\n"
					send_msg(s, clear_msg)
					send_msg(s, FLAG+"\n")
				else:
					guest_msg = "However, because you are not admin, we can not send you flag\n"
					send_msg(s, guest_msg)
			else:
				invalid_msg = "We can not recognize your input for our service\n"
				send_msg(s, invalid_msg)
		except Exception as e:
			send_msg(s, str(e) + '\n')

class TaskHandler(socketserver.BaseRequestHandler):
	def handle(self):
		main(self.request)

if __name__ == '__main__':
	socketserver.ThreadingTCPServer.allow_reuse_address = True
	server = socketserver.ThreadingTCPServer(('0.0.0.0', 3000), TaskHandler)
	server.serve_forever()
