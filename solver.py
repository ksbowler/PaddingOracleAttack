from Crypto.Util.number import *
from functools import reduce
from operator import mul
from itertools import combinations
import sys
import socket, struct, telnetlib
from tqdm import tqdm
import base64
from Crypto.Util.Padding import pad,unpad

# --- common funcs ---
def sock(remoteip, remoteport):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((remoteip, remoteport))
	return s, s.makefile('rw')

def read_until(f, delim='\n'):
	data = ''
	while not data.endswith(delim):
		data += f.read(1)
	return data

		
def xorrev(rev):
	k = len(rev)//2+1
	cnt = len(rev)//2
	ret = ""
	for i in range(0,len(rev),2):
		tmp = int(rev[i:i+2],16)^cnt^k
		cnt-=1
		tmp = str(hex(tmp))[2:]
		if len(tmp) == 1: tmp = "0"+tmp
		ret += tmp

	return ret
	
#HOSTはIPアドレスでも可
HOST, PORT = "0.0.0.0", 3000
s, f = sock(HOST, PORT)
read_until(f)
#暗号文とIVを取得
enc = read_until(f).split()[-1]
iv = read_until(f).split()[-1]
print("encrypted message :",enc,"and len enc :",len(enc))
print("iv :",iv)
#Decryption Attack
#各パラメータ設定
m = b"" #求めたい平文
dec3 = 0 #Encryption Attackで使う最後のブロックのkey decrypt後の値
num = 94
enc = iv+enc
for i in range(3):
	#各ブロックについて
	bef_rev = ""
	rev = enc[32*(3-i):32*(3-i+1)] #0:64:96, 1:32:64, 2:0:32 brute force するブロックの一つ後ろのブロック
	for j in tqdm(range(16)):
		#各ブロックの1byteについて
		#brute forceするbyte以外の暗号文の調整
		mes = "00"*(16*(3-i)-j-1)
		rem = xorrev(bef_rev)
		for k in range(256):
			#brute force start
			read_until(f,"(hex): ")
			t = str(hex(k))[2:]
			if len(t) == 1: t = "0"+t
			tmes = mes + t + rem + rev
			assert len(tmes) == 32*(4-i)
			s.send(tmes.encode()+b"\n")
			recv_m = read_until(f).strip()
			if "check" in recv_m:
				#paddingが成功した
				kk = str(hex(k))[2:]
				if len(kk) == 1: kk = "0"+kk
				bef_rev = kk + bef_rev
				if i == 0:
					#Encryption Attackで使う
					temp_dec3 = k^(j+1)
					dec3 += temp_dec3*pow(256,j)
				dec = k^(j+1) #dec(cx)が求まる
				tmp = int(enc[num:num+2],16)^dec #平文が求まる
				num -= 2
				m = long_to_bytes(tmp)+ m
				print("m =",m)
				break
			
print("decryption attack finish!")
print("plaintext m =",m)
M = base64.b64decode(m)
tamp = M[:-5] + b"admin"
tames = pad(base64.b64encode(tamp),16)

#このような平文に対する暗号文を生成したい
#Encryption Attack
print("I want this mes.",tames)
modi = str(hex(bytes_to_long(tames)))[2:]
assert len(modi)%32 == 0
m3 = bytes_to_long(tames[-16:])
c3 = dec3^m3
c3 = str(hex(c3))[2:]
print(c3,len(c3))
last = c3 + enc[96:]
rev = c3
num = 62
C = ""
for i in range(2):
	bef_rev = ""
	for j in tqdm(range(16)):
		mes = "00"*(16*(2-i)-j-1)
		rem = xorrev(bef_rev)
		for k in range(256):
			read_until(f,"(hex): ")
			t = str(hex(k))[2:]
			if len(t) == 1: t = "0"+t
			tmes = mes + t + rem + rev
			assert len(tmes) == 32*(3-i)
			s.send(tmes.encode()+b"\n")
			recv_m = read_until(f).strip()
			if "check" in recv_m:
				#padding成功した
				kk = str(hex(k))[2:]
				if len(kk) == 1: kk = "0"+kk
				bef_rev = kk + bef_rev
				dec = k^(j+1)
				tmp_c = int(modi[num:num+2],16)^dec
				num -= 2
				tmp_c = str(hex(tmp_c))[2:]
				if len(tmp_c) == 1: tmp_c = "0" + tmp_c
				last = tmp_c + last
	rev = last[:32]
read_until(f,"(hex): ")
s.send(last.encode()+b"\n")
while True: print(read_until(f))








"""
temp_enc = enc[:64]
for j in tqdm(range(16)):
	print("temp_enc:",temp_enc)
	#mes = modify(temp_enc,i,j)
	num = 32-(j+1)*2
	print("num: ",num)
	mes = modify(temp_enc,0,j,num)
	#print(mes)
	for k in range(256):
			#mes = modify(enc,i,j)
		read_until(f,"(hex): ")
		t = str(hex(k))[2:]
		if len(t) == 1: t = "0"+t
		tmes = mes[:num] + t + mes[num:]
			#print(tmes[:32*(i+1)-(j+1)*2],tmes[32*(i+1)-(j+1)*2:32*(i+1)-(j+1)*2+2],tmes[32*(i+1)-(j+1)*2+2:])
			#print(tmes[:num],tmes[num:num+2],tmes[num+2:])
		#print(tmes[:num],tmes[num:num+2],tmes[num+2:])
		assert len(tmes) == 64
			#print(k,tmes)
		s.send(tmes.encode()+b"\n")
		recv_m = read_until(f).strip()
			#print(i,j,recv_m)
			#print(k,recv_m)
		if "check" in recv_m:
			print(recv_m)
			#if k == 0xf: continue
			#padding上手くいった
				#m = c^c'^m' // m' = \x01とか, c' = k, cは該当バイト
				#num = 32*(i+1)-(j+1)*2
			print("Find!",hex(k))
			#print(i,j,num)
			print(temp_enc)
			temp_enc = temp_enc[:num] + t + temp_enc[num+2:]
			print(temp_enc)
			tmp = int(enc[num:num+2],16)^k^(j+1)
			m = chr(tmp)+ m
			#print("j:",j)
			print("Find padding! temp m is that")
			print(m)
			print()
			break
print(base64.b64decode(m.encode()))
#'b2dpbl9zZXJ2aWNlOiBJD1hZG1pbg==' の暗号文が欲しい
tamp = base64.b64encode(b"_service: ID=admin")
print("bef tamp",tamp)
#print(m.encode()[-16:])
#print(tamp[-16:])
#assert m.encode()[:-16] == tamp[:-16]
tamp = tamp[-8:]+b"\x08"*8
print("tamp:",tamp)
print("assert :",base64.b64decode(long_to_bytes(dec2^int(enc[32:64],16))))
print(bin(bytes_to_long(tamp))[2:])
print(bin(dec2)[2:])
tampered_c1 = str(hex(dec2^bytes_to_long(tamp)))[2:]
while len(tampered_c1) < 32: tampered_c1 = "0" + tampered_c1
assert len(tampered_c1) == 32
last = enc[:32]+tampered_c1+enc[64:]
print(enc)
print(last)
"""
"""
tampered_c1 = str(hex(dec2^bytes_to_long(b"ID=admin")))[2:]
while len(tampered_c1) < 32: tampered_c1 = "0" + tampered_c1
assert len(tampered_c1) == 32
last = enc[:32]+tampered_c1+enc[64:]
"""
#print(read_until(f,"(hex): "))
#s.send(last.encode()+b"\n")

#while True: print(read_until(f))
#print(long_to_bytes(int(enc[:32],16)^int(iv,16)))
#s.close()
#read_untilの使い方
#返り値があるのでprintするか、何かの変数に入れる
#1行読む：read_until(f)
#特定の文字まで読む：read_until(f,"input")
#配列に格納する：recv_m = read_until(f).split() or .strip()

#サーバーに何か送るとき
#s.send(b'1\n') : 1を送っている
#バイト列で送ること。str->bytesにするには、変数の後に.encode()
#必ず改行を入れること。終了ポイントが分からなくなる。ex) s.send(flag.encode() + b'\n')

