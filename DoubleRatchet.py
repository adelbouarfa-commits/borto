from cryptography.hazmat.primitives.asymmetric import x25519
import hmac
import hashlib

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.number import long_to_bytes
# im here 

key = bytes.fromhex(HexMykey)
data = bytes.fromhex(HexEncryptedOriginalMessage)
cipher = AES.new(key, AES.MODE_GCM)
dec = cipher.decrypt_and_verify(data)


#HKDF function:
def hkdf_extract(salt, ikm, hash=hashlib.sha512):
    #ikm is input key material (in our case it's the concatination of DH)
	#compare with kdf
    hash_len = hash().digest_size
    if salt == None or len(salt) == 0:
        salt = bytearray((0,) * hash_len)
    return hmac.new(bytes(salt), ikm, hash).digest()

def hkdf_expand(pseudo_random_key,info=b"", length=32, hash=hashlib.sha512):
    #length is the length of generated keys:
	hash_len = hash().digest_size
	length = int(length)
	if length > 255 * hash_len:
		raise Exception("Cannot expand to more than 255 * %d = %d bytes using the specified hash function" %\
			(hash_len, 255 * hash_len))
	blocks_needed = length // hash_len + (0 if length % hash_len == 0 else 1) # ceil
	okm = b""
	#output key material
	output_block = b""
	for counter in range(blocks_needed):
		output_block = hmac.new(pseudo_random_key, output_block + info + bytearray((counter + 1,)),
			hash).digest()
		okm += output_block
	return okm[:length]



# 1. Alice generates her key pair
IK_a_private = x25519.X25519PrivateKey.generate()
IK_a = IK_a_private.public_key()

# 2. Bob generates his key pair
IK_b_private = x25519.X25519PrivateKey.generate()
IK_b = IK_b_private.public_key()


#Signed key:
SPK_b_private = x25519.X25519PrivateKey.generate()
SPK_b_public = SPK_b_private.public_key()

def X3DH(IK_a_private,EK_private,IK_b,SPK_public,OPK_public):
      # DH1 = DH(IK_A, SPK_B)
    DH1 = IK_a_private.exchange(SPK_public)

# DH2 = DH(EK_A, IK_B)
    DH2 = EK_private.exchange(IK_b)

# DH3 = DH(EK_A, SPK_B)
    DH3 = EK_private.exchange(SPK_public)



#input key material IKM
    if(OPK_public==None ):
          return DH1 + DH2 + DH3
       # DH4 = DH(EK_A, OPK_B)
    DH4 = EK_private.exchange(OPK_public)
    return DH1 + DH2 + DH3 + DH4
      


    
# ephemeral key:
EK_a_private = x25519.X25519PrivateKey.generate()
EK_a_public = EK_a_private.public_key()

#One time key:
OPK_b_private = x25519.X25519PrivateKey.generate()
OPK_b_public = OPK_b_private.public_key()

#Bob's ratchet side:
DHr_private=x25519.X25519PrivateKey.generate()
DHr_public=DHr_private.public_key() #to be sent


SK=X3DH(IK_a_private,EK_a_private,IK_b,SPK_b_public,OPK_b_public)
#intialise RK:
RK=hkdf_extract(SK)
for i in range(5): #DH ratchet
    DHs_private=x25519.X25519PrivateKey.generate()
    DHs_public=DHs_private.public_key() #to be sent

    DH=DHs_private.exchange(DHr_public) #shared secret

    RK_extract=hkdf_extract(RK,DH) 
    RK_con=hkdf_expand(RK_extract,length=64)
    RK=RK_con[:32] #root key
    CK=RK_con[32:] #chain key

    #kdf ratchet:
    for j in range(5):
          MK=hmac.new(CK, b"\x01", hashlib.sha512).digest()
          CK=hmac.new(CK, b"\x02", hashlib.sha512).digest()
	