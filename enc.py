# Include the Dropbox SDK
import dropbox

# Get your app key and secret from the Dropbox developer website
app_key = '1bb1g8k8r63sext'
app_secret = '76ohlmjf7pi1mn2'

flow = dropbox.client.DropboxOAuth2FlowNoRedirect(app_key, app_secret)

# Have the user sign in and authorize this token
authorize_url = flow.start()
print '1. Go to: ' + authorize_url
print '2. Click "Allow" (you might have to log in first)'
print '3. Copy the authorization code.'
code = raw_input("Enter the authorization code here: ").strip()

# This will fail if the user enters an invalid authorization code
access_token, user_id = flow.finish(code)

client = dropbox.client.DropboxClient(access_token)
print 'linked account: ', client.account_info()

###encryption code -- file name se2.pdf.enc -->O/P from encryption code

from Crypto.Cipher import AES

key = '0123456789abcdef'
IV = 16 * '\x00'           # Initialization vector: discussed later
mode = AES.MODE_CBC
encryptor = AES.new(key, mode, IV=IV)

text = 'j' * 64 + 'i' * 128
ciphertext = encryptor.encrypt(text)

import hashlib

password = 'kitty'
key = hashlib.sha256(password).digest()

decryptor = AES.new(key, mode, IV=IV)
plain = decryptor.decrypt(ciphertext)

import os, random, struct
from Crypto.Cipher import AES

def encrypt_file(key, se2, out_filename=None, chunksize=64*1024):
    """ Encrypts a file using AES (CBC mode) with the
	given key.
	key:
	    The encryption key - a string that must be
	    either 16, 24 or 32 bytes long. Longer keys
	    are more secure.

	in_filename:
	    Name of the input file

	out_filename:
	    If None, '<in_filename>.enc' will be used.

	chunksize:
	    Sets the size of the chunk which the function
	    uses to read and encrypt the file. Larger chunk
	    sizes can be faster for some files and machines.
	    chunksize must be divisible by 16.
    """
    if not out_filename:
	out_filename = se2 + '.enc'

    iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(se2)

    with open(se2, 'rb') as infile:
	with open(out_filename, 'wb') as outfile:
	    outfile.write(struct.pack('<Q', filesize))
	    outfile.write(iv)
	    while True:
	        chunk = infile.read(chunksize)
	        if len(chunk) == 0:
	            break
	        elif len(chunk) % 16 != 0:
	            chunk += ' ' * (16 - len(chunk) % 16)

	        outfile.write(encryptor.encrypt(chunk))

encrypt_file(key,'se2.pdf', out_filename=None, chunksize=64*1024)
f = open('se2.pdf.enc', 'rb')
response = client.put_file('/se2.pdf.enc', f)
print 'uploaded: ', response

#folder_metadata = client.metadata('/')
#print 'metadata: ', folder_metadata

f, metadata = client.get_file_and_metadata('/se2.pdf.enc')
out = open('se2.pdf.enc', 'wb')
out.write(f.read())
out.close()
##decryption code goes here - O/P file name se2.pdf

def decrypt_file(key, in_filename, out_filename='se2Out.pdf', chunksize=24*1024):
    """ Decrypts a file using AES (CBC mode) with the
	given key. Parameters are similar to encrypt_file,
	with one difference: out_filename, if not supplied
	will be in_filename without its last extension
	(i.e. if in_filename is 'aaa.zip.enc' then
	out_filename will be 'aaa.zip')
    """
    if not out_filename:
	out_filename = os.path.splitext(in_filename)[0]

    with open(in_filename, 'rb') as infile:
	origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
	iv = infile.read(16)
	decryptor = AES.new(key, AES.MODE_CBC, iv)

	with open(out_filename, 'wb') as outfile:
	    while True:
	        chunk = infile.read(chunksize)
	        if len(chunk) == 0:
	            break
	        outfile.write(decryptor.decrypt(chunk))

	    outfile.truncate(origsize)

decrypt_file(key, in_filename='se2.pdf.enc', out_filename='se2Out.pdf', chunksize=24*1024)

#delete se2.pdf.enc from local folder
#os.remove('se2.pdf.enc')
#print metadata
