import os
import sys
import requests
import json
# You'll need to install the following modules
# I used PyCrypto which can be installed manually or using "pip install pycrypto"
import binascii
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from base64 import b64decode

tab_server_url = "http://YourTableauServerUrlGoesHere"
tableau_username = raw_input("Enter your username: ")
tableau_password = raw_input("Input your password: ")

def _encode_for_display(text):
    """
    Encodes strings so they can display as ASCII in a Windows terminal window.
    This function also encodes strings for processing by xml.etree.ElementTree functions.
    Returns an ASCII-encoded version of the text.
    Unicode characters are converted to ASCII placeholders (for example, "?").
    """
    return text.encode('ascii', errors="backslashreplace").decode('utf-8')

# Establish a session so we can retain the cookies
session = requests.Session()

def generatePublicKey():
      payload = "{\"method\":\"generatePublicKey\",\"params\":{}}"
      endpoint = "generatePublicKey"
      url = tab_server_url + "/vizportal/api/web/v1/"+endpoint
      headers = {
      'content-type': "application/json;charset=UTF-8",
      'accept': "application/json, text/plain, */*",
      'cache-control': "no-cache"
      }
      response = session.post(url, data=payload, headers=headers)
      response_text = json.loads(_encode_for_display(response.text))
      response_values = {"keyId":response_text["result"]["keyId"], "n":response_text["result"]["key"]["n"],"e":response_text["result"]["key"]["e"]}
      return response_values

# Generate a pubilc key that will be used to encrypt the user's password
public_key = generatePublicKey()
pk = public_key["keyId"]


# Encrypt with RSA public key (it's important to use PKCS11)
def assymmetric_encrypt(val, public_key):
     modulusDecoded = long(public_key["n"], 16)
     exponentDecoded = long(public_key["e"], 16)
     keyPub = RSA.construct((modulusDecoded, exponentDecoded))
     # Generate a cypher using the PKCS1.5 standard
     cipher = PKCS1_v1_5.new(keyPub)
     return cipher.encrypt(val)

# Encrypt the password used to login
encryptedPassword = assymmetric_encrypt(tableau_password,public_key)

def vizportalLogin(encryptedPassword, keyId):
     encodedPassword = binascii.b2a_hex(encryptedPassword)
     payload = "{\"method\":\"login\",\"params\":{\"username\":\"%s\", \"encryptedPassword\":\"%s\", \"keyId\":\"%s\"}}" % (tableau_username, encodedPassword,keyId)
     endpoint = "login"
     url = tab_server_url + "/vizportal/api/web/v1/"+endpoint
     headers = {
     'content-type': "application/json;charset=UTF-8",
     'accept': "application/json, text/plain, */*",
     'cache-control': "no-cache"
     }
     response = session.post(url, data=payload, headers=headers)
     return response

login_response = vizportalLogin(encryptedPassword, pk)
if login_response.status_code == 200:
    print "Login to Vizportal Successful!"

sc = login_response.headers["Set-Cookie"]
set_cookie = dict(item.split("=") for item in sc.split(";"))
xsrf_token, workgroup_session_id = set_cookie[" HttpOnly, XSRF-TOKEN"], set_cookie["workgroup_session_id"]
#Use this for connections with SSL
sc = login_response.headers["Set-Cookie"]
headers = []
for item in sc.split(";"):
    print item
    if "workgroup" in item:
        headers.append(item.split("=")[1])
    elif "XSRF" in item:
        headers.append(item.split("=")[1])
workgroup_session_id, xsrf_token = headers[0], headers[1]
