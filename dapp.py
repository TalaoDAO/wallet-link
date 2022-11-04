from flask import Flask,render_template, request, jsonify, redirect,session
import uuid 
import json
import redis
import socket
import string
import random
from pytezos.crypto import key

app = Flask(__name__)
app.secret_key ='miaou'
# https://github.com/airgap-it/beacon-sdk
# https://tezostaquito.io/docs/signing/
characters = string.ascii_letters + string.digits + string.punctuation

def extract_ip():
    st = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:       
        st.connect(('10.255.255.255', 1))
        IP = st.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        st.close()
    return IP

red= redis.Redis(host='127.0.0.1', port=6379, db=0)

def char2Bytes(text):
    return text.encode('utf-8').hex()
input = "Just a text for OPERATION"

def create_payload (input, type) :
  formattedInput = ''.join([
    'Tezos signed message',
    ' ',
    input
  ])
  print(formattedInput)
  if type == 'MICHELINE' :
    sep = '05'
  else :
    sep = '03'
  bytes = char2Bytes(formattedInput)
  payloadBytes = sep + '0100' + char2Bytes(str(len(bytes)))  + bytes
  return payloadBytes

def init_app(app,red) : #mode en param
    app.add_url_rule('/sandbox/saas4ssi/dapp',  view_func=dapp_wallet, methods = ['GET', 'POST'], defaults={'red' : red})
    app.add_url_rule('/sandbox/saas4ssi/dapp/webhook',  view_func=dapp_webhook, methods = ['GET', 'POST'], defaults={'red' : red})
    app.add_url_rule('/validate_sign' , view_func=validate_sign,methods=['GET'])
    global link, client_secret
    #if mode.myenv == 'aws':
        #link = 'https://talao.co/sandbox/op/issuer/kfvuelfugb'
        #client_secret = "c8a7ce61-52e7-11ed-96ff-0a1628958560"
    #else :
    link = "http://192.168.1.17:3000/sandbox/op/issuer/ovjyigjpbc"
    client_secret = '9828d8f8-52d1-11ed-9758-47cea17512cf'

    return

def dapp_wallet(red):
    if request.method == 'GET' :
        nonce = ''.join(random.choice(characters) for i in range(16))
        session["nonce"]="Verify address owning for Altme : "+nonce
        return render_template('dapp.html',nonce= create_payload(session.get('nonce'),'MICHELINE'))
    else :
        id = str(uuid.uuid1())
        red.set(id, json.dumps({"associatedAddress" : request.form["address"],
                                "accountName" : request.form["wallet"],
                                "issuedBy" : {"name" : "Altme"}}))

        return redirect (link + "?id=" + id)

def dapp_webhook(red) :
    if request.headers.get("key") != client_secret :
        return jsonify("Forbidden"), 403
    data = request.get_json()
    try :
        data_returned = json.loads(red.get(data["id"]).decode())   
    except :
        print("error redis")
        data_returned = ""
    # send back data to issue credential
    if data['event'] == 'ISSUANCE' :
        return jsonify(data_returned)
    else :
        return jsonify('ok')
        
def validate_sign():
    print(request.headers.get('signature'))
    print('Tezos signed message '+session.get("nonce"))
    print(key.Key.from_encoded_key("edpkvZWUhJmApw88fjonoCQoJqgywwXgK3Qv7ncZkM9Q4HDR4KPm8w").verify(request.headers.get('signature'), 'Tezos signed message '+session.get("nonce")))

    return("ok"),200
if __name__ == '__main__':
    IP = extract_ip()
    init_app(app,red)
    app.run( host = IP, port=3000, debug =True)


