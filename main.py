
from web3 import Web3
from hexbytes import HexBytes
from eth_account.messages import encode_defunct,defunct_hash_message
import hashlib
from flask import Flask,render_template, request, jsonify, redirect,session, Response
from flask_mobility import Mobility
import uuid 
from flask_qrcode import QRcode
import json
import redis
import string
import random
import os
import environment
from datetime import datetime, timedelta
import didkit
from pytezos.crypto import key
import logging
logging.basicConfig(level=logging.INFO)
issuer_key = json.dumps(json.load(open("keys.json", "r"))['talao_Ed25519_private_key'])
issuer_did = "did:tz:tz1NyjrTUNxDpPaqNZ84ipGELAcTWYg6s5Du"
issuer_vm = "did:tz:tz1NyjrTUNxDpPaqNZ84ipGELAcTWYg6s5Du#blockchainAccountId"
w3 = Web3(Web3.HTTPProvider("https://mainnet.infura.io/v3/f2be8a3bf04d4a528eb416566f7b5ad6"))

"""mesage= encode_defunct(text="6875972781")

address = w3.eth.account.recover_message(mesage,signature=HexBytes("0xe277c9ce2fc17d3c6903410a7886cb87f18a064e7fc3e2f1e23df223b01b48371d5a5b37b6f217e0b5431a0a158023a0ee2184a422f68a82ce4b57d5d71252511c"))
"""

def create_payload (input, type) :
  formattedInput = ' '.join([
    'Tezos Signed Message:',
    'altme.io',
    datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
    input
  ])
  sep = '05' if type == 'MICHELINE'  else  '03'
  bytes = char2Bytes(formattedInput)
  return  sep + '01' + '00' + char2Bytes(str(len(bytes)))  + bytes
    


app = Flask(__name__)
QRcode(app)
app.secret_key ='miaou'

Mobility(app)

characters = string.digits


#init environnement variable
myenv = os.getenv('MYENV')
if not myenv :
   myenv='thierry'
mode = environment.currentMode(myenv)

red= redis.Redis(host='127.0.0.1', port=6379, db=0)
def char2Bytes(text):
    return text.encode('utf-8').hex()


def init_app(app,red) :
    app.add_url_rule('/wallet-link',  view_func=dapp_wallet, methods = ['GET', 'POST'], defaults={'red' : red})
    app.add_url_rule('/wallet-link/validate_sign' , view_func=validate_sign,methods=['GET'])

    # credential issuer routes
    app.add_url_rule('/wallet-link/qrcode',  view_func=wallet_link_qrcode, methods = ['GET', 'POST'], defaults={'mode' : mode})
    app.add_url_rule('/wallet-link/endpoint/<id>',  view_func=wallet_link_endpoint, methods = ['GET', 'POST'], defaults={'red' : red})
    app.add_url_rule('/wallet-link/stream',  view_func=wallet_link_stream, methods = ['GET', 'POST'], defaults={'red' : red})
    app.add_url_rule('/wallet-link/followup',  view_func=wallet_link_followup, methods = ['GET'])
    return

def dapp_wallet(red):
    logging.info("dapp_wallet")
    if request.method == 'GET' :
        session['is_connected'] = True
        nonce = ''.join(random.choice(characters) for i in range(6))
        session["nonce"] = "Verify address owning for Altme : " + nonce
        logging.info("nonce " +session.get('nonce'))
        """if(request.args['blockchain']=="ethereum"):
            session['cryptoWalletPayload'] = encode_defunct(text=session['nonce'])
            session['blockchain']="eth"     
            if(request.MOBILE==False):
                return render_template('demo.html',nonce= session['nonce'],link="https://192.168.1.17:3000/wallet-link/validate_sign")
            else:
                return render_template('demoMOBILE.html',nonce= session['nonce'],link="https://192.168.1.17:3000/wallet-link/validate_sign")"""
        #if(request.args['blockchain']=="tezos"):

            #session['blockchain']="tez"
        logging.info(session.get('blockchain'))
        session['cryptoWalletPayload'] = create_payload(session['nonce'],'MICHELINE')
        if(request.MOBILE==False):
            return render_template('dapp.html',nonce= session['cryptoWalletPayload'],link=mode.server+"wallet-link/validate_sign")
        else:
            return render_template('dappMOBILE.html',nonce= session['cryptoWalletPayload'],link=mode.server+"wallet-link/validate_sign")

            
    else :
        if not session['is_connected'] :
            return jsonify('Unauthorized'), 403
        id = str(uuid.uuid1())
        logging.info("address verified "+session["addressVerified"])
        red.setex(id, 180, json.dumps({"associatedAddress" : session["addressVerified"],
                                        "accountName" : request.headers["wallet"],
                                        "cryptoWalletPayload" : str(session['cryptoWalletPayload']),
                                        "cryptoWalletSignature" : request.headers["cryptoWalletSignature"]
                                }))        
        return redirect (mode.server+'wallet-link/qrcode' + "?id=" + id)


# route '/wallet-link/qrcode'
def wallet_link_qrcode(mode) :
    if not session['is_connected'] :
        return jsonify('Unauthorized'), 403
    id = request.args['id']
    url =mode.server+'wallet-link/endpoint/' + id 
    logging.info('qr code = %s', url)
    return render_template('qrcode.html', url=url, id=id)


# route '/wallet-link/endpoint/
async def wallet_link_endpoint(id, red):
    credential=None
    
    credential = json.load(open('TezosAssociatedAddress.jsonld', 'r'))
    
    credential["issuer"] = issuer_did 
    credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    credential['expirationDate'] =  (datetime.now() + timedelta(days= 365)).isoformat() + "Z"
    
    if request.method == 'GET': 
        
        credential_manifest = json.load(open('TezosAssociatedAddress_credential_manifest.json', 'r'))
        
        credential_manifest['id'] = str(uuid.uuid1())
        credential_manifest['issuer']['id'] = issuer_did
        credential_manifest['output_descriptors'][0]['id'] = str(uuid.uuid1())    
        credential['id'] = "urn:uuid:random" # for preview
        credential['credentialSubject']['id'] = "did:wallet" # for preview
        credential_offer = {
            "type": "CredentialOffer",
            "credentialPreview": credential,
            "expires" : (datetime.now() + timedelta(seconds = 180)).replace(microsecond=0).isoformat(),
            "credential_manifest" : credential_manifest
        }
        return jsonify(credential_offer)

    else :  #POST
        credential['id'] = "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = request.form['subject_id']
        try :
            data = json.loads(red.get(id).decode())
        except :
            logging.error('redis id is expired or deleted')
            # followup function call through js
            data = json.dumps({"id" : id,
                         'message' : 'Server error'})
            red.publish('wallet-link', data)
            return jsonify('server error'), 500 # sent to wallet
        credential['credentialSubject']['cryptoWalletSignature'] = data['cryptoWalletSignature']
        credential['credentialSubject']['cryptoWalletPayload'] = data['cryptoWalletPayload']
        credential['credentialSubject']['associatedAddress'] = data['associatedAddress']
        credential['credentialSubject']['accountName'] = data['accountName']
        credential['credentialSubject']['issuedBy']['name'] = 'Altme'
        logging.info('credential = %s', credential)

        # credential signature 
        didkit_options = {
            "proofPurpose": "assertionMethod",
            "verificationMethod": issuer_vm
            }
        signed_credential =  await didkit.issue_credential(
                json.dumps(credential),
                didkit_options.__str__().replace("'", '"'),
                issuer_key)
        # followup function call through js
        data = json.dumps({"id" : id,
                         'message' : 'Ok credential transfered'})
        red.publish('wallet-link', data)
        red.delete(id)
        # cerdential sent to wallet
        return jsonify(signed_credential)


# followup function
def wallet_link_followup():
    if not session['is_connected'] :
        return jsonify('Unauthorized'), 403
    # a voir si utile ???
    #print(request.args.get('message', 'No message'))
    return render_template("validation.html")
    return jsonify (request.args.get('message', 'No message'))


# server event push for user agent EventSource
def wallet_link_stream(red):
    def event_stream(red):
        pubsub = red.pubsub()
        pubsub.subscribe('wallet-link')
        for message in pubsub.listen():
            if message['type']=='message':
                yield 'data: %s\n\n' % message['data'].decode()  
    headers = { "Content-Type" : "text/event-stream",
                "Cache-Control" : "no-cache",
                "X-Accel-Buffering" : "no"}
    return Response(event_stream(red), headers=headers)
        


def validate_sign():
    #print("validateSign")
    #print(request.headers.get('signature'))
    #print('Tezos signed message '+session.get("nonce"))
    #print("nonce "+session.get('nonce'))
    #print("payload "+str(encode_defunct(text=session.get('nonce'))))
    #print(session.get('cryptoWalletPayload'))
    #print('signature '+request.headers.get('signature'))
    if(session.get('blockchain')=="eth"):
        try:
            #print("verifying ethereum")
            message_hash = defunct_hash_message(text=session.get('nonce'))
            address = w3.eth.account.recoverHash(message_hash, signature=request.headers.get('signature'))
            #print(address)
            session["addressVerified"]=address
            #print("address verified "+session["addressVerified"])

            
            return({'status':'ok'}),200
        except ValueError:
            pass
            return({'status':'error'}),403
    if(session.get('blockchain')=="tez"):
        try:
            #print("verifying tezos")
            #print(key.Key.from_encoded_key(request.headers.get('pubKey')).verify(request.headers.get('signature'), 
            #session.get('cryptoWalletPayload')))
            #print("verified :" +key.Key.from_encoded_key(request.headers.get('pubKey')).public_key_hash())
            session["addressVerified"]=key.Key.from_encoded_key(request.headers.get('pubKey')).public_key_hash()
            return({'status':'ok'}),200
        except ValueError:
            pass
            return({'status':'error'}),403
@app.route('/')
def index():
    return render_template("demo.html",nonce=session.get("nonce"))

if __name__ == '__main__':
    logging.info("app init")
    #print(mode.IP)
    #print(mode.port)
    #app.run( host = mode.IP, port= mode.port, debug =True,ssl_context='adhoc')
    app.run( host = mode.IP, port= mode.port, debug =True)
    """,ssl_context='adhoc'"""
init_app(app,red)

logging.info("testLogging")