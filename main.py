
from web3 import Web3
from hexbytes import HexBytes
from eth_account.messages import encode_defunct,defunct_hash_message
import hashlib
from flask import Flask,render_template, request, jsonify, redirect,session, Response,send_file
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
issuer_vm = "did:web:app.altme.io:issuer#key-1"
issuer_did = "did:web:app.altme.io:issuer"
w3 = Web3(Web3.HTTPProvider("https://mainnet.infura.io/v3/"+json.dumps(json.load(open("keys.json", "r"))["infuraApiKey"])))

app = Flask(__name__,static_folder=os.path.abspath('/home/achille/wallet-link/static'))
QRcode(app)
app.secret_key =json.dumps(json.load(open("keys.json", "r"))["appSecretKey"])

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
        
        if not request.args.__contains__('blockchain'):
            blockchain="tezos"
        else:
            blockchain=request.args['blockchain']
        if(blockchain=="ethereum"):
            session['blockchain']="ethereum"     
            logging.info(session.get('blockchain'))
            session['cryptoWalletPayload'] = encode_defunct(text=session['nonce'])
            if not request.MOBILE:
                return render_template('demo.html',nonce= session['nonce'],link=mode.server+"wallet-link/validate_sign")
            else:
                return render_template('demoMOBILE.html',nonce= session['nonce'],link=mode.server+"wallet-link/validate_sign")
        if(blockchain=="fantom"):
            session['blockchain']="fantom"     
            logging.info(session.get('blockchain'))
            session['cryptoWalletPayload'] = encode_defunct(text=session['nonce'])
            if not request.MOBILE:
                return render_template('demoFTM.html',nonce= session['nonce'],link=mode.server+"wallet-link/validate_sign")
            else:
                return render_template('demoMOBILE.html',nonce= session['nonce'],link=mode.server+"wallet-link/validate_sign")
        if(blockchain=="polygon"):
            session['blockchain']="polygon"     
            logging.info(session.get('blockchain'))
            session['cryptoWalletPayload'] = encode_defunct(text=session['nonce'])
            if not request.MOBILE:
                return render_template('demoPOL.html',nonce= session['nonce'],link=mode.server+"wallet-link/validate_sign")
            else:
                return render_template('demoMOBILE.html',nonce= session['nonce'],link=mode.server+"wallet-link/validate_sign")
        if(blockchain=="bsc"):
            session['blockchain']="bsc"     
            logging.info(session.get('blockchain'))
            session['cryptoWalletPayload'] = encode_defunct(text=session['nonce'])
            if not request.MOBILE:
                return render_template('demoBSC.html',nonce= session['nonce'],link=mode.server+"wallet-link/validate_sign")
            else:
                return render_template('demoMOBILE.html',nonce= session['nonce'],link=mode.server+"wallet-link/validate_sign")
        if(blockchain=="tezos"):
            session['blockchain']="tezos"
            logging.info(session.get('blockchain'))
            session['cryptoWalletPayload'] = create_payload(session['nonce'],'MICHELINE')
            if not request.MOBILE:
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
        return redirect (mode.server+'wallet-link/qrcode' + "?id=" + id+"&blockchain="+session.get('blockchain')+"&address="+session["addressVerified"])


# route '/wallet-link/qrcode'
def wallet_link_qrcode(mode) :
    if not session['is_connected'] :
        return jsonify('Unauthorized'), 403
    id = request.args['id']
    blockchain = request.args['blockchain']
    logging.info("blockchain")
    logging.info(blockchain)

    logging.info("blockchain")

    url =mode.server+'wallet-link/endpoint/' + id +"?blockchain="+blockchain+"&address="+request.args['address']
    logging.info('qr code = %s', url)
    return render_template('qrcode.html', url=url, id=id)


# route '/wallet-link/endpoint/
async def wallet_link_endpoint(id, red):  
    blockchain = request.args['blockchain']
    logging.info("blockchain")
    logging.info(blockchain)

    logging.info("blockchain")
    credential=None
    if blockchain=="tezos":
        credential = json.load(open('TezosAssociatedAddress.jsonld', 'r'))
    if blockchain=="ethereum":
        credential = json.load(open('EthereumAssociatedAddress.jsonld', 'r'))
    if blockchain=="fantom":
        credential = json.load(open('FantomAssociatedAddress.jsonld', 'r'))
    if blockchain=="polygon":
        credential = json.load(open('PolygonAssociatedAddress.jsonld', 'r'))
    if blockchain=="bsc":
        credential = json.load(open('BinanceAssociatedAddress.jsonld', 'r'))
    credential["issuer"] = issuer_did 
    credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    credential['expirationDate'] =  (datetime.now() + timedelta(days= 365)).isoformat() + "Z"
    credential["credentialSubject"]["associatedAddress"]=request.args['address']
    if request.method == 'GET': 
        credential_manifest=None
        if blockchain=="tezos":
            credential_manifest = json.load(open('TezosAssociatedAddress_credential_manifest.json', 'r'))
        if blockchain=="ethereum":
            credential_manifest = json.load(open('EthereumAssociatedAddress_credential_manifest.json', 'r'))
        if blockchain=="fantom":
            credential_manifest = json.load(open('FantomAssociatedAddress_credential_manifest.json', 'r')) 
        if blockchain=="bsc":
            credential_manifest = json.load(open('BinanceAssociatedAddress_credential_manifest.json', 'r')) 
        if blockchain=="polygon":
            credential_manifest = json.load(open('PolygonAssociatedAddress_credential_manifest.json', 'r')) 
        credential_manifest['id'] = str(uuid.uuid1())
        #credential_manifest['evidence']['id'] = str(uuid.uuid1())
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
        credential['evidence'][0]['id'] = request.form['subject_id']

        try :
            presentation = json.loads(request.form['presentation']) 
        except :
            logging.warning("presentation does not exist")
            return jsonify('Unauthorized'), 401
        if request.form['subject_id'] != presentation['holder'] :
            logging.warning("holder does not match subject")
            return jsonify('Unauthorized'), 401
        presentation_result = await didkit.verify_presentation(request.form['presentation'], '{}')
        if not json.loads(presentation_result)['errors'] :
            logging.warning("presentation failed  %s", presentation_result)
            return jsonify('Unauthorized'), 401
        

        try :
            data = json.loads(red.get(id).decode())
        except :
            logging.error('redis id is expired or deleted')
            # followup function call through js
            data = json.dumps({"id" : id,
                         'message' : 'Server error'})
            red.publish('wallet-link', data)
            return jsonify('server error'), 500 # sent to wallet
        credential['evidence'][0]['cryptoWalletSignature'] = data['cryptoWalletSignature']
        credential['evidence'][0]['cryptoWalletPayload'] = data['cryptoWalletPayload']
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
    return render_template("validation.html")


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
    if(session.get('blockchain')=="ethereum" or session.get('blockchain')=="fantom" or session.get('blockchain')=="bsc" or session.get('blockchain')=="polygon"):
        try:
            logging.info("verifying "+session.get('blockchain'))
            message_hash = defunct_hash_message(text=session.get('nonce'))
            print(message_hash)
            print(session.get('nonce'))
            address = w3.eth.account.recoverHash(message_hash, signature=request.headers.get('signature'))
            address2 = w3.eth.account.recoverHash(session.get('nonce'), signature=request.headers.get('signature'))
            logging.info("address verified : " +address)
            logging.info("address verified2 : " +address2)
            session["addressVerified"]=address
            return({'status':'ok'}),200
        except ValueError:
            pass
            return({'status':'error'}),403
    if(session.get('blockchain')=="tezos"):
        try:
            logging.info("verifying tezos")
            logging.info(key.Key.from_encoded_key(request.headers.get('pubKey')).verify(request.headers.get('signature'), 
            session.get('cryptoWalletPayload')))
            logging.info("address verified : " +key.Key.from_encoded_key(request.headers.get('pubKey')).public_key_hash())
            if(key.Key.from_encoded_key(request.headers.get('pubKey')).public_key_hash()!=request.headers.get('address')):
                return redirect (mode.server+'wallet-link/error',403)
            session["addressVerified"]=key.Key.from_encoded_key(request.headers.get('pubKey')).public_key_hash()
            return({'status':'ok'}),200
        except ValueError:
            pass
            return redirect (mode.server+'wallet-link/error',403)

@app.route('/wallet-link/error',methods=['GET'])
def error():
    logging.info(error)
    return render_template("error.html")

@app.route('/wallet-link/static/<filename>',methods=['GET'])
def serve_static(filename):
    logging.info(filename)
    return send_file('./static/'+filename, download_name=filename)

if __name__ == '__main__':
    logging.info("app init")
    

    app.run( host = mode.IP, port= mode.port, debug =True)

init_app(app,red)
""",ssl_context='adhoc'"""
