
from web3 import Web3
from eth_account.messages import encode_defunct
from flask import Flask, render_template, request, jsonify, redirect, session, Response, send_file
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
import requests
import message
from random import randint


logging.getLogger().setLevel(logging.INFO)
# file logger
my_logger = logging.getLogger("experimentation")
file_handler = logging.FileHandler('issuer.log')
# file_handler = TimedRotatingFileHandler('issuer.log', when='D', interval=1)
my_logger.addHandler(file_handler)


logging.basicConfig(level=logging.INFO)
ISSUER_KEY = json.dumps(json.load(open("keys.json", "r"))[
                        'talao_Ed25519_private_key'])
ISSUER_VM = "did:web:app.altme.io:issuer#key-1"
ISSUER_DID = "did:web:app.altme.io:issuer"
w3 = Web3(Web3.HTTPProvider("https://mainnet.infura.io/v3/" +
          json.dumps(json.load(open("keys.json", "r"))["infuraApiKey"])))
app = Flask(__name__, static_folder=os.path.abspath(
    '/home/achille/altme-identity/static'))
QRcode(app)
app.secret_key = json.dumps(json.load(open("keys.json", "r"))["appSecretKey"])
Mobility(app)
characters = string.digits
url = "https://talao.co/sandbox/ebsi/issuer/api/dghevjfkzk"
client_secret =  json.dumps(json.load(open("keys.json", "r"))["client_secret"])
# init environnement variable
myenv = os.getenv('MYENV')
if not myenv:
    myenv = 'achille'
mode = environment.currentMode(myenv)
red = redis.Redis(host='127.0.0.1', port=6379, db=0)


def char2Bytes(text):
    return text.encode('utf-8').hex()


def create_payload(input, type):
    formattedInput = ' '.join([
        'Tezos Signed Message:',
        'altme.io',
        datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        input
    ])
    sep = '05' if type == 'MICHELINE' else '03'
    bytes = char2Bytes(formattedInput)
    return sep + '01' + '00' + char2Bytes(str(len(bytes))) + bytes


activeLinks = ["""
                    <a href="/altme-identity?blockchain=tezos">
                    <p class="activeNav" id="tezos">Tezos</p></a>
                  """,
               """
                    <a href="/altme-identity?blockchain=ethereum">
                      <p class="activeNav" id="ethereum">Ethereum</p>
                    </a>
                  """,
               """
                    <a href="/altme-identity?blockchain=fantom">
                    <p class="activeNav" id="fantom">Fantom</p></a>
                  """,
               """
                    <a href="/altme-identity?blockchain=polygon">
                      <p class="activeNav" id="polygon">Polygon</p>
                    </a>
                  """,
               """
                    <a href="/altme-identity?blockchain=bnb">
                      <p class="activeNav" id="bnb">BNB Chain</p>
                    </a>
                  """]
inactiveLinks = ["""
                    <p class="inactiveNav" id="tezos">Tezos</p>
                  """,
                 """
                    
                      <p class="inactiveNav" id="ethereum">Ethereum</p>
                    
                  """,
                 """
                    <p class="inactiveNav" id="fantom">Fantom</p>
                  """,
                 """
                    
                      <p class="inactiveNav" id="polygon">Polygon</p>
                    
                  """,
                 """
                      <p class="inactiveNav" id="bnb">BNB Chain</p>
                    
                  """]


def navBarMaker(blockchain):
    navbar = ""

    for i in range(0, 5):
        if i == blockchain:
            navbar = navbar+inactiveLinks[i]
        else:
            navbar = navbar+activeLinks[i]
    return navbar


def init_app(app, red):
    app.add_url_rule('/altme-identity',  view_func=dapp_wallet,
                     methods=['GET', 'POST'], defaults={'red': red})
    app.add_url_rule('/altme-identity/validate_sign',
                     view_func=validate_sign, methods=['GET'])
    # credential issuer routes
    app.add_url_rule('/altme-identity/qrcode',  view_func=wallet_link_qrcode,
                     methods=['GET', 'POST'], defaults={'mode': mode})
    app.add_url_rule('/altme-identity/endpoint/<id>',  view_func=wallet_link_endpoint,
                     methods=['GET', 'POST'], defaults={'red': red})
    app.add_url_rule('/altme-identity/stream',  view_func=wallet_link_stream,
                     methods=['GET', 'POST'], defaults={'red': red})
    app.add_url_rule('/altme-identity/oidc',  view_func=dapp_wallet_oidc,
                     methods=['GET', 'POST'], defaults={'red': red})
    app.add_url_rule('/altme-identity/validate_sign_oidc',
                     view_func=validate_sign_oidc, methods=['GET'])
    app.add_url_rule('/altme-identity/post_oidc',  view_func=post_oidc,
                     methods=['POST'], defaults={'red': red})
    app.add_url_rule('/altme-identity/success_oidc',  view_func=success_oidc,
                     methods=['get'])
    return

@app.errorhandler(500)
def error_500(e):
    message.message("Error 500 wallet-link",'support@talao.io', str(e))
    return redirect(mode.server)



def dapp_wallet(red):
    if request.method == 'GET':
        if not request.args.__contains__('blockchain'):
            blockchain = "tezos"
        else:
            blockchain = request.args['blockchain']
        session['is_connected'] = True
        nonce = ''.join(random.choice(characters) for i in range(6))
        session["nonce"] = "Verify address owning for Altme : " + nonce
        session['blockchain'] = blockchain
        session['cryptoWalletPayload'] = session['nonce']

        """if(blockchain=="ethereum"):
            return render_template('demo.html',nonce= session['nonce'],link=mode.server+"altme-identity/validate_sign",navbar=navBarMaker(1))
        if(blockchain=="fantom"):
            return render_template('demo.html',nonce= session['nonce'],link=mode.server+"altme-identity/validate_sign",navbar=navBarMaker(2))
        if(blockchain=="polygon"):
            return render_template('demo.html',nonce= session['nonce'],link=mode.server+"altme-identity/validate_sign",navbar=navBarMaker(3))
        """
        if (blockchain == "bnb"):
            return render_template('demo.html', nonce=session['nonce'], link=mode.server+"altme-identity/validate_sign", navbar=activeLinks[0]+inactiveLinks[4])
        if (blockchain == "tezos"):
            session['cryptoWalletPayload'] = create_payload(
                session['nonce'], 'MICHELINE')
            if not request.MOBILE:
                return render_template('dapp.html', nonce=session['cryptoWalletPayload'], link=mode.server+"altme-identity/validate_sign",
                                       navbar=inactiveLinks[0]+activeLinks[4]
                                       )
            else:
                return render_template('dappMOBILE.html', nonce=session['cryptoWalletPayload'], link=mode.server+"altme-identity/validate_sign",
                                       navbar=inactiveLinks[0]+activeLinks[4]
                                       )
    else:
        if not session.get('is_connected'):
            return jsonify('Unauthorized'), 403
        id = str(uuid.uuid1())
        red.setex(id, 180, json.dumps({"associatedAddress": session["addressVerified"],
                                       "accountName": request.headers["wallet"],
                                       "cryptoWalletPayload": str(session['nonce']),
                                       "cryptoWalletSignature": request.headers["cryptoWalletSignature"],
                                       "blockchain": session.get('blockchain')
                                       }))
        logging.info({"associatedAddress": session["addressVerified"],
                      "accountName": request.headers["wallet"],
                      "cryptoWalletPayload": str(session['nonce']),
                      "cryptoWalletSignature": request.headers["cryptoWalletSignature"],
                      "blockchain": session.get('blockchain')
                      })
        data = {"url": mode.server+'altme-identity/qrcode' + "?id=" + id}
        return json.dumps(data)


def dapp_wallet_oidc(red):
    if request.method == 'GET':
        if not request.args.__contains__('blockchain'):
            blockchain = "tezos"
        else:
            blockchain = request.args['blockchain']
        session['is_connected'] = True

        session['blockchain'] = blockchain

        if (blockchain == "ethereum"):
            return render_template('demo_oidc.html',  link=mode.server+"altme-identity/validate_sign", navbar=inactiveLinks[1], server=mode.server)
        """
        if(blockchain=="fantom"):
            return render_template('demo.html',link=mode.server+"altme-identity/validate_sign",navbar=navBarMaker(2))
        if(blockchain=="polygon"):
            return render_template('demo.html',link=mode.server+"altme-identity/validate_sign",navbar=navBarMaker(3))
        """
        if (blockchain == "bnb"):
            return render_template('demo_oidc.html',  link=mode.server+"altme-identity/validate_sign", navbar=activeLinks[0]+inactiveLinks[4])
        if (blockchain == "tezos"):
            session['cryptoWalletPayload'] = create_payload(
                session['nonce'], 'MICHELINE')
            if not request.MOBILE:
                return render_template('dapp.html',  link=mode.server+"altme-identity/validate_sign",
                                       navbar=inactiveLinks[0]+activeLinks[4]
                                       )
            else:
                return render_template('dappMOBILE.html', link=mode.server+"altme-identity/validate_sign",
                                       navbar=inactiveLinks[0]+activeLinks[4]
                                       )


def post_oidc(red):
    email = request.headers["email"]
    nonce = ''.join(random.choice(characters) for i in range(6))
    session["nonce"] = "Verify address owning for Altme : " + nonce
    session["code_pin"] = nonce
    logging.info("code pin %s", str(nonce))
    subject = ' Altme secret code'
    message.messageHTML(subject, email, 'code_auth_en', {'code': str(nonce)})
    print(session.get("nonce"))
    data = {"status": "ok", "nonce": session.get("nonce")}
    return json.dumps(data)


def validate_sign_oidc():
    blockchain = session.get('blockchain')
    if (blockchain in ["ethereum", "fantom", "bnb", "polygon"]):
        try:
            print(session.get('nonce'))
            message_hash = encode_defunct(text=session.get('nonce'))
            print(message_hash)
            print(request.headers.get('signature'))
            address = w3.eth.account.recover_message(
                message_hash, signature=request.headers.get('signature'))
            session["addressVerified"] = address
            print("address verified "+address)
            credential = None
            if blockchain == "tezos":
                credential = json.load(
                    open('./credentials/TezosAssociatedAddress.jsonld', 'r'))
            if blockchain == "ethereum":
                credential = json.load(
                    open('./credentials/EthereumAssociatedAddress.jsonld', 'r'))
            if blockchain == "fantom":
                credential = json.load(
                    open('./credentials/FantomAssociatedAddress.jsonld', 'r'))
            if blockchain == "polygon":
                credential = json.load(
                    open('./credentials/PolygonAssociatedAddress.jsonld', 'r'))
            if blockchain == "bnb":
                credential = json.load(
                    open('./credentials/BinanceAssociatedAddress.jsonld', 'r'))
            credential["issuer"] = ISSUER_DID
            credential['issuanceDate'] = datetime.utcnow().replace(
                microsecond=0).isoformat() + "Z"
            credential['expirationDate'] = (
                datetime.now() + timedelta(days=365)).isoformat() + "Z"
            credential["credentialSubject"]["associatedAddress"] = session["addressVerified"]
            headers = {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer '+client_secret
            }
            data = {
                "vc": {"EthereumAssociatedAddress": credential},
                "issuer_state": "code",
                "credential_type": ["EthereumAssociatedAddress"],
                "pre-authorized_code": True,
                "user_pin_required": True,
                "user_pin": str(session.get("code_pin")),
                "callback": mode.server+"altme-identity/success_oidc"
            }
            resp = requests.post(url, headers=headers, data=json.dumps(data))
            logging.info(resp.json())
            return ({'status': 'ok', 'uri': resp.json()["redirect_uri"]}), 200
        except ValueError:
            pass
            return ({'status': 'error'}), 403
    if (session.get('blockchain') == "tezos"):
        try:
            logging.info(key.Key.from_encoded_key(request.headers.get('pubKey')).verify(
                request.headers.get('signature'), session.get('cryptoWalletPayload')))
            logging.info("address verified : " + key.Key.from_encoded_key(
                request.headers.get('pubKey')).public_key_hash())
            if (key.Key.from_encoded_key(request.headers.get('pubKey')).public_key_hash() != request.headers.get('address')):
                return redirect(mode.server+'altme-identity/error', 403)
            session["addressVerified"] = key.Key.from_encoded_key(
                request.headers.get('pubKey')).public_key_hash()
            return ({'status': 'ok'}), 200
        except ValueError:
            pass
            return redirect(mode.server+'altme-identity/error', 403)

# route '/altme-identity/qrcode'


def success_oidc():
    return render_template("success.html")


def wallet_link_qrcode(mode):
    if not session['is_connected']:
        return jsonify('Unauthorized'), 403
    id = request.args['id']
    url = mode.server+'altme-identity/endpoint/' + id
    return json.dumps({"url": url, "id": id})


# route '/altme-identity/endpoint/
async def wallet_link_endpoint(id, red):
    try:
        data = json.loads(red.get(id).decode())
    except:
        logging.error('redis id is expired or deleted')
        # followup function call through js
        data = json.dumps({"id": id,
                           'message': 'Server error'})
        red.publish('altme-identity', data)
        return jsonify('server error'), 500  # sent to wallet
    blockchain = data['blockchain']
    address = data["associatedAddress"]
    credential = None
    if blockchain == "tezos":
        credential = json.load(
            open('./credentials/TezosAssociatedAddress.jsonld', 'r'))
    if blockchain == "ethereum":
        credential = json.load(
            open('./credentials/EthereumAssociatedAddress.jsonld', 'r'))
    if blockchain == "fantom":
        credential = json.load(
            open('./credentials/FantomAssociatedAddress.jsonld', 'r'))
    if blockchain == "polygon":
        credential = json.load(
            open('./credentials/PolygonAssociatedAddress.jsonld', 'r'))
    if blockchain == "bnb":
        credential = json.load(
            open('./credentials/BinanceAssociatedAddress.jsonld', 'r'))
    credential["issuer"] = ISSUER_DID
    credential['issuanceDate'] = datetime.utcnow().replace(
        microsecond=0).isoformat() + "Z"
    credential['expirationDate'] = (
        datetime.now() + timedelta(days=365)).isoformat() + "Z"
    credential["credentialSubject"]["associatedAddress"] = address
    if request.method == 'GET':
        credential_manifest = None
        if blockchain == "tezos":
            credential_manifest = json.load(open(
                './credentials_manifests/TezosAssociatedAddress_credential_manifest.json', 'r'))
        if blockchain == "ethereum":
            credential_manifest = json.load(open(
                './credentials_manifests/EthereumAssociatedAddress_credential_manifest.json', 'r'))
        if blockchain == "fantom":
            credential_manifest = json.load(open(
                './credentials_manifests/FantomAssociatedAddress_credential_manifest.json', 'r'))
        if blockchain == "bnb":
            credential_manifest = json.load(open(
                './credentials_manifests/BinanceAssociatedAddress_credential_manifest.json', 'r'))
        if blockchain == "polygon":
            credential_manifest = json.load(open(
                './credentials_manifests/PolygonAssociatedAddress_credential_manifest.json', 'r'))
        credential_manifest['id'] = str(uuid.uuid1())
        # credential_manifest['evidence']['id'] = str(uuid.uuid1())
        credential_manifest['issuer']['id'] = ISSUER_DID
        credential_manifest['output_descriptors'][0]['id'] = str(uuid.uuid1())
        credential['id'] = "urn:uuid:random"  # for preview
        credential_offer = {
            "type": "CredentialOffer",
            "credentialPreview": credential,
            "expires": (datetime.now() + timedelta(seconds=180)).replace(microsecond=0).isoformat(),
            "credential_manifest": credential_manifest
        }
        return jsonify(credential_offer)

    else:  # POST
        credential['id'] = "urn:uuid:" + str(uuid.uuid1())
        # for preview
        credential['credentialSubject']['id'] = request.form['subject_id']
        credential['evidence'][0]['id'] = "https://github.com/TalaoDAO/context#evidence"

        """try :
            presentation = json.loads(request.form['presentation']) 
        except :
            logging.warning("presentation does not exist")
            return jsonify('Unauthorized'), 401
        if request.form['subject_id'] != presentation['holder'] :
            logging.warning("holder does not match subject")
            return jsonify('Unauthorized'), 401"""
        # presentation_result = await didkit.verify_presentation(request.form['presentation'], '{}')
        """if json.loads(presentation_result)['errors'] :
            logging.warning("presentation failed  %s", presentation_result)
            return jsonify('Unauthorized'), 401"""
        # logging.info(presentation_result)
        credential['evidence'][0]['cryptoWalletSignature'] = data['cryptoWalletSignature']
        credential['evidence'][0]['cryptoWalletPayload'] = data['cryptoWalletPayload']
        credential['credentialSubject']['associatedAddress'] = data['associatedAddress']
        credential['credentialSubject']['accountName'] = data['accountName']
        credential['credentialSubject']['issuedBy']['name'] = 'Altme'
        logging.info('credential = %s', credential)
        # credential signature
        didkit_options = {
            "proofPurpose": "assertionMethod",
            "verificationMethod": ISSUER_VM
        }
        signed_credential = await didkit.issue_credential(json.dumps(credential), didkit_options.__str__().replace("'", '"'), ISSUER_KEY)
        # followup function call through js
        data = json.dumps({"id": id,
                           'message': 'Ok credential transfered'})
        red.publish('altme-identity', data)
        red.delete(id)
        # cerdential sent to wallet
        if blockchain == "tezos":
            data = {"vc": "tezosassociatedaddress", "count": "1"}
        if blockchain == "ethereum":
            data = {"vc": "ethereumassociatedaddress", "count": "1"}
        if blockchain == "fantom":
            data = {"vc":  "fantomassociatedaddress", "count": "1"}
        if blockchain == "polygon":
            data = {"vc": "polygonassociatedaddress", "count": "1"}
        if blockchain == "bnb":
            data = {"vc": "binanceassociatedaddress", "count": "1"}
        # requests.post('https://issuer.talao.co/counter/update', data=data)
        return jsonify(signed_credential)


# server event push for user agent EventSource
def wallet_link_stream(red):
    def event_stream(red):
        pubsub = red.pubsub()
        pubsub.subscribe('altme-identity')
        for message in pubsub.listen():
            if message['type'] == 'message':
                yield 'data: %s\n\n' % message['data'].decode()
    headers = {"Content-Type": "text/event-stream",
               "Cache-Control": "no-cache",
               "X-Accel-Buffering": "no"}
    return Response(event_stream(red), headers=headers)


def validate_sign():
    if (session.get('blockchain') in ["ethereum", "fantom", "bnb", "polygon"]):
        try:
            print(session.get('nonce'))
            message_hash = encode_defunct(text=session.get('nonce'))
            print(message_hash)
            print(request.headers.get('signature'))
            address = w3.eth.account.recover_message(
                message_hash, signature=request.headers.get('signature'))
            session["addressVerified"] = address
            print("address verified "+address)
            return ({'status': 'ok'}), 200
        except ValueError:
            pass
            return ({'status': 'error'}), 403
    if (session.get('blockchain') == "tezos"):
        try:
            logging.info(key.Key.from_encoded_key(request.headers.get('pubKey')).verify(
                request.headers.get('signature'), session.get('cryptoWalletPayload')))
            logging.info("address verified : " + key.Key.from_encoded_key(
                request.headers.get('pubKey')).public_key_hash())
            if (key.Key.from_encoded_key(request.headers.get('pubKey')).public_key_hash() != request.headers.get('address')):
                return redirect(mode.server+'altme-identity/error', 403)
            session["addressVerified"] = key.Key.from_encoded_key(
                request.headers.get('pubKey')).public_key_hash()
            return ({'status': 'ok'}), 200
        except ValueError:
            pass
            return redirect(mode.server+'altme-identity/error', 403)


@app.route('/altme-identity/error', methods=['GET'])
def error():
    logging.info(error)
    return render_template("error.html")


@app.route('/altme-identity/static/img/<filename>', methods=['GET'])
def serve_img(filename):
    return send_file('./static/img/'+filename, download_name=filename)


@app.route('/altme-identity/static/<filename>', methods=['GET'])
def serve_static(filename):
    return send_file('./static/'+filename, download_name=filename)


@app.route('/test', methods=['GET'])
def test():
    return render_template("issuer_qrcode.html",url="https://altme.io")


init_app(app, red)


if __name__ == '__main__':
    logging.info("app init")

    app.run(host=mode.IP, port=mode.port, debug=True)
