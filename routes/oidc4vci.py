
from jwcrypto import jwk, jwt
import json
import logging
import uuid
from datetime import datetime
from random import randint
from urllib.parse import urlparse, quote
from utils import oidc4vc_crypto as oidc4vc
import requests
from flask import (Response, jsonify, request, current_app)
from utils import x509_attestation

logging.basicConfig(level=logging.INFO)

API_LIFE = 5000
ACCESS_TOKEN_LIFE = 10000
GRANT_LIFE = 5000
C_NONCE_LIFE = 5000
ACCEPTANCE_TOKEN_LIFE = 28 * 24 * 60 * 60
STATUSLIST_ISSUER_KEY = json.dumps(json.load(open('keys.json', 'r'))['talao_Ed25519_private_key'])

def init_app(app):
    
    
    # Credential issuer
    app.add_url_rule('/tezos4eudiw/issuer/.well-known/openid-credential-issuer', view_func=credential_issuer_openid_configuration_endpoint, methods=['GET'])
    app.add_url_rule('/.well-known/openid-credential-issuer/tezos4eudiw/issuer', view_func=credential_issuer_openid_configuration_endpoint, methods=['GET'])
    
    app.add_url_rule('/tezos4eudiw/issuer/credential', view_func=issuer_credential, methods=['POST'])
    app.add_url_rule('/tezos4eudiw/issuer/credential_offer_uri/<id>', view_func=issuer_credential_offer_uri, methods=['GET'])
    app.add_url_rule('/tezos4eudiw/issuer/nonce', view_func=issuer_nonce, methods=['POST'])
    
    # AS endpoint when issuer = AS
    app.add_url_rule('/tezos4eudiw/issuer/.well-known/oauth-authorization-server', view_func=oauth_authorization_server, methods=['GET'])
    app.add_url_rule('/.well-known/oauth-authorization-server/tezos4eudiw/issuer', view_func=oauth_authorization_server, methods=['GET'])
    app.add_url_rule('/tezos4eudiw/issuer/.well-known/openid-configuration', view_func=oauth_authorization_server, methods=['GET'])
    app.add_url_rule('/tezos4eudiw/issuer/token', view_func=issuer_token, methods=['POST'])

    return


def manage_error(error, error_description, status=400, webhook=None):
    """
    Return error code to wallet and front channel
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-error-response
    """
    # front channel
    if webhook:
        requests.post(webhook, json={'event': 'ERROR'}, timeout=10)

    # wallet
    payload = {
        'error': error,
        'error_description': error_description,
    }
    if error == 'invalid_proof':
        payload['c_nonce'] = str(uuid.uuid1())
        payload['c_nonce_expires_in'] = 86400
    
    logging.info('endpoint error response = %s', json.dumps(payload, indent=4))

    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    return {'response': json.dumps(payload), 'status': status, 'headers': headers}


def build_signed_metadata(key, sub, metadata) -> str:
    key = json.loads(key) if isinstance(key, str) else key
    signer_key = jwk.JWK(**key) 
    alg = oidc4vc.alg(key)
    header = {
        'typ': "openidvci-issuer-metadata+jwt",
        'alg': alg,
    }
    header['x5c'] = x509_attestation.build_x509_san_dns()
    
    payload = {
        'iss': 'https://talao.co',
        'sub': sub,
        'iat': datetime.timestamp(datetime.now())
    }
    payload |= metadata
    token = jwt.JWT(header=header, claims=payload, algs=[alg])
    token.make_signed_token(signer_key)
    return token.serialize()


# credential issuer openid configuration endpoint
def credential_issuer_openid_configuration_endpoint():
    mode = current_app.config["MODE"]
    logging.info('Call credential issuer configuration endpoint /issuer metadata : %s', request.url)
    metadata = credential_issuer_openid_configuration(mode)
    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    return Response(response=json.dumps(metadata), headers=headers)


# Credential issuer metadata
def credential_issuer_openid_configuration(mode):
    """
    provide data for endpoint /.well-known/openid-credential-issuer
    """
    # general section
    configuration = {
        'credential_issuer': mode.server + 'tezos4eudiw/issuer',
        'credential_endpoint': mode.server + 'tezos4eudiw/issuer/credential',
        'nonce_endpoint': mode.server + 'tezos4eudiw/issuer/nonce',
        'display': [
            {
                "name": "Web3 Digital Wallet"
            }
        ]
    }

    # Credential configurations supported section
    credential_configurations_filename = "credential_configuration.json"
    try:
        with open(credential_configurations_filename, "r", encoding="utf-8") as f:
            credential_configurations_supported = json.load(f)
    except Exception:
        logging.exception("Invalid credential configurations JSON: %s", credential_configurations_filename)
        credential_configurations_supported = {}

    configuration.update(
        {
            "credential_configurations_supported":  credential_configurations_supported
        }
    )
    return configuration


# /.well-known/oauth-authorization-server endpoint
def oauth_authorization_server():
    mode = current_app.config["MODE"]
    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    logging.info('Call to oauth-authorization-server endpoint')
    return Response(response=json.dumps(as_openid_configuration(mode)), headers=headers)    


# authorization server configuration 
def as_openid_configuration(mode):
    try:
        with open('authorization_server_config.json', "r", encoding="utf-8") as f:
            authorization_server_config = json.load(f)
    except Exception:
        logging.exception("Invalid credential configurations JSON: %s", credential_configurations_filename)
        authorization_server_config = {}
    config = {
        'issuer': mode.server + 'tezos4eudiw/issuer',
        'token_endpoint': mode.server + 'tezos4eudiw/issuer/token',
        'jwks_uri':  mode.server + 'tezos4eudiw/issuer/jwks',
        'pre-authorized_grant_anonymous_access_supported': True
    }
    config.update(authorization_server_config)
    return config


def thumbprint(key):
    if isinstance(key, str):
        key = json.loads(key)
    signer_key = jwk.JWK(**key)
    return signer_key.thumbprint()


# build credential offer
def build_credential_offer(pre_authorized_code, mode):
    is_test = True
    offer = {
        'credential_issuer': f'{mode.server}tezos4eudiw/issuer',
        'credential_configuration_ids': ["SCA"],
        'grants': {
            'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
                'pre-authorized_code': pre_authorized_code
            }
        }
    }
    if not is_test:
        offer['grants'][
            'urn:ietf:params:oauth:grant-type:pre-authorized_code'
        ].update({
            'tx_code': {
                'length': 6,
                'input_mode': "numeric",
                'description': "Enter your secret code"
            }
        })   
    return offer


def issuer_credential_offer_uri(id):
    """
    credential_offer_uri endpoint
    return 201
    """
    red = current_app.config["REDIS"]
    try:
        offer = json.loads(red.get(id).decode()).get("offer")
    except Exception:
        logging.warning('session expired')
        return jsonify('Session expired'), 404
    return jsonify(offer), 201


# Main API to provide the credential offer
def get_credential_offer(data, red, mode):
    pre_authorized_code = str(uuid.uuid1())
    offer = build_credential_offer(pre_authorized_code, mode)
    offer_data = {
        "offer": offer,
        "data": data
    }
    id = str(uuid.uuid1())
    offer_data["data"]["stream_id"] = id
    
    credential_offer_uri = f'{mode.server}tezos4eudiw/issuer/credential_offer_uri/{id}'
    red.setex(id, GRANT_LIFE, json.dumps(offer_data))
    red.setex(pre_authorized_code, GRANT_LIFE, json.dumps(offer_data))
    encoded_uri = quote(credential_offer_uri, safe='')
    url_to_display = f"openid-credential-offer://?credential_offer_uri={encoded_uri}"
    return jsonify({'qrcode_value': url_to_display, "id": id})


# AS nonce endpoint
def issuer_nonce():
    red = current_app.config["REDIS"]
    nonce = str(uuid.uuid1())
    logging.info('Call of the nonce endpoint, nonce = %s', nonce)
    endpoint_response = {'c_nonce': nonce}
    red.setex(nonce, 60,'nonce')
    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    return Response(response=json.dumps(endpoint_response), headers=headers)


# AS token endpoint
def issuer_token():
    red = current_app.config["REDIS"]
    logging.info('token endoint header %s', request.headers)
    logging.info('token endoint form %s', json.dumps(request.form, indent=4))
    
    # display DPoP
    if request.headers.get('DPoP'):
        try:
            DPoP_header = oidc4vc.get_header_from_token(request.headers.get('DPoP'))
            DPoP_payload = oidc4vc.get_payload_from_token(request.headers.get('DPoP'))
            logging.info('DPoP header = %s', json.dumps(DPoP_header, indent=4))
            logging.info('DPoP payload = %s', json.dumps(DPoP_payload, indent=4))
        except Exception as e:
            return Response(**manage_error('invalid_request', 'DPoP is incorrect ' + str(e)))
    else:
        logging.info('No DPoP')
    
    # check grant type
    grant_type = request.form.get('grant_type')
    if not grant_type:
        return Response(**manage_error('invalid_request', 'Request format is incorrect, grant is missing' ))

    if grant_type == 'urn:ietf:params:oauth:grant-type:pre-authorized_code' and not request.form.get('pre-authorized_code'):
        return Response(**manage_error('invalid_request', 'Request format is incorrect, this grant type is not supported' ))

    if grant_type == 'urn:ietf:params:oauth:grant-type:pre-authorized_code':
        code = request.form.get('pre-authorized_code')
        user_pin = request.form.get('tx_code')
    else:
        return Response(**manage_error('invalid_request', 'Grant type not supported'))
    
    if not code and grant_type != 'client_credentials':
        return Response(**manage_error('invalid_request', 'Request format is incorrect, code is missing'))
    
    logging.info("cient_id = %s", request.form.get("client_id"))

    # display client_authentication method
    if request.headers.get('Oauth-Client-Attestation'):
        client_authentication_method = 'client_attestation'
    elif request.headers.get('Authorization'):
        client_authentication_method = 'client_secret_basic'
    elif request.form.get('client_id') and request.form.get('client_secret'):
        client_authentication_method = 'client_secret_post'
    elif request.form.get('client_id'):
        client_authentication_method = 'client_id'
    else:
        client_authentication_method = 'none'
    logging.info('client authentication method = %s', client_authentication_method)
    
    # Check content of client assertion and proof of possession (PoP)
    if client_authentication_method == 'client_attestation':
        try:
            # https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-04.html
            client_assertion = request.headers['Oauth-Client-Attestation']
            PoP = request.headers['Oauth-Client-Attestation-Pop']
            logging.info('OAuth-Client-Attestation = %s', client_assertion)
            logging.info('OAuth-Client-Attestation-PoP = %s', PoP)
            if request.form.get('client_id') != oidc4vc.get_payload_from_token(client_assertion).get('sub'):
                #return Response(**manage_error('invalid_request', 'client_id does not match client assertion subject'))
                logging.warning('client_id does not match client assertion subject')
            if oidc4vc.get_payload_from_token(client_assertion).get('sub') != oidc4vc.get_payload_from_token(PoP).get('iss'):
                #return Response(**manage_error('invalid_request', 'sub of client assertion does not match proof of possession iss'))
                logging.warning('sub of client assertion does not match proof of possession iss')
        except Exception:
            return Response(**manage_error('invalid_request', 'Header is not correct for client attestation'))

    # check code validity
    try:
        offer_data = json.loads(red.get(code).decode())
        data = offer_data.get("data")
    except Exception:
        return Response(**manage_error('access_denied', 'Grant code expired', status=404))

    # check tx_code
    if data.get('user_pin_required') and not user_pin:
        return Response(**manage_error('invalid_request', 'User code is missing'))
    logging.info('user_pin = %s', data.get('user_pin'))
    if data.get('user_pin_required') and data.get('user_pin') not in [user_pin, str(user_pin)]:
        return Response(**manage_error('invalid_grant', 'User code is incorrect', status=404))

    # token endpoint response
    access_token = str(uuid.uuid1())
    refresh_token = str(uuid.uuid1())
    vc = data.get('vc')
    endpoint_response = {
        'access_token': access_token,
        'token_type': 'bearer',
        'expires_in': ACCESS_TOKEN_LIFE,
        'refresh_token': refresh_token
    }

    access_token_data = {
        'expires_at': datetime.timestamp(datetime.now()) + ACCESS_TOKEN_LIFE,
        #'credential_type': data.get('credential_type'),
        'vc': data.get('vc'),
        'webhook': data.get('webhook'),
        'stream_id': data.get('stream_id'),
        'issuer_state': data.get('issuer_state'),
        'client_id': request.form.get('client_id'),
        #'scope': request.form.get('scope') # not used
    }
    logging.info('token endpoint response = %s', json.dumps(endpoint_response, indent=4))
    red.setex(access_token, ACCESS_TOKEN_LIFE, json.dumps(access_token_data))
    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    return Response(response=json.dumps(endpoint_response), headers=headers)


# Issuer credential endpoint
def issuer_credential():
    logging.info('credential endoint header %s', request.headers)
    logging.info('credential endpoint request %s', json.dumps(request.json, indent=4))
    red = current_app.config["REDIS"]
    mode = current_app.config["MODE"]
    # DPoP
    if request.headers.get('DPoP'):
        try:
            DPoP_header = oidc4vc.get_header_from_token(request.headers.get('DPoP'))
            DPoP_payload = oidc4vc.get_payload_from_token(request.headers.get('DPoP'))
            logging.info('DPoP header = %s', json.dumps(DPoP_header, indent=4))
            logging.info('DPoP payload = %s', json.dumps(DPoP_payload, indent=4))
        except Exception as e:
            return Response(**manage_error('invalid_request', 'DPoP is incorrect ' + str(e)))
    else:
        logging.info('No DPoP')
        
    # Check access token
    try:
        access_token = request.headers['Authorization'].split()[1]
    except Exception:
        return Response(**manage_error('invalid_token', 'Access token not passed in request header'))
    try:
        access_token_data = json.loads(red.get(access_token).decode())
    except Exception:
        return Response(**manage_error('invalid_token', 'Access token expired'))

    # Get wallet public key
    try:
        result = request.json
    except Exception:
        return Response(**manage_error('invalid_request', 'Invalid request format'))
    #credential_configuration_id = result.get('credential_configuration_id')
    
    def nonce_exist(nonce):
        logging.info("nonce exists ?  %s", bool(red.get(nonce)))
        return bool(red.get(nonce))  
    
    wallet_jwk = []
    if result.get('proofs'):
        if jwt_proof := result["proofs"].get("jwt"):
            if isinstance(jwt_proof, str):
                jwt_proof = [jwt_proof]
            nb_proof = len(jwt_proof)
            logging.info("proof number = %s", nb_proof)
            i = 0 
            for proof in jwt_proof:
                proof_header = oidc4vc.get_header_from_token(proof)
                proof_payload = oidc4vc.get_payload_from_token(proof)
                logging.info('Proof header = %s', json.dumps(proof_header, indent=2))
                logging.info('Proof payload = %s', json.dumps(proof_payload, indent=2))
                if not proof_payload.get('nonce') and nonce_exist(proof_payload.get('nonce')):
                    return Response(**manage_error('invalid_proof', 'c_nonce is missing', status=403))
                try:
                    oidc4vc.verif_token(proof)
                    logging.info('proof %s is validated', str(i))
                except ValueError as e:
                    logging.error("Proof verification failed: %s", str(e))
                    return Response(**manage_error('invalid_proof', 'Proof of key ownership, signature verification error: ' + str(e), status=403))
                if proof_header.get('jwk'):
                    wallet_jwk.append(proof_header.get('jwk'))
                else:
                    return Response(**manage_error('invalid_proof', 'jwk does not exist in the proof of ownership', status=403))

                if access_token_data['client_id'] and proof_payload.get("iss"):
                    if proof_payload.get("iss") != access_token_data['client_id']:
                        logging.error('iss %s of proof of key is different from client_id %s', proof_payload.get("iss") ,access_token_data['client_id'] )
                        return Response(**manage_error('invalid_proof', 'iss of proof of key is different from client_id'))
        else:
            return Response(**manage_error('invalid_proof', 'Proof type not supported'))
    else:
        nb_proof = 1
        logging.warning('No proof available -> Bearer credential')
        wallet_jwk = [None]
        
    logging.info('wallet_jwk = %s', wallet_jwk)
    # get credential to issue
    credential_configuration_id = result.get("credential_configuration_id")
    credential = access_token_data['vc'].get(credential_configuration_id)
    if not credential:
        return Response(**manage_error('unsupported_credential_type', 'Credential is not found for this credential identifier'))

    # sign_credential(credential, wallet_did, c_nonce, format, issuer, mode, duration=365, wallet_jwk=None, wallet_identifier=None):
    credential_signed = []
    for i in range(nb_proof):
        c_s = sign_credential(credential, wallet_jwk[i], mode)
        logging.info('credential signed #%s sent to wallet = %s', i, c_s)
        if not c_s:
            return Response(**manage_error('internal_error', 'Credential signing error'))
        credential_signed.append(c_s)
    
    # Transfer VC
    c_nonce = str(uuid.uuid1())
    payload = {"credentials": []}
    for i in range(nb_proof):
        payload["credentials"].append({
            "credential": credential_signed[i]
        })

    # update nonce in access token for next VC request
    access_token_data['c_nonce'] = c_nonce
    red.setex(access_token, ACCESS_TOKEN_LIFE, json.dumps(access_token_data))

    # send event to webhook if it exists    
    if webhook := access_token_data.get('webhook'):
        data = {
                'event': 'CREDENTIAL_SENT',
        }
        requests.post(webhook, json=data, timeout=10)
        
    # Notify front-end (SSE via Redis pubsub)
    stream_id = access_token_data.get("stream_id")
    if stream_id:
        red.publish(
            "tezos4eudiw",
            json.dumps({"id": stream_id, "event": "CREDENTIAL_ISSUED"})
        )

    # send VC to wallet
    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    return Response(response=json.dumps(payload), headers=headers)


def sign_credential(credential, wallet_jwk, mode):
    duration = 3*30*24*60*60
    credential['status'] = {
        'status_list': {
            'idx': randint(0, 99999),
            'uri': mode.server + 'issuer/statuslist/1'
        }
    }
    return oidc4vc.sign_sd_jwt(credential, wallet_jwk, duration)
