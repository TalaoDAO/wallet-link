
from jwcrypto import jwk, jwt
import json
import logging
import uuid
from datetime import datetime
from random import randint
from urllib.parse import quote
from utils import oidc4vc_crypto as oidc4vc
import requests
from flask import (Response, jsonify, request, current_app)
from utils import x509_attestation

logging.basicConfig(level=logging.INFO)

API_LIFE = 300
URI_LIFE = 100
ACCESS_TOKEN_LIFE = 300
GRANT_LIFE = 300
C_NONCE_LIFE = 300
ACCEPTANCE_TOKEN_LIFE = 28 * 24 * 60 * 60
STATUSLIST_ISSUER_KEY = json.dumps(json.load(open('keys.json', 'r'))['talao_Ed25519_private_key'])

def init_app(app):
    
    
    # Credential issuer
    app.add_url_rule('/crypto4eudiw/issuer/.well-known/openid-credential-issuer', view_func=credential_issuer_openid_configuration_endpoint, methods=['GET'])
    app.add_url_rule('/.well-known/openid-credential-issuer/crypto4eudiw/issuer', view_func=credential_issuer_openid_configuration_endpoint, methods=['GET'])
    
    app.add_url_rule('/crypto4eudiw/issuer/credential', view_func=issuer_credential, methods=['POST'])
    app.add_url_rule('/crypto4eudiw/issuer/credential_offer_uri/<id>', view_func=issuer_credential_offer_uri, methods=['GET'])
    app.add_url_rule('/crypto4eudiw/issuer/nonce', view_func=issuer_nonce, methods=['POST'])
    
    # AS endpoint when issuer = AS
    app.add_url_rule('/crypto4eudiw/issuer/.well-known/oauth-authorization-server', view_func=oauth_authorization_server, methods=['GET'])
    app.add_url_rule('/.well-known/oauth-authorization-server/crypto4eudiw/issuer', view_func=oauth_authorization_server, methods=['GET'])
    app.add_url_rule('/crypto4eudiw/issuer/.well-known/openid-configuration', view_func=oauth_authorization_server, methods=['GET'])
    app.add_url_rule('/crypto4eudiw/issuer/token', view_func=issuer_token, methods=['POST'])
    app.add_url_rule("/crypto4eudiw/issuer/jwks", view_func=issuer_jwks, methods=["GET"])

    # external API
    app.add_url_rule('/crypto4eudiw/get_credential_offer', view_func=get_credential_offer, methods=['POST'])

    
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


def build_signed_metadata(metadata, mode) -> str:
    with open('keys.json', 'r') as f:
        keys = json.load(f)
    key = keys['issuer_key']
    signer_key = jwk.JWK(**key) 
    alg = oidc4vc.alg(key)
    header = {
        'typ': "openidvci-issuer-metadata+jwt",
        'alg': alg,
    }
    header['x5c'] = x509_attestation.build_x509_san_dns()
    
    payload = {
        'sub':  mode.server + 'crypto4eudiw/issuer',
        'iss': mode.server + "crypto4eudiw/issuer",
        'iat': int(datetime.now().timestamp()),
        'exp': int(datetime.now().timestamp()) + 86400,
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
    accept = request.headers.get("Accept","").lower()
    wants_jwt = "application/jwt" in accept
    if wants_jwt:
        headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/jwt'}
        signed_metadata = build_signed_metadata(metadata, mode)
        return Response(response=signed_metadata, headers=headers)
    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    return Response(response=json.dumps(metadata), headers=headers)


# jwk_uri endpoint
def issuer_jwks():
    with open('keys.json', 'r') as f:
        keys = json.load(f)
    jwk_pub = dict(keys["issuer_key"])
    for k in ("d","p","q","dp","dq","qi","oth"):
        jwk_pub.pop(k, None)
    jwks = {"keys": [jwk_pub]}
    headers = {
            "Content-Type": "application/json",
            "Cache-Control": "public, max-age=3600"
    }
    return Response(response=json.dumps(jwks), status=200, headers=headers)


# Credential issuer metadata
def credential_issuer_openid_configuration(mode):
    """
    provide data for endpoint /.well-known/openid-credential-issuer
    """
    # general section
    configuration = {
        'credential_issuer': mode.server + 'crypto4eudiw/issuer',
        'credential_endpoint': mode.server + 'crypto4eudiw/issuer/credential',
        'nonce_endpoint': mode.server + 'crypto4eudiw/issuer/nonce',
        "display": [
            {
                "name": "Talao issuer",
                "locale": "en-US",
                "logo": {
                    "uri": "https://talao.co/static/img/talao.png",
                    "alt_text": "Talao logo"
                }
            },
            {
                "name": "Talao issuer",
                "locale": "fr-FR",
                "logo": {
                    "uri": "https://talao.co/static/img/talao.png",
                    "alt_text": "Talao logo"
                }
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
    authorization_server_metadata = build_authorization_server_configuration(mode)
    print(json.dumps(authorization_server_metadata, indent=4))
    return Response(response=json.dumps(authorization_server_metadata), headers=headers, status=200)    


# authorization server configuration 
def build_authorization_server_configuration(mode):
    try:
        with open('authorization_server_config.json', "r", encoding="utf-8") as f:
            authorization_server_config = json.load(f)
    except Exception:
        logging.exception("Invalid credential configurations JSON")
        authorization_server_config = {}
    config = {
        'issuer': mode.server + 'crypto4eudiw/issuer',
        'token_endpoint': mode.server + 'crypto4eudiw/issuer/token',
        'jwks_uri':  mode.server + 'crypto4eudiw/issuer/jwks',
        'pre-authorized_grant_anonymous_access_supported': True
    }
    config.update(authorization_server_config)
    return config


# build credential offer
def build_credential_offer(data, pre_authorized_code, mode):
    offer = {
        'credential_issuer': f'{mode.server}crypto4eudiw/issuer',
        'credential_configuration_ids': [data.get("credential_id")],
        'grants': {
            'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
                'pre-authorized_code': pre_authorized_code
            }
        }
    }
    tx_code = data.get("tx_code") or {}
    if tx_code.get("is_required"):
        offer['grants'][
            'urn:ietf:params:oauth:grant-type:pre-authorized_code'
        ].update({
            'tx_code': {
                'length': tx_code.get("length", 5),
                'input_mode': tx_code.get("input_mode", "numeric"),
                'description': tx_code.get("description", "Enter secret code")
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
        offer = json.loads(red.get(id).decode())
    except Exception:
        logging.warning('session expired')
        return jsonify('Session expired'), 404
    return jsonify(offer), 201


# Main API endpoint to provide the credential offer
def get_credential_offer():
    mode = current_app.config["MODE"]
    red = current_app.config["REDIS"]
    data = request.get_json(silent=True) or {}
    webhook = data.get("webhook_url")
    exp = data.get("exp")
    
    if not isinstance(data, dict):
        return jsonify({
            "error": "invalid_request",
            "error_description": "Missing or invalid 'data' object"
        }), 400
        
    logging.info("API data received = %s", data)
    pre_authorized_code = str(uuid.uuid1())    
    offer = build_credential_offer(data, pre_authorized_code, mode)
    code_data = {
        "exp": int(datetime.now().timestamp()) + API_LIFE,
        "offer": offer,
        "data": data
    }
    # for request uri endpoint
    uri_id = str(uuid.uuid1()) 
    credential_offer_uri = f'{mode.server}crypto4eudiw/issuer/credential_offer_uri/{uri_id}'
    red.setex(uri_id, URI_LIFE, json.dumps(offer))
    
    # for token endpoint
    red.setex(pre_authorized_code, GRANT_LIFE, json.dumps(code_data))
    
    # push to webhook
    if webhook:
        headers = {
            "Content-Type": "application/json",
            "X-API-KEY": data.get("webhook_X-API-KEY"),
        }
        try:
            requests.post(
                webhook,
                json={
                    "session_id": data.get("session_id"),
                    "event": "CREDENTIAL_OFFER_SENT",
                },
                headers=headers,
                timeout=10,
            )
        except requests.RequestException:
            logging.exception("Webhook notification failed for session_id=%s", data.get("session_id"))

    
    # endpoint response
    encoded_uri = quote(credential_offer_uri, safe='')
    url_to_display = f"openid-credential-offer://?credential_offer_uri={encoded_uri}"
    return jsonify({
        "url": url_to_display,
        "credential_offer_uri": credential_offer_uri,
        "pre_authorized_code_expires_in": GRANT_LIFE,
    }), 200


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
    tx_code = data.get("tx_code") 
    if tx_code.get("is_required") and not user_pin:
        return Response(**manage_error('invalid_request', 'User code is missing'))
    logging.info('user_pin required = %s', tx_code.get("value"))
    if tx_code.get("is_required") and tx_code.get("value") not in [user_pin, str(user_pin)]:
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
        'vc': data.get('vc'),
        'webhook': data.get('webhook_url'),
        'webhook_X-API-KEY': data.get('webhook_X-API-KEY'),
        'session_id': data.get('session_id'),
        'issuer_state': data.get('issuer_state'),
        'client_id': request.form.get('client_id'),
        #'scope': request.form.get('scope') # not used
    }
    logging.info('token endpoint response = %s', json.dumps(endpoint_response, indent=4))
    red.setex(access_token, ACCESS_TOKEN_LIFE, json.dumps(access_token_data))
    if webhook := data.get('webhook_url'):
        headers = {
            "Content-Type": "application/json",
            "X-API-KEY": access_token_data.get("webhook_X-API-KEY"),
        }
        data = {
            "session_id": data.get("session_id"),
            "event": "TOKEN_SENT",
        }
        requests.post(webhook, json=data, headers=headers, timeout=10)
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
    # OIDC4VCI Final 1.0 only
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
                
                # nonce check
                nonce = proof_payload.get("nonce")
                if not nonce:
                    return Response(**manage_error('invalid_proof', 'c_nonce is missing', status=403))
                if not nonce_exist(nonce):
                    return Response(**manage_error('invalid_proof', 'c_nonce is expired or unknown', status=403))
                
                # Proof validation
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
            # send event to webhook if it exists    
            if webhook := access_token_data.get('webhook'):
                headers = {
                    "Content-Type": "application/json",
                    "X-API-KEY": access_token_data.get("webhook_X-API-KEY")
                }
                data = {
                    "session_id": access_token_data.get("session_id"),
                    "event": "ISSUANCE_ERROR",
                }
                requests.post(webhook, json=data, headers=headers, timeout=10)
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
        # send event to webhook if it exists    
        if webhook := access_token_data.get('webhook'):
            headers = {
                "Content-Type": "application/json",
                "X-API-KEY": access_token_data.get("webhook_X-API-KEY")
            }
            data = {
                "session_id": access_token_data.get("session_id"),
                "event": "ISSUANCE_ERROR",
            }
            requests.post(webhook, json=data, headers=headers, timeout=10)
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

    # send event to webhook if exists
    if webhook := access_token_data.get('webhook'):
        headers = {
            "Content-Type": "application/json",
            "X-API-KEY": access_token_data.get("webhook_X-API-KEY"),
        }
        data = {
            "session_id": access_token_data.get("session_id"),
            "event": "CREDENTIAL_SENT",
        }
        requests.post(webhook, json=data, headers=headers, timeout=10)

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
