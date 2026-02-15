import requests
from jwcrypto import jwk, jwt
import base58  # type: ignore
import json
from datetime import datetime, timezone
import logging
import hashlib
from random import randbytes
from utils import x509_attestation
import copy
logging.basicConfig(level=logging.INFO)
import base64
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, padding
from typing import Any, Dict

"""
https://ec.europa.eu/digital-building-blocks/wikis/display/EBSIDOC/EBSI+DID+Method
VC/VP https://ec.europa.eu/digital-building-blocks/wikis/display/EBSIDOC/E-signing+and+e-sealing+Verifiable+Credentials+and+Verifiable+Presentations
DIDS method https://ec.europa.eu/digital-building-blocks/wikis/display/EBSIDOC/EBSI+DID+Method
supported signature: https://ec.europa.eu/digital-building-blocks/wikis/display/EBSIDOC/E-signing+and+e-sealing+Verifiable+Credentials+and+Verifiable+Presentations

"""



def generate_key(curve):
    """
alg value https://www.rfc-editor.org/rfc/rfc7518#page-6

+--------------+-------------------------------+--------------------+
| "alg" Param  | Digital Signature or MAC      | Implementation     |
| Value        | Algorithm                     | Requirements       |
+--------------+-------------------------------+--------------------+
| RS256        | RSASSA-PKCS1-v1_5 using       | Recommended        |
|              | SHA-256                       |                    |
| RS384        | RSASSA-PKCS1-v1_5 using       | Optional           |
|              | SHA-384                       |                    |
| RS512        | RSASSA-PKCS1-v1_5 using       | Optional           |
|              | SHA-512                       |                    |
| ES256        | ECDSA using P-256 and SHA-256 | Recommended+       |
| ES384        | ECDSA using P-384 and SHA-384 | Optional           |
| ES512        | ECDSA using P-521 and SHA-512 | Optional           |
+--------------+-------------------------------+--------------------+
    """

    if curve in ['P-256', 'P-384', 'P-521', 'secp256k1']:
        key = jwk.JWK.generate(kty='EC', crv=curve)
    elif curve == 'RSA':
        key = jwk.JWK.generate(kty='RSA', size=2048)
    else:
        raise Exception("Curve not supported")
    return json.loads(key.export(private_key=True))


def alg(key) -> str:
    """
    Return the JOSE 'alg' for a given JWK.
    Accepts:
      - dict JWK
      - JSON string containing a JWK
      - jwcrypto.jwk.JWK instance
    """
    # Normalize input type
    if hasattr(key, "export") and callable(getattr(key, "export")):
        # jwcrypto.jwk.JWK -> dict
        key_dict = key.export(as_dict=True)
    elif isinstance(key, str):
        key_dict = json.loads(key)
    elif isinstance(key, dict):
        key_dict = key
    else:
        raise TypeError(f"Unsupported key type: {type(key).__name__}")

    kty = key_dict.get("kty")
    if not kty:
        raise ValueError("Missing 'kty' in JWK")

    if kty == "EC":
        crv = key_dict.get("crv")
        if not crv:
            raise ValueError("Missing 'crv' in EC JWK")

        # Normalize common aliases without mutating input
        crv_norm = {
            "P-256K": "secp256k1",
            "secp256k1": "secp256k1",
            "P-256": "P-256",
            "P-384": "P-384",
            "P-521": "P-521",
        }.get(crv)

        if crv_norm == "secp256k1":
            return "ES256K"
        if crv_norm == "P-256":
            return "ES256"
        if crv_norm == "P-384":
            return "ES384"
        if crv_norm == "P-521":
            return "ES512"

        raise ValueError(f"Unsupported EC curve: {crv}")

    if kty == "RSA":
        return "RS256"

    if kty == "OKP":
        crv = key_dict.get("crv")
        if not crv:
            raise ValueError("Missing 'crv' in OKP JWK")
        if crv == "Ed25519":
            return "EdDSA"
        raise ValueError(f"Unsupported OKP curve for EdDSA: {crv}")

    raise ValueError(f"Unsupported JWK kty: {kty}")



def pub_key(key):
    key = json.loads(key) if isinstance(key, str) else key
    Key = jwk.JWK(**key) 
    return Key.export_public(as_dict=True)
    


def salt():
    return base64.urlsafe_b64encode(randbytes(16)).decode().replace("=", "")


def hash(text):
    m = hashlib.sha256()
    m.update(text.encode())
    return base64.urlsafe_b64encode(m.digest()).decode().replace("=", "")


def sd(data):
    unsecured = copy.deepcopy(data)
    payload = {'_sd': []}
    disclosed_claims = ['status', 'status_list', 'idx', 'uri', 'vct', 'iat', 'nbf', 'aud', 'iss', 'exp', '_sd_alg', 'cnf', 'vct#integrity']
    _disclosure = ""
    disclosure_list = unsecured.get("disclosure", [])
    for claim in [attribute for attribute in unsecured.keys()]:
        if claim == "disclosure":
            pass
        # for undisclosed attribute
        elif isinstance(unsecured[claim], (str, bool, int)) or claim in ["status", "status_list"]:
            if claim in disclosure_list or claim in disclosed_claims:
                payload[claim] = unsecured[claim]
            else:
                contents = json.dumps([salt(), claim, unsecured[claim]])
                disclosure = base64.urlsafe_b64encode(contents.encode()).decode().replace("=", "")
                if disclosure:
                    _disclosure += "~" + disclosure
                payload['_sd'].append(hash(disclosure))
        # for nested json
        elif isinstance(unsecured[claim], dict):
            if claim in disclosure_list or claim in disclosed_claims:
                payload[claim], disclosure = sd(unsecured[claim])
                if disclosure:
                    _disclosure += "~" + disclosure
            else:
                nested_content, nested_disclosure = sd(unsecured[claim])
                contents = json.dumps([salt(), claim, nested_content])
                if nested_disclosure:
                    _disclosure += "~" + nested_disclosure
                disclosure = base64.urlsafe_b64encode(contents.encode()).decode().replace("=", "")
                if disclosure:
                    _disclosure += "~" + disclosure
                payload['_sd'].append(hash(disclosure))
        # for list
        elif isinstance(unsecured[claim], list):  # list
            if claim in disclosure_list or claim in disclosed_claims:
                payload[claim] = unsecured[claim]
            else:
                nb = len(unsecured[claim])
                payload.update({claim: []})
                for index in range(0, nb):
                    if isinstance(unsecured[claim][index], dict):
                        nested_disclosure_list = unsecured[claim][index].get("disclosure", [])
                        if not nested_disclosure_list:
                            logging.warning("disclosure is missing for %s", claim)
                    else:
                        nested_disclosure_list = []
                for index in range(0, nb):
                    if isinstance(unsecured[claim][index], dict):
                        pass  # TODO
                    elif unsecured[claim][index] in nested_disclosure_list:
                        payload[claim].append(unsecured[claim][index])
                    else:
                        contents = json.dumps([salt(), unsecured[claim][index]])
                        nested_disclosure = base64.urlsafe_b64encode(contents.encode()).decode().replace("=", "")
                        if nested_disclosure:
                            _disclosure += "~" + nested_disclosure
                        payload[claim].append({"...": hash(nested_disclosure)})
        else:
            logging.warning("type not supported")
    if payload.get('_sd'):
        # add 1 fake digest
        contents = json.dumps([salt(), "decoy", "decoy"])
        disclosure = base64.urlsafe_b64encode(contents.encode()).decode().replace("=", "")
        payload['_sd'].append(hash(disclosure))
    else:
        payload.pop("_sd", None)
    _disclosure = _disclosure.replace("~~", "~")
    return payload, _disclosure


def sign_sd_jwt(unsecured, wallet_key, duration):
    
    with open('keys.json', 'r') as f:
        keys = json.load(f)
    issuer_key = keys['issuer_key']
    issuer = "https://talao.co" 

    # normalize wallet_key
    wallet_key = json.loads(wallet_key) if isinstance(wallet_key, str) else wallet_key
    wallet_key.pop('use', None)
    wallet_key.pop('alg', None)
        
    now = int(datetime.now(timezone.utc).timestamp())
    payload = {
        'iss': issuer,
        'iat': now,
        'exp': now + duration,
        "cnf": {
            "jwk": wallet_key
        }
    }
    
    # Calculate selective disclosure 
    if unsecured and "all" in unsecured.get("disclosure", []):
        unsecured_payload = unsecured
        unsecured_payload.pop("disclosure")
        disclosure = ""
    else:
        unsecured_payload, disclosure = sd(unsecured)
        payload["_sd_alg"] = "sha-256"
    
    # update payload with selective disclosure
    payload.update(unsecured_payload)
    if not payload.get("_sd"):
        logging.info("no _sd present")
        payload.pop("_sd_alg", None)
    logging.info("sd-jwt payload = %s", json.dumps(payload, indent=4))
    
    signer_key = jwk.JWK(**issuer_key)
    
    # build header
    header = { 
        "alg": alg(issuer_key),
        "typ": "dc+sd-jwt",
        "x5c": x509_attestation.build_x509_san_dns()
    }
    
    if unsecured.get('status'): 
        payload['status'] = unsecured['status']
    token = jwt.JWT(header=header, claims=payload, algs=[alg(issuer_key)])
    token.make_signed_token(signer_key)
    sd_token = token.serialize() + disclosure + "~"
    return sd_token


def base58_to_jwk(base58_key: str):
    key_bytes = base58.b58decode(base58_key)
    x_b64url = base64.urlsafe_b64encode(key_bytes).decode().rstrip("=")
    jwk = {
        "kty": "OKP",  # Type de clé pour Ed25519
        "crv": "Ed25519",
        "x": x_b64url
    }
    return jwk

def base58_to_jwk_secp256k1(base58_key: str):
    key_bytes = base58.b58decode(base58_key)
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), key_bytes)
    nums = pub.public_numbers()
    return {
        "kty": "EC",
        "crv": "secp256k1",
        "x": _b64url(nums.x.to_bytes(32, "big")),
        "y": _b64url(nums.y.to_bytes(32, "big")),
    }


def verif_token(token: str):
    header = get_header_from_token(token)
    if x5c_list := header.get('x5c'):
        try:
            cert_der = base64.b64decode(x5c_list[0])
            cert = x509.load_der_x509_certificate(cert_der)
            public_key = cert.public_key()
            issuer_key = jwk.JWK.from_pyca(public_key)
        except Exception as e:
            raise ValueError(f"Invalid x5c certificate or public key extraction failed: {e}")

    elif header.get('jwk'):
        try:
            jwk_data = header['jwk']
            if isinstance(jwk_data, str):
                jwk_data = json.loads(jwk_data)
            issuer_key = jwk.JWK(**jwk_data)
        except Exception as e:
            raise ValueError(f"Invalid 'jwk' in header: {e}")

    elif header.get('kid'):
        dict_key = resolve_did(header['kid'])
        if not dict_key or not isinstance(dict_key, dict):
            raise ValueError(f"Unable to resolve public key from kid: {header['kid']}")
        try:
            issuer_key = jwk.JWK(**dict_key)
        except Exception as e:
            raise ValueError(f"Invalid public key structure from DID: {e}")

    else:
        raise ValueError("Header missing key info: expected 'x5c', 'jwk', or 'kid'")

    try:
        parsed_jwt = jwt.JWT.from_jose_token(token)
        parsed_jwt.validate(issuer_key)
    except Exception as e:
        raise ValueError(f"JWT signature validation failed: {e}")

    return True  # if no exceptions, verification succeeded



def get_payload_from_token(token) -> dict:
    payload = token.split('.')[1]
    payload += "=" * ((4 - len(payload) % 4) % 4)  # solve the padding issue of the base64 python lib
    try:
        return json.loads(base64.urlsafe_b64decode(payload).decode())
    except Exception as e:
        raise ValueError(f"Invalid token payload: {e}")


def get_header_from_token(token):
    header = token.split('.')[0]
    header += "=" * ((4 - len(header) % 4) % 4)  # solve the padding issue of the base64 python lib
    try:
        return json.loads(base64.urlsafe_b64decode(header).decode())
    except Exception as e:
        raise ValueError(f"Invalid token header: {e}")


def thumbprint(key):
    key = json.loads(key) if isinstance(key, str) else key
    if key.get('crv') == 'P-256K':
        key['crv'] = 'secp256k1'
    signer_key = jwk.JWK(**key)
    return signer_key.thumbprint()





def load_cert_from_b64(b64_der):
    der = base64.b64decode(b64_der)
    return x509.load_der_x509_certificate(der)


def verify_signature(cert, issuer_cert):
    pubkey = issuer_cert.public_key()
    try:
        if isinstance(pubkey, rsa.RSAPublicKey):
            pubkey.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
        elif isinstance(pubkey, ec.EllipticCurvePublicKey):
            pubkey.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm)
            )
        elif isinstance(pubkey, ed25519.Ed25519PublicKey):
            pubkey.verify(
                cert.signature,
                cert.tbs_certificate_bytes
            )
        else:
            return f"Error: Unsupported public key type: {type(pubkey)}"
        return None  # success
    except InvalidSignature:
        return "Error: Signature verification failed."
    except Exception as e:
        return f"Error: Verification failed with exception: {e}"


def verify_x5c_chain(x5c_list):
    """
    Verifies a certificate chain from the x5c header field of a JWT.
    
    Checks:
      1. Each certificate is signed by the next one in the list.
      2. Each certificate is valid at the current time.
    
    Args:
        x5c_list (List[str]): List of base64-encoded DER certificates (leaf to root).
    
    Returns:
        str: Info or error message.
    """
    if not x5c_list:
        return "Error: Insufficient certificate chain."
    if len(x5c_list) == 1:
        return "Warning: Only one certificate in the x5c list."
    try:
        certs = [load_cert_from_b64(b64cert) for b64cert in x5c_list]
    except Exception as e:
        return f"Error loading certificates: {e}"

    now = datetime.now(timezone.utc)

    for i, cert in enumerate(certs):
        if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
            return (
                f"Error: Certificate {i} is not valid at current time:\n"
                f" - Not before: {cert.not_valid_before_utc}\n"
                f" - Not after : {cert.not_valid_after_utc}"
            )
        else:
            logging.info(f"Certificate {i} is within validity period.")

    for i in range(len(certs) - 1):
        cert = certs[i]
        issuer_cert = certs[i + 1]
        result = verify_signature(cert, issuer_cert)
        if result:
            return f"Error: Certificate {i} verification failed: {result}"
        else:
            logging.info(f"Certificate {i} is signed by certificate {i+1}.")

    return "Info: Certificate chain and validity periods are all OK."



def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def base64url_decode(input_str):
    padding = '=' * (4 - (len(input_str) % 4))
    return base64.urlsafe_b64decode(input_str + padding)


def decode_sd_jwt(sd_jwt_str):
    parts = sd_jwt_str.split("~")
    jwt_header_payload_signature = parts[0]
    disclosures = parts[1:-1]  # skip the last detached JWS if present

    # Decode JWT payload
    jwt_parts = jwt_header_payload_signature.split(".")
    payload_b64 = jwt_parts[1]
    payload_json = json.loads(base64url_decode(payload_b64).decode("utf-8"))

    # Print or collect disclosures
    revealed = {}
    for disclosure_b64 in disclosures:
        try:
            decoded = base64url_decode(disclosure_b64).decode("utf-8")
            disclosure = json.loads(decoded)
            salt, claim_name, claim_value = disclosure
            revealed[claim_name] = claim_value
        except Exception as e:
            print("Invalid disclosure:", disclosure_b64)
            print(e)

    return revealed

# MAIN entry point for test
if __name__ == '__main__':
    pass