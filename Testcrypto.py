
from web3 import Web3
from hexbytes import HexBytes
from eth_account.messages import encode_defunct
import hashlib
w3 = Web3(Web3.HTTPProvider("https://mainnet.infura.io/v3/f2be8a3bf04d4a528eb416566f7b5ad6"))

mesage= encode_defunct(text="ewww")
print(mesage)
address = w3.eth.account.recover_message(mesage,signature=HexBytes("0xcad3f498272a63a0601ed6e01d4472a369231a26056b7455bdda462c190f15217b0a71abf91d1968eeaabffe90488c1dc07e520ddc4e1afffe17b4c6782fe3441b"))
print(address)
