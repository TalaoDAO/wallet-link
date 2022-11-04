from pytezos.crypto import key
import pytezos
private_key = 'edsk3nM41ygNfSxVU4w1uAW3G9EnTQEB5rjojeZedLTGmiGRcierVv'
print(key.Key.from_encoded_key(private_key).public_key())
print(key.Key.from_encoded_key(private_key).sign('test'))
public_key = 'edpku976gpuAD2bXyx1XGraeKuCo1gUZ3LAJcHM12W1ecxZwoiu22R'
signature = 'edsigtzLBGCyadERX1QsYHKpwnxSxEYQeGLnJGsSkHEsyY8vB5GcNdnvzUZDdFevJK7YZQ2ujwVjvQZn62ahCEcy74AwtbA8HuN'
"""edsigtsT7ZSGLbqqxTstecrYvxHNJTXcYRgpZXoPZS5GBVadGTJER2HEWPjUJCSwLbsQBJ4zG4hW5Nxy4a2WxBimxnRkMMTVRxf"""
print(key.Key.from_encoded_key(public_key).verify(signature, 'test'))
#pk = key.Key.from_encoded_key('edpkvFujbm3Xiamfxceg4GbsUBHzvqLZQmZvddg7xcFFvFQBEjeHTp').verify('miaou','ee')
"""private_key = 'edsk3nM41ygNfSxVU4w1uAW3G9EnTQEB5rjojeZedLTGmiGRcierVv'
key.Key(private_key).sign('test')"""
print(pytezos.crypto.encoding.base58_decode('ddfd09c32a0780578e9dbc734c2dbb7ab14c11fef606d18d885eab1477621918'))