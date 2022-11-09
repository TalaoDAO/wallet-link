from pytezos.crypto import key
import pytezos
public_key = 'edpkvZWUhJmApw88fjonoCQoJqgywwXgK3Qv7ncZkM9Q4HDR4KPm8w'
print(key.Key.from_encoded_key("edpkvZWUhJmApw88fjonoCQoJqgywwXgK3Qv7ncZkM9Q4HDR4KPm8w").public_key_hash())

signature = 'edsigtzLBGCyadERX1QsYHKpwnxSxEYQeGLnJGsSkHEsyY8vB5GcNdnvzUZDdFevJK7YZQ2ujwVjvQZn62ahCEcy74AwtbA8HuN'
"""edsigtsT7ZSGLbqqxTstecrYvxHNJTXcYRgpZXoPZS5GBVadGTJER2HEWPjUJCSwLbsQBJ4zG4hW5Nxy4a2WxBimxnRkMMTVRxf"""
#print(key.Key.from_encoded_key(public_key).verify(signature, 'test'))
#pk = key.Key.from_encoded_key('edpkvFujbm3Xiamfxceg4GbsUBHzvqLZQmZvddg7xcFFvFQBEjeHTp').verify('miaou','ee')
"""private_key = 'edsk3nM41ygNfSxVU4w1uAW3G9EnTQEB5rjojeZedLTGmiGRcierVv'
key.Key(private_key).sign('test')"""
