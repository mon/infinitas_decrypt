import os
import errno

from Crypto.Cipher import AES
from ifstools import IFS, GenericFile, GenericFolder
from kbinxml import KBinXML
from tqdm import tqdm

enc_base = r'D:\infinitas\KONAMI\eacloud\beatmania IIDX INFINITAS'
dec_base = r'D:\infinitas\beatmania IIDX INFINITAS (Decrypted game files)'

# monkeypatching
class CryptFile(GenericFile):
    def _load_from_ifs(self, convert_kbin = True):
        data = self.ifs_data.get(self.start, self.size)
        data = decrypt(self.name + 'r', data)
        return data

def main():
    for subdir in ['launcher','updater','game']:
        enc_path = os.path.join(enc_base, subdir)
        dec_path = os.path.join(dec_base, subdir)
        mountfile = os.path.join(enc_path, 'conf', 'mounttable.binr')
        configfile = os.path.join(enc_path, 'conf', 'config.binr')

        # whatever
        with open(mountfile,'rb') as f:
            mounts = decrypt(mountfile, f.read())
        mounts = KBinXML(mounts)
        with open(configfile,'rb') as f:
            config = decrypt(configfile, f.read())
        config = KBinXML(config)

        cfg_dec = os.path.join(dec_path, 'config')
        mkdir_p(cfg_dec)
        with open(os.path.join(cfg_dec, 'config.xml'), 'w') as f:
            f.write(config.to_text())
        with open(os.path.join(cfg_dec, 'mounttable.xml'), 'w') as f:
            f.write(mounts.to_text())

        for vfs in tqdm(mounts.xml_doc):
            dst = vfs.attrib['dst']
            src = vfs.attrib['src']
            src = src.lstrip('/')
            dst = dst.lstrip('/')

            src = os.path.join(enc_path, src)
            dst = os.path.join(dec_path, dst)
            if dst[-1].isdigit():
                dst = dst[:-1]

            ifs = IFS(src)
            for f in ifs.tree.all_files:
                if f.name.endswith('r') and type(f) == GenericFile and type(f.parent) == GenericFolder:
                    f.__class__ = CryptFile
                    f.name = f.name[:-1] # strip r

            mkdir_p(dst)
            ifs.extract(use_cache = False, recurse = False, path = dst)

def decrypt(filename, data = None):
    '''filename is used for key generation and is always required'''
    salt = b'sg_TlTNF80vAUgGLafxkT3YgvKpyh_e2'
    name_xor = b'\x117\xd2sc\xe5Ov\x84\x8c)\xf1\x162Tu\xbf\xd8~\xf9#\xa1\xddy\x8c&\xf72\xf7\xe6\xe3e'
    decname = filename[:-1] # strip trailing r

    mangled = os.path.basename(decname).encode('utf8') + salt
    mangled = mangled[:32]
    key = bytes(bytearray([x^y for x, y in zip(mangled, name_xor)]))

    if data is None:
        with open(filename,'rb') as f:
            enc = f.read()
    else:
        enc = data

    iv = enc[:16]
    aes = AES.new(key, AES.MODE_CBC, iv)

    enc = enc[16:]
    extra_len = len(enc) % 16
    pad_len = 16 - extra_len
    # ciphertext stealing, bleurgh
    if extra_len:
        extra = enc[-extra_len:]
        enc = enc[:-extra_len]

        last_full = enc[-16:]
        enc = enc[:-16]

        last_full_dec = AES.new(key, AES.MODE_CBC, b'\0'*16).decrypt(last_full)
        extra += last_full_dec[-pad_len:]

        dec = aes.decrypt(enc + extra + last_full)[:-pad_len]
    else:
        dec = aes.decrypt(enc)

    if data is None:
        with open(decname,'wb') as f:
            f.write(dec)
    else:
        return dec

def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

if __name__ == '__main__':
    main()
