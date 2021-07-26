import base64
import os
import json

from Crypto.Cipher import AES
from Crypto.Util import Counter
from hashlib import sha256

from middlewared.service import Service
from middlewared.plugins.cluster_linux.utils import CTDBConfig
from middlewared.plugins.gluster_linux.utils import GlusterConfig
from middlewared.utils.tdb import TDBWrap

PWENC_BLOCK_SIZE = 32
PWENC_FILE_SECRET = os.environ.get('FREENAS_PWENC_SECRET', '/data/pwenc_secret')
PWENC_PADDING = b'{'
PWENC_CHECK = 'Donuts!'
CLUSTER_PWENC_FILE_SECRET = f'{CTDBConfig.GM_SECRETS.value}/pwenc_secret.tdb'
CLUSTER_PWENC_VERSION = {"major": 0, "minor": 1}


class PWEncService(Service):

    secret = None

    class Config:
        private = True

    def file_secret_path(self):
        return PWENC_FILE_SECRET

    def generate_secret(self, reset_passwords=True):
        secret = os.urandom(PWENC_BLOCK_SIZE)
        with open(PWENC_FILE_SECRET, 'wb') as f:
            os.chmod(PWENC_FILE_SECRET, 0o600)
            f.write(secret)
        self.reset_secret_cache()

        settings = self.middleware.call_sync('datastore.config', 'system.settings')
        self.middleware.call_sync('datastore.update', 'system.settings', settings['id'], {
            'stg_pwenc_check': self.encrypt(PWENC_CHECK),
        })

        if reset_passwords:
            for table, field in (
                ('directoryservice_activedirectory', 'ad_bindpw'),
                ('directoryservice_ldap', 'ldap_bindpw'),
                ('services_dynamicdns', 'ddns_password'),
                ('services_webdav', 'webdav_password'),
                ('services_ups', 'ups_monpwd'),
                ('system_email', 'em_pass'),
            ):
                self.middleware.call_sync('datastore.sql', f'UPDATE {table} SET {field} = \'\'')

    def check(self):
        try:
            settings = self.middleware.call_sync('datastore.config', 'system.settings')
        except IndexError:
            self.middleware.call_sync('datastore.insert', 'system.settings', {})
            settings = self.middleware.call_sync('datastore.config', 'system.settings')

        return self.decrypt(settings['stg_pwenc_check']) == PWENC_CHECK

    @classmethod
    def get_secret(cls):
        if cls.secret is None:
            with open(PWENC_FILE_SECRET, 'rb') as f:
                cls.secret = f.read()

        return cls.secret

    @classmethod
    def reset_secret_cache(cls):
        cls.secret = None

    def encrypt(self, data):
        return encrypt(data)

    def decrypt(self, encrypted, _raise=False):
        return decrypt(encrypted, _raise)


class ClusterPWEncService(PWEncService):

    secret = None

    class Config:
        private = True

    def generate_secret(self, reset_passwords=False):
        def get_hwm_cb(tdb_key, tdb_val, state):
            if not tdb_key.startswith('SECRET_'):
                return True

            current_idx = int(tdb_key[7:])
            if state['hwm'] > current_idx:
                return True

            state['hwm'] = current_idx
            return True

        with open(GlusterConfig.SECRETS_FILE.value, 'rb') as f:
            gluster_secret = f.read()

        secret = str(sha256(gluster_secret).hexdigest()[32:])
        state = {"hwm": 0}

        with TDBWrap(CLUSTER_PWENC_FILE_SECRET, flags=os.O_CREAT|os.O_RDWR) as t:
            current = t.get('CURRENT')
            if current:
                entry = json.loads(current)
                if secret == entry['secret']:
                    return

            payload = {"version": CLUSTER_PWENC_VERSION, "secret": secret}
            t.set('CURRENT', json.dumps(payload))
            t.traverse(get_hwm_cb, state)
            t.set(f'SECRET_{state["hwm"] + 1}', json.dumps(payload))

        self.reset_secret_cache()

    @classmethod
    def get_secret(cls):
        if cls.secret is None:
            with TDBWrap(CLUSTER_PWENC_FILE_SECRET) as t:
                entry = t.get('CURRENT')
                if entry is None:
                    raise KeyError('CURRENT')

                current = json.loads(entry)
                entry_version = f'{current["version"]["major"]}.{current["version"]["minor"]}'
                current_version = f'{CLUSTER_PWENC_VERSION["major"]}.{CLUSTER_PWENC_VERSION["minor"]}'
                if float(entry_version) > float(current_version):
                    raise ValueError("Cluster pwenc secret version mismatch. Update all nodes to TrueNAS release.")

                cls.secret = current['secret'].encode()

        return cls.secret

    def encrypt(self, data):
        return encrypt(data, True)

    def decrypt_search(self, encrypted):
        def decrypt_entry_cb(TDB_KEY, TDB_VAL, state):
            if not TDB_KEY.startswith('SECRET_'):
                return True

            val = json.loads(TDB_VAL)
            decrypted = decrypt(state['encrypted'], False, True, val['secret'])
            if decrypted:
                state['decrypted'] = decrypted
                return False

            return True

        state = {"encrypted": encrypted, "decrypted": ""}
        with TDBWrap(CLUSTER_PWENC_FILE_SECRET) as t:
            t.traverse(decrypt_entry_cb, state)

        return state['decrypted']

    def decrypt(self, encrypted, _raise=False):
        """
        Encryption key derived from jwt. If cached key fails,
        take slow route and walk through old keys.
        """
        try:
            decrypted = decrypt(encrypted, True, True)
        except Exception:
            decrypted = self.decrypt_search(encrypted)
            if not decrypted and _raise:
                raise

        return decrypted


async def setup(middleware):
    if not await middleware.call('pwenc.check'):
        middleware.logger.debug('Generating new pwenc secret')
        await middleware.call('pwenc.generate_secret')


def encrypt(data, cluster=False):
    data = data.encode('utf8')

    def pad(x):
        return x + (PWENC_BLOCK_SIZE - len(x) % PWENC_BLOCK_SIZE) * PWENC_PADDING

    method = PWEncService if not cluster else ClusterPWEncService
    nonce = os.urandom(8)

    cipher = AES.new(method.get_secret(), AES.MODE_CTR, counter=Counter.new(64, prefix=nonce))
    encoded = base64.b64encode(nonce + cipher.encrypt(pad(data)))
    return encoded.decode()


def decrypt(encrypted, _raise=False, cluster=False, _secret=None):
    if not encrypted:
        return ''

    method = PWEncService if not cluster else ClusterPWEncService
    try:
        encrypted = base64.b64decode(encrypted)
        nonce = encrypted[:8]
        encrypted = encrypted[8:]
        secret = _secret if _secret else method.get_secret()
        cipher = AES.new(secret, AES.MODE_CTR, counter=Counter.new(64, prefix=nonce))
        return cipher.decrypt(encrypted).rstrip(PWENC_PADDING).decode('utf8')
    except Exception:
        if _raise:
            raise
        return ''
