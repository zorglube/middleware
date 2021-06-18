import tdb
import json
from middlewared.service_exception import MatchNotFound
from middlewared.utils import filter_list


class TDBWrap(object):
    def __init__(self, path, **kwargs):
        self.path = path
        self.flags = kwargs.get('flags', 0)
        self.tdb = None
        self.is_open = False

    def open_tdb(self):
        self.tdb = tdb.open(self.path, self.flags)
        self.is_open = True

    def get(self, key):
        """
        Get value associated with string `key`.
        If entry does not exist, then None type returned,
        otherwise string is returned.
        """
        tdb_key = key.encode()
        tdb_val = self.tdb.get(tdb_key)
        return tdb_val.decode() if tdb_val else None

    def set(self, key, val):
        """
        Set key to value, creating if necessary.
        `key` and `val` are both strings.
        """
        tdb_key = key.encode()
        tdb_val = val.encode()
        self.tdb.store(tdb_key, tdb_val)
        return

    def remove(self, key):
        """
        remove a single entry from tdb file.
        """
        tdb_key = key.encode()
        self.tdb.delete(tdb_key)

    def traverse(self, fn, private_data):
        ok = True
        for i in self.tdb.keys():
            tdb_key = i.decode()
            tdb_val = self.get(tdb_key)
            ok = fn(tdb_key, tdb_val, private_data)
            if not ok:
                break

        return ok

    def wipe(self):
        """
        Remove all entries with associated schema.
        If schema is None, then entire file contents
        are removed.
        """
        if self.schema is None:
            self.tdb.clear()
            return

        for tdb_key in self.keys():
            key = tdb_key.decode()
            if key.startswith(self.schema):
                self.tdb.remove(tdb_key)

        return

    def service_version(self):
        v = self.get("service_version")
        if v is None:
            return None

        maj, min = v.split(".")
        return {"major": int(maj), "minor": int(min)}

    def version_check(self, new):
        local_version = self.service_version()
        if local_version is None:
            self.set("service_version", f'{new["major"]}.{new["minor"]}')
            return

        if new == local_version:
            return

        raise ValueError

    def __enter__(self):
        self.open_tdb()
        return self

    def __exit__(self, typ, value, traceback):
        if self.is_open:
            self.tdb.close()


class TDBWrapConfig(TDBWrap):
    schema = None

    def __init__(self, path, schema, **kwargs):
        super().__init__(path, **kwargs)
        self.schema = schema

    def config(self):
        vers = self.service_version()
        tdb_val = self.get(self.schema)
        output = json.loads(tdb_val) if tdb_val else None
        return {"version": vers, "data": output}

    def update(self, payload):
        vers = payload['version']
        data = payload['data']

        self.version_check(vers)

        tdb_val = json.dumps(data)
        self.set(self.schema, tdb_val)


class TDBWrapCRUD(TDBWrap):
    schema = None

    def __init__(self, path, schema, **kwargs):
        super().__init__(path, **kwargs)
        self.schema = schema

    def query(self, filters=None, options=None):
        output = []
        if filters is None:
            filters = []

        if options is None:
            options = {}

        vers = self.service_version()
        entries = self.get(self.schema)
        entries = [] if entries is None else entries.split()
        for tdb_key in entries:
            prefix_len = len(self.schema) + 1
            data = {"id": int(tdb_key[prefix_len:])}
            tdb_val = self.get(tdb_key)
            data.update(json.loads(tdb_val))
            output.append(data)

        res = filter_list(output, filters, options)
        return {"version": vers, "data": res}

    def create(self, payload):
        vers = payload['version']
        data = payload['data']

        self.version_check(vers)

        self.tdb.transaction_start()
        try:
            hwm = 0
            entries = self.get(self.schema)
            entries = [] if entries is None else entries.split()

            for i in entries:
                prefix_len = len(self.schema) + 1
                id = int(i[prefix_len:])
                if id > hwm:
                    hwm = id

            tdb_key = f'{self.schema}_{hwm + 1}'
            self.set(tdb_key, json.dumps(data))
            entries.append(tdb_key)
            with open("/tmp/tdb.log", "w") as f:
                f.write(f'HMW: {hwm}, TDB_KEY: {tdb_key}, entries: {entries}')
            self.set(self.schema, ' '.join(entries))

        except Exception as e:
            self.tdb.transaction_cancel()
            raise e

        self.tdb.transaction_commit()
        return hwm + 1

    def update(self, id, payload):
        tdb_key = f'{self.schema}_{id}'
        vers = payload['version']
        new = payload['data']

        self.version_check(vers)

        self.tdb.transaction_start()
        try:
            entries = self.get(self.schema)
            entries = [] if entries is None else entries.split()
            if tdb_key not in entries:
                raise MatchNotFound()

            old = json.loads(self.get(tdb_key))
            old.update(new)
            tdb_val = json.dumps(old)
            self.set(tdb_key, tdb_val)
            entries.append(tdb_key)
            self.set(self.schema, ' '.join(entries))

        except Exception as e:
            self.tdb.transaction_cancel()
            raise e

        self.tdb.transaction_commit()
        return

    def delete(self, id):
        tdb_key = f'{self.schema}_{id}'

        self.tdb.transaction_start()
        try:
            entries = self.get(self.schema)
            entries = [] if entries is None else entries.split()
            if tdb_key not in entries:
                raise MatchNotFound()

            self.remove(tdb_key)
            entries.remove(tdb_key)
            self.set(self.schema, ' '.join(entries))

        except Exception as e:
            self.tdb.transaction_cancel()
            raise e

        self.tdb.transaction_commit()
        return
