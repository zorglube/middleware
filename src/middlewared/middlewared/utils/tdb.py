import json
from middlewared.service_exception import MatchNotFound, CallError
from middlewared.utils import filter_list
from subprocess import run


class TDBWrap(object):
    def __init__(self, dbid, **kwargs):
        self.dbid = dbid

    def get(self, key):
        """
        Get value associated with string `key`.
        If entry does not exist, then None type returned,
        otherwise string is returned.
        """
        cmd = ['ctdb', 'pfetch', self.dbid, key]
        tdb_get = run(cmd, capture_output=True)
        if tdb_get.returncode != 0:
            raise CallError(f"{key}: failed to fetch: {tdb_get.stderr.decode()}")
            return None

        tdb_val = tdb_get.stdout.decode().strip()
        if not tdb_val:
            return None

        return tdb_val

    def set(self, key, val):
        """
        Set key to value, creating if necessary.
        `key` and `val` are both strings.
        """
        tdb_set = run(['ctdb', 'pstore', self.dbid, key, val], capture_output=True)
        if tdb_set.returncode != 0:
            raise CallError(f"{key}: failed to set to {val}: {tdb_set.stderr.decode()}")

        return

    def remove(self, key):
        """
        remove a single entry from tdb file.
        """
        tdb_del = run(['ctdb', 'pdelete', self.dbid, key], capture_output=True)
        if tdb_del.returncode != 0:
            raise CallError(f"{key}: failed to delete: {tdb_del.stderr.decode()}")
            return None

        return

    def traverse(self, fn, private_data):
        ok = True
        trv = run(['ctdb', 'catdb_json', self.dbid], capture_output=True)
        if trv.returncode != 0:
            raise CallError(f"{self.dbid}: failed to traverse: {trv.stderr.decode()}")

        tdb_entries = json.loads(trv.stdout.decode())
        for i in tdb_entries['data'][1:]:
            ok = fn(i['key'], i['val'], private_data)
            if not ok:
                break

        return ok

    def wipe(self):
        w = run(['ctdb', 'wipedb', self.dbid], capture_output=True)
        if w.returncode != 0:
            raise CallError(f"{self.dbid}: failed to w: {w.stderr.decode()}")

        return

    def service_version(self):
        v = self.get("service_version")
        if v is None:
            return None

        with open("/tmp/service.out", "w") as f:
            f.write(f"XXX: {v}")

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

        return hwm + 1

    def update(self, id, payload):
        tdb_key = f'{self.schema}_{id}'
        vers = payload['version']
        new = payload['data']

        self.version_check(vers)

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

        return

    def delete(self, id):
        tdb_key = f'{self.schema}_{id}'

        entries = self.get(self.schema)
        entries = [] if entries is None else entries.split()
        if tdb_key not in entries:
            raise MatchNotFound()

        self.remove(tdb_key)
        entries.remove(tdb_key)
        self.set(self.schema, ' '.join(entries))

        return
