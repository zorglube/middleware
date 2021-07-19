import tdb
import json
from middlewared.service_exception import MatchNotFound, CallError
from middlewared.utils import filter_list
from subprocess import run

class TDBWrap(object):
    def __init__(self, path, **kwargs):
        self.path = path
        self.flags = kwargs.get('flags', 0)
        self.handle = None
        self.is_open = False
        self.is_clustered = kwargs.get('clustered', False)

    def open_tdb(self):
        self.handle = tdb.open(self.path, self.flags)
        self.is_open = True

    def get(self, key):
        """
        Get value associated with string `key`.
        If entry does not exist, then None type returned,
        otherwise string is returned.
        """
        tdb_key = key.encode()
        tdb_val = self.handle.get(tdb_key)
        return tdb_val.decode() if tdb_val else None

    def set(self, key, val):
        tdb_key = key.encode()
        tdb_val = val.encode()
        self.handle.store(tdb_key, tdb_val)
        return

    def remove(self, key):
        tdb_key = key.encode()
        self.handle.delete(tdb_key)

    def traverse(self, fn, private_data):
        ok = True
        for i in self.handle.keys():
            tdb_key = i.decode()
            tdb_val = self.get(tdb_key)
            ok = fn(tdb_key, tdb_val, private_data)
            if not ok:
                break

        return ok

    def wipe(self):
        if self.schema is None:
            self.handle.clear()
            return

        for tdb_key in self.keys():
            key = tdb_key.decode()
            if key.startswith(self.schema):
                self.handle.remove(tdb_key)

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
        if not self.is_clustered:
            self.open_tdb()

        return self

    def __exit__(self, typ, value, traceback):
        if self.is_open:
            self.handle.close()


class CTDBWrap(TDBWrap):
    def __init__(self, dbid, **kwargs):
        super().__init__(dbid, **kwargs)
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
        with open("/tmp/traverse.out", "w") as f:
            f.write(str(tdb_entries))

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


class TDBWrapConfig(CTDBWrap):
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


class TDBWrapCRUD(CTDBWrap):
    schema = None

    def __init__(self, path, schema, **kwargs):
        super().__init__(path, **kwargs)
        self.schema = schema

    def _tdb_entries(self):
        def tdb_to_list(tdb_key, tdb_val, data):
            if tdb_key == "hwm":
                data['hwm'] = int(tdb_val)
                return True

            if not tdb_key.startswith(data['schema']):
                return True

            entry = {"id": int(tdb_key[data["prefix_len"]:])}
            tdb_json = json.loads(tdb_val)
            entry.update(tdb_json)

            data['entries'].append(entry)
            data['by_id'][entry['id']] = entry
            return True

        state = {
            "schema": self.schema,
            "prefix_len": len(self.schema) + 1,
            "hwm": 1,
            "entries": [],
            "by_id": {}
        }

        self.traverse(tdb_to_list, state)

        return state

    def query(self, filters=None, options=None):
        output = []
        if filters is None:
            filters = []

        if options is None:
            options = {}

        self._tdb_entries()
        vers = self.service_version()
        state = self._tdb_entries()

        res = filter_list(state['entries'], filters, options)
        return {"version": vers, "data": res}

    def create(self, payload):
        vers = payload['version']
        data = payload['data']

        self.version_check(vers)
        state = self._tdb_entries()

        id = state["hwm"] + 1
        tdb_key = f'{self.schema}_{id}'

        self.set(tdb_key, json.dumps(data))
        self.set("hwm", str(id))

        return id

    def update(self, id, payload):
        tdb_key = f'{self.schema}_{id}'
        vers = payload['version']
        new = payload['data']

        self.version_check(vers)
        state = self._tdb_entries()

        old = state['by_id'].get(id)
        if not old:
            raise MatchNotFound()

        old.update(new)
        old.pop('id')
        tdb_val = json.dumps(old)
        self.set(tdb_key, tdb_val)
        return

    def delete(self, id):
        tdb_key = f'{self.schema}_{id}'

        state = self._tdb_entries()
        if not state['by_id'].get(id):
            raise MatchNotFound()

        self.remove(tdb_key)
        return
