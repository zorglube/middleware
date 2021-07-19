from middlewared.schema import Any, Str, Dict, accepts, Int, Bool
from middlewared.service import Service, private, job, filterable
from middlewared.utils import filter_list, osc, run
from middlewared.utils.tdb import CTDBWrap
from middlewared.service_exception import CallError


from collections import namedtuple
import time
import pickle
import json
import pwd
import grp
import os
import errno


class ClusterCacheService(Service):
    is_clustered_fn = None
    tdb_attach_fn = None
    tdb_init_fn = None
    tdb_handle = None

    class Config:
        private = True

    async def assert_ctdb_healthy(self):
        healthy = await self.middleware.call('ctdb.general.healthy')
        if healthy:
            return

        raise CallError("ctdb must be enabled and healthy in order "
                        "to access clustered cache", errno.ENXIO)

    async def _tdb_initialize(self):
        await self.is_clustered_fn()
        if self.tdb_handle is not None:
            return

        dbid = await self.tdb_attach_fn()
        self.tdb_handle = CTDBWrap(dbid)
        return

    async def _tdb_attach(self):
        tdb_name = "middlewared.tdb"
        cmd = ["ctdb", "attach", tdb_name, "persistent"]
        attach = await run(cmd, check=False)
        if attach.returncode != 0:
            self.logger.warning("Failed to attach backend: %s",
                                attach.stderr.decode())
            return

        dbmap = await self.middleware.call("ctdb.general.getdbmap",
                                           [("name", "=", tdb_name)])

        if not dbmap:
            self.logger.warning("dbmap lookup failed for %s", tdb_name)
            return

        return dbmap[0]["dbid"]

    @accepts(Str('key'))
    async def get(self, key):
        """
        Get `key` from cache.

        Raises:
            KeyError: not found in the cache
            CallError: issue with clustered key-value store

        CLOCK_REALTIME because clustered
        """
        await self.tdb_init_fn()
        tdb_value = self.tdb_handle.get(key)

        if tdb_value is None:
            raise KeyError(key)

        expires = float(tdb_value[:12])
        now = time.clock_gettime(time.CLOCK_REALTIME)
        if expires and now > expires:
            self.tdb_handle.remove(key)
            raise KeyError(f'{key} has expired')

        is_encrypted = bool(int(tdb_value[14]))
        if is_encrypted:
            raise NotImplementedError

        data = json.loads(tdb_value[18:])
        return data

    @accepts(Str('key'))
    async def pop(self, key):
        """
        Removes and returns `key` from cache.
        """
        await self.tdb_init_fn()
        tdb_value = self.tdb_handle.get(key)
        is_encrypted = False

        if tdb_value:
            self.tdb_handle.remove(key)
            is_encrypted = bool(int(tdb_value[14]))
            tdb_value = json.loads(tdb_value[18:])

        return tdb_value

    @accepts(Str('key'))
    async def has_key(self, key):
        await self.tdb_init_fn()
        tdb_value = self.tdb_handle.get(key)

        return bool(tdb_value)

    @accepts(
        Str('key'),
        Dict('value', additional_attrs=True),
        Int('timeout', default=0),
        Dict('options', Str('flag', enum=["CREATE", "REPLACE"], default=None, null=True), Bool('private', default=False),)
    )
    async def put(self, key, value, timeout, options):
        """
        Put `key` of `value` in the cache. `timeout` specifies time limit
        after which it will be removed.

        The following options are supported:
        `flag` optionally specifies insertion behavior.
        `CREATE` flag raises KeyError if entry exists. `UPDATE` flag
        raises KeyError if entry does not exist. When no flags are specified
        then entry is simply inserted.

        `private` determines whether data should be encrypted before being
        committed to underlying storage backend.
        """
        if options['private']:
            # will implement in later commit
            raise NotImplementedError

        await self.tdb_init_fn()

        if timeout != 0:
            ts = f'{time.clock_gettime(time.CLOCK_REALTIME) + timeout:.2f}'
        else:
            ts = '0000000000.00'

        tdb_key = key

        # This format must not be changed without careful consideration
        # Zeros are left as padding in middle to expand boolean options if needed
        tdb_val = f'{ts}{int(options["private"])}0000{json.dumps(value)}'

        if options['flag']:
            has_entry = False
            try:
                has_entry = bool(await self.get(tdb_key))
            except KeyError:
                pass

            if options['flag'] == "CREATE" and has_entry:
                raise KeyError(key)

            if options['flag'] == "UPDATE" and not has_entry:
                raise KeyError(key)

        self.tdb_handle.set(tdb_key, tdb_val)
        return

    @filterable
    async def query(self, filters, options):
        def cache_convert_cb(tdb_key, tdb_val, entries):
            entries.append({
                "key": tdb_key,
                "timeout": float(tdb_val[:12]),
                "private": bool(int(tdb_val[14])),
                "value": json.loads(tdb_val[18:])
            })
            return True

        await self.tdb_init_fn()
        if not filters:
            filters = []
        if not options:
            options = {}

        tdb_entries = []
        self.tdb_handle.traverse(cache_convert_cb, tdb_entries)

        return filter_list(tdb_entries, filters, options)

    def __init__(self, *args, **kwargs):
        super(ClusterCacheService, self).__init__(*args, **kwargs)
        self.is_clustered_fn = self.assert_ctdb_healthy
        self.tdb_attach_fn = self._tdb_attach
        self.tdb_init_fn = self._tdb_initialize


class CacheService(Service):

    class Config:
        private = True

    def __init__(self, *args, **kwargs):
        super(CacheService, self).__init__(*args, **kwargs)
        self.__cache = {}
        self.kv_tuple = namedtuple('Cache', ['value', 'timeout'])

    @accepts(Str('key'))
    def has_key(self, key):
        """
        Check if given `key` is in cache.
        """
        return key in self.__cache

    @accepts(Str('key'))
    def get(self, key):
        """
        Get `key` from cache.

        Raises:
            KeyError: not found in the cache
        """

        if self.__cache[key].timeout > 0:
            self.get_timeout(key)

        return self.__cache[key].value

    @accepts(Str('key'), Any('value'), Int('timeout', default=0))
    def put(self, key, value, timeout):
        """
        Put `key` of `value` in the cache.
        """

        if timeout != 0:
            timeout = time.monotonic() + timeout

        v = self.kv_tuple(value=value, timeout=timeout)
        self.__cache[key] = v

    @accepts(Str('key'))
    def pop(self, key):
        """
        Removes and returns `key` from cache.
        """
        cache = self.__cache.pop(key, None)

        if cache is not None:
            cache = cache.value

        return cache

    @private
    def get_timeout(self, key):
        """
        Check if 'key' has expired
        """
        now = time.monotonic()
        value, timeout = self.__cache[key]

        if now >= timeout:
            # Bust the cache
            del self.__cache[key]

            raise KeyError(f'{key} has expired')

    @private
    def get_or_put(self, key, timeout, method):
        try:
            return self.get(key)
        except KeyError:
            value = method()
            self.put(key, value, timeout)
            return value


class DSCache(Service):

    class Config:
        private = True

    def get_uncached_user(self, username=None, uid=None):
        """
        Returns dictionary containing pwd_struct data for
        the specified user or uid. Will raise an exception
        if the user does not exist. This method is appropriate
        for user validation.
        """
        if username:
            u = pwd.getpwnam(username)
        elif uid is not None:
            u = pwd.getpwuid(uid)
        else:
            return {}
        return {
            'pw_name': u.pw_name,
            'pw_uid': u.pw_uid,
            'pw_gid': u.pw_gid,
            'pw_gecos': u.pw_gecos,
            'pw_dir': u.pw_dir,
            'pw_shell': u.pw_shell
        }

    def get_uncached_group(self, groupname=None, gid=None):
        """
        Returns dictionary containing grp_struct data for
        the specified group or gid. Will raise an exception
        if the group does not exist. This method is appropriate
        for group validation.
        """
        if groupname:
            g = grp.getgrnam(groupname)
        elif gid is not None:
            g = grp.getgrgid(gid)
        else:
            return {}
        return {
            'gr_name': g.gr_name,
            'gr_gid': g.gr_gid,
            'gr_mem': g.gr_mem
        }

    def initialize(self):
        dstypes = [('activedirectory', 'AD'), ('ldap', 'LDAP')]
        if osc.IS_FREEBSD:
            dstypes.append(('nis', 'NIS'))

        for ds in dstypes:
            if (self.middleware.call_sync(f'{ds[0]}.config'))['enable']:
                try:
                    with open(f'/var/db/system/.{ds[1]}_cache_backup', 'rb') as f:
                        pickled_cache = pickle.load(f)
                    self.middleware.call_sync('cache.put', f'{ds[1]}_cache', pickled_cache)
                except FileNotFoundError:
                    self.logger.debug('User cache file for [%s] is not present.', ds[0])

    def backup(self):
        dstypes = [('activedirectory', 'AD'), ('ldap', 'LDAP')]
        if osc.IS_FREEBSD:
            dstypes.append(('nis', 'NIS'))

        for ds in dstypes:
            if (self.middleware.call_sync(f'{ds[0]}.config'))['enable']:
                try:
                    ds_cache = self.middleware.call_sync('cache.get', f'{ds[1]}_cache')
                    with open(f'/var/db/system/.{ds[1]}_cache_backup', 'wb') as f:
                        pickle.dump(ds_cache, f)
                except KeyError:
                    self.logger.debug('No cache exists for directory service [%s].', ds[0])

    async def query(self, objtype='USERS', filters=None, options=None):
        """
        Query User / Group cache with `query-filters` and `query-options`.

        `objtype`: 'USERS' or 'GROUPS'

        Each directory service, when enabled, will generate a user and group cache using its
        respective 'fill_cache' method (ex: ldap.fill_cache). The cache entry is formatted
        as follows:

        The cache can be refreshed by calliing 'dscache.refresh'. The actual cache fill
        will run in the background (potentially for a long time). The exact duration of the
        fill process depends factors such as number of users and groups, and network
        performance. In environments with a large number of users (over a few thousand),
        administrators may consider disabling caching. In the case of active directory,
        the dscache will continue to be filled using entries from samba's gencache (the end
        result in this case will be that only users and groups actively accessing the share
        will be populated in UI dropdowns). In the case of other directory services, the
        users and groups will simply not appear in query results (UI features).

        """
        res = []
        ds_state = await self.middleware.call('directoryservices.get_state')

        is_name_check = bool(filters and len(filters) == 1 and filters[0][0] in ['username', 'groupname'])

        res.extend((await self.middleware.call(f'{objtype.lower()[:-1]}.query', filters, options)))

        for dstype, state in ds_state.items():
            if state != 'DISABLED':
                """
                Avoid iteration here if possible.  Use keys if single filter "=" and x in x=y is a
                username or groupname.
                """
                if is_name_check and filters[0][1] == '=':
                    cache = (await self.middleware.call(f'{dstype}.get_cache'))[objtype.lower()]
                    name = filters[0][2]
                    return [cache.get(name)] if cache.get(name) else []

                else:
                    res.extend(filter_list(
                        list((await self.middleware.call(f'{dstype}.get_cache'))[objtype.lower()].values()),
                        filters,
                        options
                    ))

        return res

    @job(lock="dscache_refresh")
    async def refresh(self, job):
        """
        This is called from a cronjob every 24 hours and when a user clicks on the
        UI button to 'rebuild directory service cache'.
        """
        available_ds = ['activedirectory', 'ldap']
        if osc.IS_FREEBSD:
            available_ds.append('nis')

        for ds in available_ds:
            ds_state = await self.middleware.call(f'{ds}.get_state')
            if ds_state == 'HEALTHY':
                await job.wrap(await self.middleware.call(f'{ds}.fill_cache', True))
            elif ds_state != 'DISABLED':
                self.logger.debug('Unable to refresh [%s] cache, state is: %s' % (ds, ds_state))
            else:
                if ds == 'activedirectory':
                    backup_path = "/var/db/system/.AD_cache"
                elif ds == 'ldap':
                    backup_path = "/var/db/system/.LDAP_cache"
                else:
                    backup_path = "/var/db/system/.NIS_cache"
                try:
                    os.unlink(backup_path)
                except FileNotFoundError:
                    pass
                except Exception:
                    self.logger.error("Failed to remove directory service cache backup [%s].",
                                      backup_path, exc_info=True)

        await self.middleware.call('dscache.backup')


async def setup(middleware):
    """
    During initial boot, we need to wait for the system dataset to be imported.
    """
    if await middleware.call('system.ready'):
        await middleware.call('dscache.initialize')
