from middlewared.service import Service, job, private
from middlewared.service_exception import CallError
from middlewared.utils import run
from middlewared.plugins.smb import SMBCmd, SMBBuiltin, SMBPath

import os
import re
import json
import tdb
import struct

class SMBService(Service):

    class Config:
        service = 'cifs'
        service_verb = 'restart'

    async def listmem(self, sid):
        payload = json.dumps({"alias": sid}) 
        lm = await run([
            SMBCmd.NET.value, "--json", "groupmap", "listmem", paylaod 
        ], check=False)

        if lm.returncode != 0:
            raise CallError(
               f"Failed to retrieve membership of [{sid}]: {lm.stderr.decode()}" 
            )

        return json.loads(lm.stdout.decode())

    async def addmem(self, alias, member):
        payload = json.dumps({'alias': alias, 'member': member})
        am = await run([
            SMBCmd.NET.value, "--json", "groupmap", "addmem", json.dumps({"alias": sid})
        ], check=False)
        if am.returncode != 0:
            raise CallError(
               f"Failed to add [{member}] to [{alias}]: {am.stderr.decode()}" 
            )

    @private
    async def sync_foreign_groups(self):
        """
        Domain Users, and Domain Admins must have S-1-5-32-545 and S-1-5-32-544
        added to their respective Unix tokens for correct behavior in AD domain.
        This are added by making them foreign members in the group_mapping for
        the repsective alias. This membership is generated during samba startup
        when newly creating these groups (if they don't exist), but can get
        lost, resulting in unexpected / erratic permissions behavior. There are
        only a handful such relationships and so creating a batch API for this
        was low priority as opposed to normal groupmap entries which may number
        above one hundred.
        """
        # second groupmap listing is to ensure we have accurate / current info.
        groupmap = await self.groupmap_list()
        ad_state = await self.middleware.call('activedirectory.get_state')

        # First add our local users, admins, and guests to the builtins
        admins = await self.listmem("S-1-5-32-544")
        if groupmap['local_builtins'][544]['sid'] not in admins: 
            to_add = groupmap['local_builtins'][544]['sid']
            await self.addmem("S-1-5-32-544", to_add) 
        else:
            admins.remove(groupmap['local_builtins'][544]['sid'])

        users = await self.listmem("S-1-5-32-545")
        if groupmap['local_builtins'][545]['sid'] not in users: 
            to_add = groupmap['local_builtins'][545]['sid']
            await self.addmem("S-1-5-32-545", to_add)
        else:
            users.remove(groupmap['local_builtins'][545]['sid'])
 
        guests = await self.listmem("S-1-5-32-546")
        if groupmap['local_builtins'][546]['sid'] not in guests: 
            to_add = groupmap['local_builtins'][546]['sid']
            await self.addmem("S-1-5-32-546", to_add)
        else:
            guests.remove(groupmap['local_builtins'][545]['sid'])

        local_guest = f'{groupmap["localsid"]-501}'
        if local_guest not in guests:
            await self.addmem("S-1-5-32-546", local_guest)
        else:
            guests.remove(local_guest)

        if ad_state == 'DISABLED':
            return

        if ad_state == 'FAULTED':
            self.logger.debug(
               "Unable to validate foreign group members for builting groups"
               "while Active Directory is FAULTED."
            )
            return

        # Now handle AD users / groups. This requires AD to be in healthy state
        domain_sid = await self.middleware.call('idmap.domain_info', 'DS_TYPE_ACTIVEDIRECTORY')
        domain_admins = f'{domain_sid}-512'
        domain_users = f'{domain_sid}-513'
        domain_guests = f'{domain_sid}-514'

        if domain_admins not in admins:
            await self.addmem('S-1-5-32-544', domain_admins)
        else:
            admins.remove(domain_admins)

        if domain_users not in users:
            await self.addmem('S-1-5-32-545', domain_users)
        else:
            users.remove(domain_users)

        if domain_guests not in guests:
            await self.addmem('S-1-5-32-546', domain_guests)
        else:
            admins.remove(domain_admins)

        # Purge all entries that shouldn't be there
        for dom_sid, group in [('S-1-5-32-544', admins), ('S-1-5-32-545', users), ('S-1-5-32-546', guests)]:
            for sid in group:
                self.logger.debug("removing [%s] from [%s]", sid, dom_sid)
                await self.delmem(dom_sid, sid) 

    @private
    def validate_groupmap_hwm(self, low_range):
        """
        Middleware forces allocation of GIDs for Users, Groups, and Administrators
        to be deterministic with the default idmap backend. Bump up the idmap_tdb
        high-water mark to avoid conflicts with these and remove any mappings that
        conflict. Winbindd will regenerate the removed ones as-needed.
        """
        must_reload = False
        tdb_handle = tdb.open(f"{SMBPath.STATEDIR.platform()}/winbindd_idmap.tdb")

        try:
            group_hwm_bytes = tdb_handle.get(b'GROUP HWM\00')
            hwm = struct.unpack("<L", group_hwm_bytes)[0] 
            if hwm < low_range + 2:
                tdb_handle.transaction_start()
                new_hwm_bytes = struct.pack("<L", group_hwm_bytes)
                tdb_handle.store(b'GROUP HWM\00', new_hwm_bytes)
                tdb_handle.transaction_commit()
                must_reload = True

            for key in tdb_handle.keys():
                if key[:3] == b'GID' and int(key.decode()[4:-3]) < (low_range + 2):
                    reverse = tdb_handle.get(key)
                    tdb_handle.transaction_start()
                    tdb_handle.delete(key)
                    tdb_handle.delete(reverse)
                    tdb_handle.transaction_commit()
                    must_reload = True

        except Exception as e:
            self.logger.warning("TDB maintenace failed: %s", e)

        finally:
            tdb_handle.close()

        return must_reload

    @private
    async def groupmap_list(self):
        """
        Convert JSON groupmap output to dict to get O(1) lookups by `gid`

        Separate out the groupmap output into builtins, locals, and invalid entries.
        Invalid entries are ones that aren't from our domain, or are mapped to gid -1.
        Latter occurs when group mapping is lost. In case of invalid entries, we store
        list of SIDS to be removed. SID is necessary and sufficient for groupmap removal.
        """
        rv = {"builtins": {}, "local": {}, "local_builtins": {}, "invalid": []}
        localsid = await self.middleware.call('smb.get_system_sid')
        if localsid is None:
            raise CallError("Unable to retrieve local system SID. Group mapping failure.")

        out = await run([SMBCmd.NET.value, '--json', 'groupmap', 'list', 'verbose'], check=False)
        if out.returncode != 0:
            raise CallError(f'groupmap list failed with error {out.stderr.decode()}')

        gm = json.loads(out.stdout.decode())
        for g in gm['groupmap']:
            gid = g['gid']
            if gid == -1:
                rv['invalid'].append(g['sid'])
                continue

            if g['sid'].startswith("S-1-5-32"):
                rv['builtins'][gid] = g
            elif g['sid'].startswith(localsid) and g['gid'] in range(544, 547):
                rv['local_builtins'][gid] = g
            elif g['sid'].startswith(localsid):
                rv['local'][gid] = g
            else:
                rv['invalid'].append(g['sid'])

        rv["localsid"] = localsid
        return rv 

    @private
    async def sync_builtins(self, groupmap):
        idmap_backend = await self.middleware.call("smb.getparm", "idmap config *:backend", "GLOBAL")
        idmap_range = await self.middleware.call("smb.getparm", "idmap config *:range", "GLOBAL")
        payload = {"ADD": [], "MOD": []}

        if idmap_backend != "tdb":
            """
            idmap_autorid and potentially other allocating idmap backends may be used for
            the default domain. We do not want to touch how these are allocated.
            """
            return

        low_range = int(idmap_range.split("-")[0].strip())
        sid_lookup = {x["sid"]: x for x in groupmap.values()}

        for b in SMBBuiltin:
            sid = b.value[1]
            rid = int(sid.split('-')[-1])
            gid = low_range + (rid - 544)
            entry = sid_lookup.get(sid, None)
            if entry and entry['gid'] == gid:
                # Value is correct, nothing to do.
                continue
            elif entry and entry['gid'] != gid:
                payload['MOD'].append({
                    'sid': str(sid),
                    'gid': gid,
                    'group_type_str': 'local',
                    'nt_name': b.value[0][8:].capitalize()
                })
            else:
                payload['ADD'].append({
                    'sid': str(sid),
                    'gid': gid,
                    'group_type_str': 'local',
                    'nt_name': b.value[0][8:].capitalize()
                })

        await self.batch_groupmap(payload)
        must_reload = await self.middleware.call('smb.validate_groupmap_hwm', low_range)
        return must_reload 

    @private
    async def batch_groupmap(self, data):
        for op in ["ADD", "MOD", "DEL"]:
            if data.get(op) is not None and len(data[op]) == 0:
                data.pop(op) 

        payload = json.dumps(data)
        self.logger.debug("payload: %s", payload)
        out = await run([SMBCmd.NET.value, '--json', 'groupmap', 'batch_json', f'data={payload}'], check=False)
        if out.returncode != 0:
            raise CallError(f'groupmap list failed with error {out.stderr.decode()}')

    @private
    @job(lock="groupmap_sync")
    async def synchronize_group_mappings(self, job):
        """
        This method does the following:
        1) prepares payload for a batch groupmap operation. These are added to two arrays:
           "to_add" and "to_del". Missing entries are added, invalid entries are deleted.
        2) we synchronize S-1-5-32-544, S-1-5-32-545, and S-1-5-32-546 separately
        3) we add any required group mappings for the SIDs in (2) above.
        4) we flush various caches if required.
        """
        payload = {}
        to_add = []
        to_del = []

        if await self.middleware.call('ldap.get_state') != "DISABLED":
            return

        self.logger.debug("Synchronizing groupmap")
        groupmap = await self.groupmap_list()
        must_remove_cache = False
        passdb_backend = await self.middleware.call('smb.getparm', 'passdb backend', 'global')

        groups = await self.middleware.call('group.query', [('builtin', '=', False), ('smb', '=', True)])
        g_dict = {x["gid"]: x for x in groups}

        set_to_add = set(g_dict.keys()) - set(groupmap["local"].keys())
        set_to_del = set(groupmap["local"].keys()) - set(g_dict.keys())

        to_add = [{
            "gid": g_dict[x]["gid"],
            "nt_name": g_dict[x]["group"],
            "group_type_str": "local"
        } for x in set_to_add]

        to_del = [{
            "sid": groupmap["local"][x]["sid"]
        } for x in set_to_del]

        for sid in groupmap['invalid']:
            to_del.append({"sid": sid})

        for gid in range(544, 547):
            if not groupmap["local_builtins"].get(gid):
                builtin = SMBBuiltin.by_rid(gid)
                rid = 512 + (gid - 544)
                sid = f'{groupmap["localsid"]}-{rid}'
                to_add.append({
                    "gid": gid,
                    "nt_name": f"local_{builtin.name.lower()}",
                    "group_type_str": "local",
                    "sid": sid,
                })

        if to_add:
            payload["ADD"] = to_add

        if to_del:
            payload["DEL"] = to_del

        self.logger.debug("payload: %s", payload)
        await self.middleware.call('smb.fixsid')
        await self.batch_groupmap(payload)
        must_remove_cache = await self.sync_builtins(groupmap['builtins'])
        await self.sync_foreign_groups(groupmap)

        if must_remove_cache:
            if os.path.exists(f'{SMBPath.STATEDIR.platform()}/winbindd_cache.tdb'):
                os.remove(f'{SMBPath.STATEDIR.platform()}/winbindd_cache.tdb')
            flush = await run([SMBCmd.NET.value, 'cache', 'flush'], check=False)
            if flush.returncode != 0:
                self.logger.debug('Attempt to flush cache failed: %s', flush.stderr.decode().strip())
