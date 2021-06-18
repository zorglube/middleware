from middlewared.plugins.smb_.registry_base import RegObj, RegistrySchema
from bidict import bidict

LOGLEVEL_MAP = bidict({
    '0': 'NONE',
    '1': 'MINIMUM',
    '2': 'NORMAL',
    '3': 'FULL',
    '10': 'DEBUG',
})


class GlobalSchema(RegistrySchema):
    def smb_proto_transform(entry, conf):
        val = conf.pop(entry.smbconf, entry.default)
        if val == entry.default:
            return val

        return val['raw'] == "NT1"

    def set_min_protocol(entry, val, data_in, data_out):
        data_out[entry.smbconf] = {"parsed": "NT1" if val else "SMB2_10"}
        return

    def log_level_transform(entry, conf):
        val = conf.pop(entry.smbconf, entry.default)
        if val == entry.default:
            return val

        if val['raw'].startswith("syslog@"):
            val = val['raw'][len("syslog@")]

        return LOGLEVEL_MAP.get(val['raw'].split()[0])

    def set_log_level(entry, val, data_in, data_out):
        loglevelint = LOGLEVEL_MAP.inv.get(val, "MINIMUM")
        loglevel = f"{loglevelint} auth_json_audit:3@/var/log/samba4/auth_audit.log"
        if data_in['syslog']:
            logging = f'syslog@{"3" if loglevelint > 3 else val} file'
        else:
            logging = "file"
        data_out.update({
            "log level": {"parsed": loglevel},
            "logging": {"parsed": logging},
        })
        return

    def bind_ip_transform(entry, conf):
        val = conf.pop(entry.smbconf, entry.default)
        if val == entry.default:
            return val

        conf.pop('bind interfaces only', None)

        if type(val) == dict:
            bind_ips = val['raw'].split()
        else:
            bind_ips = val

        if bind_ips:
            bind_ips.remove("127.0.0.1")

        return bind_ips

    def set_bind_ips(entry, val, data_in, data_out):
        if val:
            val.insert(0, "127.0.0.1")
            data_out['interfaces'] = {"parsed": val}

        data_out['bind interfaces only'] = {"parsed": True}
        return

    def mask_transform(entry, conf):
        val = conf.pop(entry.smbconf, entry.default)
        if val == entry.default:
            return val

        if val['raw'] == "0775":
            return ""

        return val['raw']

    def set_mask(entry, val, data_in, data_out):
        if not val:
            val = entry.default

        data_out[entry.smbconf] = {"parsed": val}
        return

    schema = [
        RegObj("netbiosname", "tn:netbiosname", "truenas"),
        RegObj("netbiosname_b", "tn:netbiosname_b", "truenas-b"),
        RegObj("netbiosname_local", "netbios name", ""),
        RegObj("workgroup", "workgroup", "WORKGROUP"),
        RegObj("cifs_SID", "tn:sid", ""),
        RegObj("next_rid", "tn:next_rid", -1),
        RegObj("netbiosalias", "netbios aliases", []),
        RegObj("description", "server string", ""),
        RegObj("enable_smb1", "server min protocol", False,
               smbconf_parser=smb_proto_transform, schema_parser=set_min_protocol),
        RegObj("unixcharset", "unix charset", "UTF8"),
        RegObj("syslog", "syslog only", False),
        RegObj("apple_extensions", "tn:fruit_enabled", False),
        RegObj("localmaster", "local master", False),
        RegObj("loglevel", "log level", "MINIMUM",
               smbconf_parser=log_level_transform, schema_parser=set_log_level),
        RegObj("guest", "guest account", "nobody"),
        RegObj("admin_group", "tn:admin_group", ""),
        RegObj("filemask", "create mask", "0775",
               smbconf_parser=mask_transform, schema_parser=set_mask),
        RegObj("dirmask", "directory mask", "0775",
               smbconf_parser=mask_transform, schema_parser=set_mask),
        RegObj("ntlmv1_auth", "ntlm auth", False),
        RegObj("bindip", "interfaces", [],
               smbconf_parser=bind_ip_transform, schema_parser=set_bind_ips),
    ]

    def __init__(self):
        super().__init__(self.schema)
