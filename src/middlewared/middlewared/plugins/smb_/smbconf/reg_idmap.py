from middlewared.plugins.smb_.registry_base import RegObj, RegistrySchema
import enum


class DSType(enum.Enum):
    """
    The below DS_TYPES are defined for use as system domains for idmap backends.
    DS_TYPE_NT4 is defined, but has been deprecated. DS_TYPE_DEFAULT_DOMAIN corresponds
    with the idmap settings under services->SMB, and is represented by 'idmap domain = *'
    in the smb4.conf. The only instance where the idmap backend for the default domain will
    not be 'tdb' is when the server is (1) joined to active directory and (2) autorid is enabled.
    """
    DS_TYPE_ACTIVEDIRECTORY = 1
    DS_TYPE_LDAP = 2
    DS_TYPE_DEFAULT_DOMAIN = 5

    def choices():
        return [x.name for x in DSType]


class IdmapRegObj(RegObj):
    def __init__(self, name, smbconf, default, **kwargs):
        self.middleware = kwargs.get("middleware")
        self.domain = kwargs.get("domain")
        self.logger = kwargs.get("logger")
        super().__init__(name, smbconf, default, **kwargs)


class IdmapSchema(RegistrySchema):
    def name_get(entry, conf):
        workgroup = conf.pop('workgroup')
        security = conf.pop('security')

        if entry.domain == "*":
            return DSType.DS_TYPE_DEFAULT_DOMAIN.name

        if entry.domain.casefold() == workgroup['raw'] and security['raw'] == "ADS":
            return DSType.DS_TYPE_ACTIVEDIRECTORY.name

        return entry.domain

    def name_set(entry, val, data_in, data_out):
        """
        This does not set any values in smb.conf. Purpose is
        to prepare idmap domain name that will be used in
        parameter prefixes.

        Setting entry.name to None means that the idmap entry
        will be skipped.
        """
        workgroup = data_in.get('workgroup')
        ad = data_in.get('ad')
        ldap = data_in.get('ldap')
        autorid = data_in.get("autorid_enabled")

        if entry.domain == DSType.DS_TYPE_DEFAULT_DOMAIN.name:
            if autorid:
                data_in['name'] = None
                return

        if entry.domain == DSType.DS_TYPE_ACTIVEDIRECTORY.name:
            if ad['enabled']:
                data_in['name'] = None
                return

            if data_in.get('idmap_backend') == 'AUTORID':
                data_in['name'] = "*"
            else:
                data_in['name'] = workgroup

        elif entry.domain == DSType.DS_TYPE_LDAP.name:
            if not ldap['enabled']:
                data_in['name'] = None
                return

            data_in['name'] = workgroup

        else:
            data_in['name'] = entry.domain

        return

    def dns_name_get(entry, conf):
        """
        This information is not currently stored in smb.conf.
        """
        return ""

    def dns_name_set(entry, val, data_in, data_out):
        """
        This information is not currently stored in smb.conf.
        """
        return

    def range_low_get(entry, conf):
        idmap_range = conf['range']['raw']
        return idmap_range.split("-")[0].strip()

    def range_low_set(entry, val, data_in, data_out):
        domain = data_in.get('name')
        if domain is None:
            return

        prefix = f"idmap config {domain} : range"
        data_out[prefix] = {'parsed': data_in['range_low']}
        return

    def range_high_get(entry, conf):
        idmap = conf.pop('range')
        return idmap['raw'].split("-")[1].strip()

    def range_high_set(entry, val, data_in, data_out):
        domain = data_in.get('name')
        if domain is None:
            return

        prefix = f"idmap config {domain} : range"
        range = data_out[prefix]
        range['parsed'] = f'{range["parsed"]} - {data_in["range_high"]}'
        return

    def backend_get(entry, conf):
        idmap = conf.pop('backend')
        return idmap['raw']

    def backend_set(entry, val, data_in, data_out):
        domain = data_in.get('name')
        if domain is None:
            return

        prefix = f"idmap config {domain} : backend"
        data_out[prefix] = {'parsed': data_in['backend']}
        return

    def options_get(entry, conf):
        """
        List all other configured idmap parameters as "options"
        """
        rv = {}

        for k, v in conf.items():
            rv.update({k: v['raw']})

        return rv

    def options_set(entry, val, data_in, data_out):
        domain = data_in.get('name')
        if domain is None:
            return

        idmap_prefix = f"idmap config {domain} :"
        if domain == DSType.DS_TYPE_LDAP.name and data_in['backend'] == "LDAP":
            ldap = data_in.get('ldap')
            data_out.update({
                f"{idmap_prefix} ldap_base_dn": ldap['basedn'],
                f"{idmap_prefix} ldap_url": ' '.join(ldap['uri_list']),
            })

        for k, v in data_in['options'].items():
            data_out[f'{idmap_prefix} {k}'] = v['parsed']

        return

    def cert_get(entry, conf):
        return None

    def cert_set(entry, val, data_in, data_out):
        return

    schema = [
        IdmapRegObj("name", None, "",
                    smbconf_parser=name_get, schema_parser=name_set),
        IdmapRegObj("dns_domain_name", None, "",
                    smbconf_parser=dns_name_get, schema_parser=dns_name_set),
        IdmapRegObj("range_low", None, -1,
                    smbconf_parser=range_low_get, schema_parser=range_low_set),
        IdmapRegObj("range_high", None, -1,
                    smbconf_parser=range_high_get, schema_parser=range_high_set),
        IdmapRegObj("idmap_backend", None, "rid",
                    smbconf_parser=backend_get, schema_parser=backend_set),
        IdmapRegObj("options", None, {},
                    smbconf_parser=options_get, schema_parser=options_set),
        IdmapRegObj("certificate", None, None,
                    smbconf_parser=cert_get, schema_parser=cert_set),
    ]

    def __init__(self, middleware, domain):
        self.middleware = middleware
        self.logger = middleware.logger
        self.domain = domain

        for entry in self.schema:
            entry.domain = domain
            entry.middleware = middleware
            entry.logger = self.logger

        super().__init__(self.schema)
