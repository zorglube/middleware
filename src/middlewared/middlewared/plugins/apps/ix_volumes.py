import collections

from middlewared.schema import accepts, Bool, Dict, returns, Str
from middlewared.service import filterable, filterable_returns, Service
from middlewared.utils import filter_list

from .ix_apps.path import get_app_mounts_ds


class AppsIxVolumeService(Service):

    class Config:
        namespace = 'app.ix_volume'
        event_send = False
        cli_namespace = 'app.ix_volume'

    @filterable(roles=['APPS_READ'])
    @filterable_returns(Dict(
        'ix-volumes_query',
        Str('app_name'),
        Str('name'),
        additional_attrs=True,
    ))
    async def query(self, filters, options):
        """
        Query ix-volumes with `filters` and `options`.
        """
        if not await self.middleware.call('docker.state.validate', False):
            return filter_list([], filters, options)

        docker_ds = (await self.middleware.call('docker.config'))['dataset']
        datasets = await self.middleware.call(
            'zfs.dataset.query', [['id', '^', f'{get_app_mounts_ds(docker_ds)}/']], {
                'extra': {'retrieve_properties': False, 'flat': True}
            }
        )
        apps = collections.defaultdict(list)
        for ds_name in filter(lambda d: d.count('/') > 3, map(lambda d: d['id'], datasets)):
            name_split = ds_name.split('/', 4)
            apps[name_split[3]].append(name_split[-1])

        volumes = []
        for app, app_volumes in apps.items():
            for volume in app_volumes:
                volumes.append({
                    'name': volume,
                    'app_name': app,
                })

        return filter_list(volumes, filters, options)

    @accepts(Str('app_name'))
    @returns(Bool('ix_volumes_exist'))
    async def exists(self, app_name):
        """
        Check if ix-volumes exist for `app_name`.
        """
        return bool(await self.query([['app_name', '=', app_name]]))
