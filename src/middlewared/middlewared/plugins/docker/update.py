import middlewared.sqlalchemy as sa

from middlewared.schema import accepts, Bool, Dict, Int, Patch, Str, ValidationErrors
from middlewared.service import CallError, ConfigService, job, private, returns
from middlewared.utils.zfs import query_imported_fast_impl

from .state_utils import Status
from .utils import applications_ds_name


class DockerModel(sa.Model):
    __tablename__ = 'services_docker'

    id = sa.Column(sa.Integer(), primary_key=True)
    pool = sa.Column(sa.String(255), default=None, nullable=True)
    enable_image_updates = sa.Column(sa.Boolean(), default=True)
    nvidia = sa.Column(sa.Boolean(), default=False)


class DockerService(ConfigService):

    class Config:
        datastore = 'services.docker'
        datastore_extend = 'docker.config_extend'
        cli_namespace = 'app.docker'
        role_prefix = 'DOCKER'

    ENTRY = Dict(
        'docker_entry',
        Bool('enable_image_updates', required=True),
        Int('id', required=True),
        Str('dataset', required=True),
        Str('pool', required=True, null=True),
        Bool('nvidia', required=True),
        update=True,
    )

    @private
    async def config_extend(self, data):
        data['dataset'] = applications_ds_name(data['pool']) if data.get('pool') else None
        return data

    @accepts(
        Patch(
            'docker_entry', 'docker_update',
            ('rm', {'name': 'id'}),
            ('rm', {'name': 'dataset'}),
            ('attr', {'update': True}),
        )
    )
    @job(lock='docker_update')
    async def do_update(self, job, data):
        """
        Update Docker service configuration.
        """
        old_config = await self.config()
        old_config.pop('dataset')
        config = old_config.copy()
        config.update(data)

        verrors = ValidationErrors()
        if config['pool'] and not await self.middleware.run_in_thread(query_imported_fast_impl, [config['pool']]):
            verrors.add('docker_update.pool', 'Pool not found.')

        verrors.check()

        if old_config != config:
            if config['pool'] != old_config['pool']:
                job.set_progress(20, 'Stopping Docker service')
                try:
                    await self.middleware.call('service.stop', 'docker')
                except Exception as e:
                    raise CallError(f'Failed to stop docker service: {e}')

                await self.middleware.call('docker.state.set_status', Status.UNCONFIGURED.value)

            await self.middleware.call('datastore.update', self._config.datastore, old_config['id'], config)

            if config['pool'] != old_config['pool']:
                job.set_progress(60, 'Applying requested configuration')
                await self.middleware.call('docker.setup.status_change')

            if not old_config['nvidia'] and config['nvidia']:
                await (
                    await self.middleware.call(
                        'nvidia.install',
                        job_on_progress_cb=lambda encoded: job.set_progress(
                            80 + int(encoded['progress']['percent'] * 0.2),
                            encoded['progress']['description'],
                        )
                    )
                ).wait(raise_error=True)

        job.set_progress(100, 'Requested configuration applied')
        return await self.config()

    @accepts(roles=['DOCKER_READ'])
    @returns(Dict(
        Str('status', enum=[e.value for e in Status]),
        Str('description'),
    ))
    async def status(self):
        """
        Returns the status of the docker service.
        """
        return await self.middleware.call('docker.state.get_status_dict')

    @accepts(roles=['DOCKER_READ'])
    @returns(Bool())
    async def lacks_nvidia_drivers(self):
        """
        Returns true if an NVIDIA GPU is present, but NVIDIA drivers are not installed.
        """
        return await self.middleware.call('nvidia.present') and not await self.middleware.call('nvidia.installed')