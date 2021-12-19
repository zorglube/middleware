import asyncio


async def configure_waagent(middleware):
    if await middleware.call('system.ready'):
        return

    dmi_info = await middleware.call('system.dmidecode_info')
    if dmi_info['system-manufacturer'] == 'Microsoft Corporation':
        # TODO: Let's test this on azure please to see what we have or how we can differentiate
        pass


async def setup(middleware):
    asyncio.ensure_future(configure_waagent(middleware))
