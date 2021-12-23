from asyncio import ensure_future

from middlewared.plugins.geom_.geom_cache import GeomCacheThread
from middlewared.service import Service


GCT = None  # global object representing geom cache thread
CLASSES = ('PART', 'MULTIPATH', 'DISK', 'LABEL', 'DEV', 'RAID')


class Geom(Service):

    class Config:
        private = True

    def get_disks(self):
        return GCT.disks

    def get_xml(self):
        return GCT.xml

    def get_class_xml(self, class_name):
        if GCT is not None:
            class_name = class_name.upper()
            if class_name in CLASSES and GCT.xml:
                return GCT.xml.find(f'.//class[name="{class_name}"]')

    def invalidate_cache(self):
        GCT.invalidate()

    def remove_disk(self, disk):
        GCT.remove(disk)


async def _event_system(middleware, *args, **kwargs):
    global GCT
    try:
        shutting_down = args[1]['id'] == 'shutdown'
    except (IndexError, KeyError):
        shutting_down = False

    if not shutting_down and (GCT is None or not GCT.is_alive()):
        # start the geom cache thread
        GCT = GeomCacheThread()
        GCT.start()
    elif shutting_down and (GCT is not None and GCT.is_alive()):
        GCT.stop()
        GCT = None


async def setup(middleware):
    ensure_future(_event_system(middleware))  # start thread on middlewared service start/stop
    middleware.event_subscribe('system', _event_system)  # catch shutdown event and clean up thread
