from os import environ


CLUSTER_INFO = {
    'CLUSTER_IP': environ.get('CLUSTER_IP'),
    'NODE_A_IP': environ.get('NODE_A_IP'),
    'NODE_B_IP': environ.get('NODE_B_IP'),
    'NODE_C_IP': environ.get('NODE_C_IP'),
    'NETMASK': int(environ.get('NETMASK')),
    'INTERFACE': environ.get('INTERFACE'),
    'DEFGW': environ.get('DEFGW'),
    'DNS1': environ.get('DNS1'),
    'APIUSER': environ.get('APIUSER'),
    'APIPASS': environ.get('APIPASS'),
    'ZPOOL_DISK': environ.get('ZPOOL_DISK'),
    'ZPOOL': environ.get('ZPOOL'),
    'GLUSTER_VOLUME': environ.get('GLUSTER_VOLUME'),
}