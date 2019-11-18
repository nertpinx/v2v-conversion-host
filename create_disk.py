import ovirtsdk4 as sdk
import ovirtsdk4.types as types

import sys
sd_name = sys.argv[1]

conn = sdk.Connection(
    url='https://ovirt-eng.virt/ovirt-engine/api',
    username='admin@internal',
    password='redhat',
    ca_file='/home/nert/ovirt-mine/ca.pem',
    insecure=True)
system_service = conn.system_service()
sds_service = system_service.storage_domains_service()
domains = sds_service.list(search='name=%s' % sd_name)

if len(domains) != 1:
    print('There are %d storage domains with name %s' % (len(domains), sd_name))
    sys.exit(1)

domain = domains[0]
# sds_service.storage_domain_service(domains.id)

disk = types.Disk(
    name='test',
    format=types.DiskFormat.COW,
    provisioned_size=1<<20,
    sparse=True,
    storage_domains=[domain])
disk = system_service.disks_service().add(disk)
disk = system_service.disks_service().disk_service(disk.id)

print(disk.get().id)
