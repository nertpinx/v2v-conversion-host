import ovirtsdk4 as sdk
import ovirtsdk4.types as types

import sys
diskid = sys.argv[1]

conn = sdk.Connection(
    url='https://ovirt-eng.virt/ovirt-engine/api',
    username='admin@internal',
    password='redhat',
    ca_file='/home/nert/ovirt-mine/ca.pem',
    insecure=True)
system_service = conn.system_service()
disk = system_service.disks_service().disk_service(diskid).get()
if disk.status != types.DiskStatus.OK:
    print("%s is not ok, but %s" % (disk.name, disk.status))
    sys.exit(1)

print(disk.status)
