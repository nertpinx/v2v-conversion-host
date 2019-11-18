import ovirtsdk4 as sdk
import ovirtsdk4.types as types

import sys
vmid = sys.argv[1]
diskid = sys.argv[2]

conn = sdk.Connection(
    url='https://ovirt-eng.virt/ovirt-engine/api',
    username='admin@internal',
    password='redhat',
    ca_file='/home/nert/ovirt-mine/ca.pem',
    insecure=True)
system_service = conn.system_service()
vm = system_service.vms_service().vm_service(vmid)
disk = system_service.disks_service().disk_service(diskid).get()

disk_att = types.DiskAttachment(
    active=True,
    bootable=False,
    description="test attachment",
    disk=disk,
    vm=vm.get(),
    interface=types.DiskInterface.VIRTIO)

disk_att = vm.disk_attachments_service().add(disk_att)

print(disk_att.id)
