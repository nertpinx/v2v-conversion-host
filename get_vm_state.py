import ovirtsdk4 as sdk
import ovirtsdk4.types as types

import sys
vmid = sys.argv[1]

conn = sdk.Connection(
    url='https://dell-r430-02.lab.eng.brq.redhat.com/ovirt-engine/api',
    username='admin@internal',
    password='redhat',
    ca_file='/home/nert/dev/wrapper-test/rhv-libvirt/ca.pem')
system_service = conn.system_service()
try:
    vm = system_service.vms_service().vm_service(vmid).get()
    if vm.status != types.VmStatus.UP:
        print("%s is not up" % vm.name)
        sys.exit(1)
except sdk.NotFoundError:
    print('vm not found')
    sys.exit(1)

print('Yay, that is it')
