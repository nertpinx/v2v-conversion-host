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
vm_serv = system_service.vms_service().vm_service(vmid)
try:
    vm = vm_serv.get()
except sdk.NotFoundError:
    print('vm not found')
    sys.exit(1)

if vm.status == types.VmStatus.UP:
    print('%s is already up' % vm.name)
elif vm.status != types.VmStatus.DOWN:
    print('%s is in state %s, not starting' % (vm.name, vm.status))
else:
    print('%s is not up, starting' % vm.name)
    vm_serv.start()
