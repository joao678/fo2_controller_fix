const baseAddress = Module.getBaseAddress("FlatOut2.exe");
const enterBindingOffset = 0xAE5E9;
let functionAddressLeaveBinding = baseAddress.add(enterBindingOffset);

Interceptor.attach(functionAddressLeaveBinding, {
    onEnter: function (args) {
        console.log("1");
    }
});

const leaveBindingOffset = 0x226B;
let functionAddressEnterBinding = baseAddress.add(leaveBindingOffset);

Interceptor.attach(functionAddressEnterBinding, {
    onEnter: function (args) {
        console.log("0");
    }
});
