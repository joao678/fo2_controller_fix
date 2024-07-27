const baseAddress = Module.getBaseAddress("FlatOut2.exe"); // Replace with your module's name or the executable if it's in the main module
const enterBindingOffset = 0xAE5E9; // Replace with your function's offset
let functionAddress = baseAddress.add(enterBindingOffset);

Interceptor.attach(functionAddress, {
    onEnter: function (args) {
        console.log("1");
    },
    /* onLeave: function (retval) {
        console.log("Function at offset 0xAE5E9 is returning");
    } */
});

const leaveBindingOffset = 0x1EDA;
functionAddress = baseAddress.add(leaveBindingOffset);

Interceptor.attach(functionAddress, {
    onEnter: function (args) {
        console.log("0");
    },
    /* onLeave: function (retval) {
        console.log("Function at offset 0x1EDA is returning");
    } */
});
