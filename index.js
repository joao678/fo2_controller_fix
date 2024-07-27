import dialog_led from "./dialog.led" with { type: "file" };
import frida_script from "./frida_script.js" with { type: "text" };

import { execFile } from 'child_process';
import { connect } from 'frida-js';
import { button, dialog, iup, text } from "iupjs";
import { resolve } from 'path';
import { feedXidiDataFlatOut2 } from './fo2_controller_fix.js';

execFile(resolve('frida-server.exe'), { windowsHide: true });
let isBindingKey = false;

setTimeout(async () => {
    const fridaClient = await connect();

    fridaClient.enumerateProcesses().then((processes) => {
        const fo2 = processes.filter((p) => p.name === 'FlatOut2.exe').at(0).pid;

        fridaClient.injectIntoProcess(fo2, frida_script).then(({ session }) => {
            session.onMessage(function (message) {
                isBindingKey = !!(parseInt(message.payload));
            });
        });
    });
}, 2000);

iup.open();

await iup.loadLedFromFile(dialog_led);
const win = dialog.fromHandleName('dlg_led');
let minRangeValue = -12000;
let maxRangeValue = 12000;

const minRangeControl = text.fromHandleName('minRange');
const maxRangeControl = text.fromHandleName('maxRange');

minRangeControl.value = minRangeValue;
maxRangeControl.value = maxRangeValue;

[minRangeControl, maxRangeControl].forEach(control => control.mask = '[+/-]?/d+');

const applyButton = button.fromHandleName('applyButton');

applyButton.action = function () {
    if (isNaN(parseInt(minRangeControl.value))) return iup.messageError(null, 'Please enter a valid minimum value');
    if (isNaN(parseInt(maxRangeControl.value))) return iup.messageError(null, 'Please enter a valid maximum value');

    minRangeValue = minRangeControl.value;
    maxRangeValue = maxRangeControl.value;
}

win.show();

win.close_cb = function () {
    process.exit();
}

setInterval(async () => {
    feedXidiDataFlatOut2(minRangeValue, maxRangeValue, isBindingKey);

    iup.loopStep();
}, 1);