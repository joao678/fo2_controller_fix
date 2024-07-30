import dialog_led from "./dialog.led" with { type: "file" };
import frida_script from "./frida_script.js" with { type: "text" };
import tray_icon from "./icon.png" with { type: "file" };

import { execFile } from 'child_process';
import { connect } from 'frida-js';
import { button, dialog, item, iup, IUP_IGNORE, IUP_MOUSEPOS, IupLoadImage, IupPopup, IupSetHandle, menu, str, text } from "iupjs";
import { resolve } from 'path';
import { feedXidiDataFlatOut2 } from './fo2_controller_fix.js';
import { $ } from "bun";

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
iup.imgLibOpen();

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

iup.map(win);

IupSetHandle(str`trayICN`, IupLoadImage(str`${tray_icon}`));

win.tray = 'YES';
win.trayimage = 'trayICN';
win.traytip = 'FO2 Controller fix running...';
win.hidetaskbar = 'YES';

const trayMenu = new menu((() => {
    const i = new item('Exit');
    i.action = () => process.exit();
    return i;
})());

win.trayclick_cb = function (ih, but, pressed, dclick) {
    if (dclick && but === 1) win.visible == 'NO' ? win.visible = 'YES' : win.visible = 'NO';
    if (but === 3) IupPopup(trayMenu.handle, IUP_MOUSEPOS, IUP_MOUSEPOS);
}

win.close_cb = function () {
    win.visible = 'NO';
    return IUP_IGNORE;
}

setInterval(async () => {
    const isRunning = (await $`tasklist /fi "IMAGENAME eq flatout2.exe" /fo csv`.text()).toLowerCase().indexOf('flatout2.exe') != -1;
    if (!isRunning) process.exit();
}, 1000);

setInterval(async () => {
    feedXidiDataFlatOut2(minRangeValue, maxRangeValue, isBindingKey);

    iup.loopStep();
}, 1);