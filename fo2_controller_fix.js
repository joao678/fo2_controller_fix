import { dlopen } from "bun:ffi";
import { parseArgs } from "util";
import shared_memory_lib from "./lib/shared_memory.dll" with { type: "file" };
import { iup } from "iupjs";

const {
    writeSharedMemXidi,
    initSharedMem
} = dlopen(shared_memory_lib, {
    writeSharedMemXidi: {
        args: ["cstring"],
        returns: "i32",
    },
    initSharedMem: {
        args: [],
    }
}).symbols;

const memoryjs = require('memoryjs');
const {
    SDL_Init,
    SDL_GameControllerOpen,
    SDL_GameControllerUpdate,
    SDL_GameControllerGetButton,
    SDL_GameControllerGetAxis,
    SDL_CONTROLLER_BUTTON_INVALID,
    SDL_CONTROLLER_BUTTON_A,
    SDL_CONTROLLER_BUTTON_B,
    SDL_CONTROLLER_BUTTON_X,
    SDL_CONTROLLER_BUTTON_Y,
    SDL_CONTROLLER_BUTTON_BACK,
    SDL_CONTROLLER_BUTTON_GUIDE,
    SDL_CONTROLLER_BUTTON_START,
    SDL_CONTROLLER_BUTTON_LEFTSTICK,
    SDL_CONTROLLER_BUTTON_RIGHTSTICK,
    SDL_CONTROLLER_BUTTON_LEFTSHOULDER,
    SDL_CONTROLLER_BUTTON_RIGHTSHOULDER,
    SDL_CONTROLLER_BUTTON_DPAD_UP,
    SDL_CONTROLLER_BUTTON_DPAD_DOWN,
    SDL_CONTROLLER_BUTTON_DPAD_LEFT,
    SDL_CONTROLLER_BUTTON_DPAD_RIGHT,
    SDL_CONTROLLER_BUTTON_MISC1,
    SDL_CONTROLLER_BUTTON_PADDLE1,
    SDL_CONTROLLER_BUTTON_PADDLE2,
    SDL_CONTROLLER_BUTTON_PADDLE3,
    SDL_CONTROLLER_BUTTON_PADDLE4,
    SDL_CONTROLLER_BUTTON_TOUCHPAD,
    SDL_CONTROLLER_BUTTON_MAX,
    SDL_CONTROLLER_AXIS_INVALID,
    SDL_CONTROLLER_AXIS_LEFTX,
    SDL_CONTROLLER_AXIS_LEFTY,
    SDL_CONTROLLER_AXIS_RIGHTX,
    SDL_CONTROLLER_AXIS_RIGHTY,
    SDL_CONTROLLER_AXIS_TRIGGERLEFT,
    SDL_CONTROLLER_AXIS_TRIGGERRIGHT,
    SDL_CONTROLLER_AXIS_MAX,

    SDL_HINT_ACCELEROMETER_AS_JOYSTICK,
    SDL_HINT_JOYSTICK_RAWINPUT,
    SDL_HINT_JOYSTICK_HIDAPI_PS5,
    SDL_HINT_JOYSTICK_HIDAPI_PS4,
    SDL_HINT_JOYSTICK_HIDAPI_PS5_PLAYER_LED,
    SDL_HINT_JOYSTICK_HIDAPI_PS4_RUMBLE,
    SDL_HINT_JOYSTICK_HIDAPI_PS5_RUMBLE,
    SDL_HINT_JOYSTICK_ALLOW_BACKGROUND_EVENTS,
    SDL_GameControllerSetLED,
    SDL_SetHint,
    SDL_GameControllerSetSensorEnabled,
    SDL_HINT_JOYSTICK_THREAD,
    SDL_INIT_GAMECONTROLLER,
    SDL_Delay,
} = require('./sdl');
const processName = "FlatOut2.exe";

let flatout2handle = null;

try {
    flatout2handle = memoryjs.openProcess(processName);
} catch (error) {
    iup.messageError(null, 'FlatOut 2 process not found, please start FlatOut2.exe');
    process.exit()
}

const yellow = '\x1b[33m'; // ANSI code for yellow
const orange = '\x1b[38;2;255;165;0m'; // ANSI code for orange (RGB: 255, 165, 0)
const reset = '\x1b[0m'; // ANSI code to reset

console.log(`Controller fix running, you can go back to ${yellow}Flat${orange}Out 2${reset} now.`);

let color = [0, 0, 255];

let argValues = parseArgs({
    args: Bun.argv,
    strict: true,
    allowPositionals: true,
    options: {
        "extra-features": { type: 'boolean' },
    }
}).values;

//Extra features such as PlayStation controller colors, and some others in the future.
let extraFeatures = !!argValues['extra-features'];

SDL_SetHint(Buffer.from(SDL_HINT_JOYSTICK_THREAD, "utf8"), Buffer.from("1", "utf8"));
SDL_SetHint(Buffer.from(SDL_HINT_JOYSTICK_RAWINPUT, "utf8"), Buffer.from("0", "utf8"));
SDL_SetHint(Buffer.from(SDL_HINT_JOYSTICK_ALLOW_BACKGROUND_EVENTS, "utf8"), Buffer.from("1", "utf8"));
if (extraFeatures) SDL_SetHint(Buffer.from(SDL_HINT_JOYSTICK_HIDAPI_PS5, "utf8"), Buffer.from("1", "utf8"));
if (extraFeatures) SDL_SetHint(Buffer.from(SDL_HINT_JOYSTICK_HIDAPI_PS4, "utf8"), Buffer.from("1", "utf8"));
if (extraFeatures) SDL_SetHint(Buffer.from(SDL_HINT_JOYSTICK_HIDAPI_PS5_PLAYER_LED, "utf8"), Buffer.from("1", "utf8"));
if (extraFeatures) SDL_SetHint(Buffer.from(SDL_HINT_JOYSTICK_HIDAPI_PS4_RUMBLE, "utf8"), Buffer.from("1", "utf8"));
if (extraFeatures) SDL_SetHint(Buffer.from(SDL_HINT_JOYSTICK_HIDAPI_PS5_RUMBLE, "utf8"), Buffer.from("1", "utf8"));

SDL_Init(SDL_INIT_GAMECONTROLLER);
const ctrl = SDL_GameControllerOpen(0);

if (extraFeatures) SDL_GameControllerSetSensorEnabled(ctrl, 1, Buffer.from("1", "utf8"));
if (extraFeatures) SDL_GameControllerSetSensorEnabled(ctrl, 2, Buffer.from("1", "utf8"));

const controllerTemplate = {
    b1: 0,
    b2: 0,
    b3: 0,
    b4: 0,
    b5: 0,
    b6: 0,
    b7: 0,
    b8: 0,
    b9: 0,
    b10: 0,
    b11: 0,
    b12: 0,
    b13: 0,
    b14: 0,
    b15: 0,
    b16: 0,
    X: 0,
    Y: 0,
    Z: 0,
    RotX: 0,
    RotY: 0,
    RotZ: 0,
    Up: 0,
    Down: 0,
    Left: 0,
    Right: 0
}

let controllersState = [{
    keyboard: {
        released: [],
        pressed: []
    },
    mouse: {
        left: 0,
        right: 0,
        x1: 0,
        x2: 0,
        middle: 0,
        mouseMove: 0,
        x: 0,
        y: 0,
        wheelX: 0,
        wheelY: 0,
    },
    ...controllerTemplate
},
{
    ...controllerTemplate
},
{
    ...controllerTemplate
},
{
    ...controllerTemplate
}];

function remap(value, fromMin, fromMax, toMin, toMax) {
    return toMin + (value - fromMin) * (toMax - toMin) / (fromMax - fromMin);
}

function interpolateColor(value) {
    const green = [0, 255, 0];
    const red = [255, 0, 0];

    value = Math.max(0, Math.min(1, value));

    const interpolatedColor = [
        Math.round((1 - value) * green[0] + value * red[0]),
        Math.round((1 - value) * green[1] + value * red[1]),
        Math.round((1 - value) * green[2] + value * red[2])
    ];

    return interpolatedColor;
}

initSharedMem();

let boostButtonDelay = 0;
let debugPrint = false;
let bindTime = 0;

export function feedXidiDataFlatOut2(minValue, maxValue, isBindingKey) {
    if (isBindingKey) {
        if (bindTime < 30) bindTime += 1;
        if (bindTime >= 30) feedXidiDataFlatOut2_no_menu();
        return;
    } else {
        bindTime = 0;
    };

    let isSimulationPaused = !!memoryjs.readMemory(flatout2handle.handle, 9282836, memoryjs.INT8),
        isInsideCar = !!memoryjs.readMemory(flatout2handle.handle, 9282664, memoryjs.INT32),
        isInDemoOrReplayMode = memoryjs.readMemory(flatout2handle.handle, 9288716, memoryjs.INT32) === 2,
        isInUiInsideAnyEvent = !!memoryjs.readMemory(flatout2handle.handle, 9282796, memoryjs.INT32);

    SDL_GameControllerUpdate();

    if (isSimulationPaused || isInUiInsideAnyEvent || isInDemoOrReplayMode) {
        boostButtonDelay = 0;
        SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_B) ? controllersState[0].keyboard.pressed = [...controllersState[0].keyboard.pressed, 0x01] : controllersState[0].keyboard.released = [...controllersState[0].keyboard.released, 0x01];
        SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_A) ? controllersState[0].keyboard.pressed = [...controllersState[0].keyboard.pressed, 0x1C] : controllersState[0].keyboard.released = [...controllersState[0].keyboard.released, 0x1C];
        SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_X) ? controllersState[0].keyboard.pressed = [...controllersState[0].keyboard.pressed, 0xD3] : controllersState[0].keyboard.released = [...controllersState[0].keyboard.released, 0xD3];
        SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_DPAD_UP) ? controllersState[0].keyboard.pressed = [...controllersState[0].keyboard.pressed, 0xC8] : controllersState[0].keyboard.released = [...controllersState[0].keyboard.released, 0xC8];
        SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_DPAD_DOWN) ? controllersState[0].keyboard.pressed = [...controllersState[0].keyboard.pressed, 0xD0] : controllersState[0].keyboard.released = [...controllersState[0].keyboard.released, 0xD0];
        SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_DPAD_LEFT) ? controllersState[0].keyboard.pressed = [...controllersState[0].keyboard.pressed, 0xCB] : controllersState[0].keyboard.released = [...controllersState[0].keyboard.released, 0xCB];
        SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_DPAD_RIGHT) ? controllersState[0].keyboard.pressed = [...controllersState[0].keyboard.pressed, 0xCD] : controllersState[0].keyboard.released = [...controllersState[0].keyboard.released, 0xCD];
        color = [0, 0, 255];
    } else {
        if (boostButtonDelay < 50) boostButtonDelay += 1;
        SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_START) ? controllersState[0].keyboard.pressed = [...controllersState[0].keyboard.pressed, 0x01] : controllersState[0].keyboard.released = [...controllersState[0].keyboard.released, 0x01];
        SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_A) ? controllersState[0].keyboard.pressed = [...controllersState[0].keyboard.pressed, 0x1C] : controllersState[0].keyboard.released = [...controllersState[0].keyboard.released, 0x1C];
        controllersState[0].keyboard.released = [...controllersState[0].keyboard.released, 0xCB];
        controllersState[0].keyboard.released = [...controllersState[0].keyboard.released, 0xCD];
        controllersState[0].keyboard.released = [...controllersState[0].keyboard.released, 0xD3];

        const globalStruct = memoryjs.readMemory(flatout2handle.handle, flatout2handle.modBaseAddr + 0x296DC8, memoryjs.UINT32);
        if (globalStruct) {
            const actorsPtrArray = memoryjs.readMemory(flatout2handle.handle, globalStruct + 0x14, memoryjs.UINT32);
            const playerActorInfo = memoryjs.readMemory(flatout2handle.handle, actorsPtrArray + 0 * 4, memoryjs.UINT32);
            const vehicleInfo = memoryjs.readMemory(flatout2handle.handle, playerActorInfo + 0x33C, memoryjs.UINT32);
            const damageLevel = memoryjs.readMemory(flatout2handle.handle, vehicleInfo + 0x6AA0, memoryjs.FLOAT);
            color = interpolateColor(damageLevel);
        }

        if (boostButtonDelay >= 50) {
            controllersState[0].b1 = SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_A)
        } else {
            controllersState[0].b1 = 0;
        };
        controllersState[0].b2 = SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_B);
        controllersState[0].b3 = SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_X);
        controllersState[0].b4 = SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_Y);
        controllersState[0].b5 = SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_LEFTSHOULDER);
        controllersState[0].b6 = SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_RIGHTSHOULDER);
        controllersState[0].b7 = 0;
        controllersState[0].b8 = 0;
        controllersState[0].b9 = SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_BACK);
        controllersState[0].b10 = SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_START);
        controllersState[0].b11 = SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_LEFTSTICK);
        controllersState[0].b12 = SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_RIGHTSTICK);
        controllersState[0].b13 = 0;
        controllersState[0].b14 = 0;
        controllersState[0].b15 = 0;
        controllersState[0].b16 = 0;
        controllersState[0].X = remap(SDL_GameControllerGetAxis(ctrl, SDL_CONTROLLER_AXIS_LEFTX), -32768, 32767, minValue, maxValue);
        controllersState[0].Y = remap(SDL_GameControllerGetAxis(ctrl, SDL_CONTROLLER_AXIS_LEFTY), -32768, 32767, minValue, maxValue);

        if (!isInsideCar) {
            controllersState[0].Dial = remap(SDL_GameControllerGetAxis(ctrl, SDL_CONTROLLER_AXIS_LEFTY) / 2, -32768, 32767, minValue, maxValue);
        } else {
            //accel
            controllersState[0].Slider = SDL_GameControllerGetAxis(ctrl, SDL_CONTROLLER_AXIS_TRIGGERRIGHT);
        }

        controllersState[0].RotX = 0;
        controllersState[0].RotY = 0;

        if (!isInsideCar) {
            controllersState[0].Slider = remap(SDL_GameControllerGetAxis(ctrl, SDL_CONTROLLER_AXIS_LEFTY) / 2, -32768, 32767, minValue, maxValue) * -1;
        } else {
            //brake
            controllersState[0].Dial = SDL_GameControllerGetAxis(ctrl, SDL_CONTROLLER_AXIS_TRIGGERLEFT);
        }

        controllersState[0].Up = SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_DPAD_UP);
        controllersState[0].Down = SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_DPAD_DOWN);
        controllersState[0].Left = SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_DPAD_LEFT);
        controllersState[0].Right = SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_DPAD_RIGHT);
    }

    writeSharedMemXidi(Buffer.from(JSON.stringify(controllersState) + '\0', "utf8"));

    controllersState[0].keyboard.released = [];
    controllersState[0].keyboard.pressed = [];

    if (extraFeatures) SDL_GameControllerSetLED(ctrl, ...color);
}

function feedXidiDataFlatOut2_no_menu(minValue, maxValue) {
    SDL_GameControllerUpdate();
    if (debugPrint) console.log('controller updated...');

    controllersState[0].b1 = SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_A);
    controllersState[0].b2 = SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_B);
    controllersState[0].b3 = SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_X);
    controllersState[0].b4 = SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_Y);
    controllersState[0].b5 = SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_LEFTSHOULDER);
    controllersState[0].b6 = SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_RIGHTSHOULDER);
    controllersState[0].b7 = 0;
    controllersState[0].b8 = 0;
    controllersState[0].b9 = SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_BACK);
    controllersState[0].b10 = SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_START);
    controllersState[0].b11 = SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_LEFTSTICK);
    controllersState[0].b12 = SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_RIGHTSTICK);
    controllersState[0].b13 = 0;
    controllersState[0].b14 = 0;
    controllersState[0].b15 = 0;
    controllersState[0].b16 = 0;

    controllersState[0].X = remap(SDL_GameControllerGetAxis(ctrl, SDL_CONTROLLER_AXIS_LEFTX), -32768, 32767, minValue, maxValue);
    controllersState[0].Y = remap(SDL_GameControllerGetAxis(ctrl, SDL_CONTROLLER_AXIS_LEFTY), -32768, 32767, minValue, maxValue);

    controllersState[0].RotX = remap(SDL_GameControllerGetAxis(ctrl, SDL_CONTROLLER_AXIS_RIGHTX), -32768, 32767, minValue, maxValue);
    controllersState[0].RotY = remap(SDL_GameControllerGetAxis(ctrl, SDL_CONTROLLER_AXIS_RIGHTY), -32768, 32767, minValue, maxValue);

    //brake
    controllersState[0].Slider = SDL_GameControllerGetAxis(ctrl, SDL_CONTROLLER_AXIS_TRIGGERRIGHT);
    //accel
    controllersState[0].Dial = SDL_GameControllerGetAxis(ctrl, SDL_CONTROLLER_AXIS_TRIGGERLEFT);

    controllersState[0].Up = SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_DPAD_UP);
    controllersState[0].Down = SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_DPAD_DOWN);
    controllersState[0].Left = SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_DPAD_LEFT);
    controllersState[0].Right = SDL_GameControllerGetButton(ctrl, SDL_CONTROLLER_BUTTON_DPAD_RIGHT);
    if (debugPrint) console.log('virtual controller set...');

    writeSharedMemXidi(Buffer.from(JSON.stringify(controllersState) + '\0', "utf8"));

    controllersState[0].keyboard.released = [];
    controllersState[0].keyboard.pressed = [];

    if (debugPrint) console.log('string sent...');
    if (extraFeatures) SDL_GameControllerSetLED(ctrl, ...color);
    if (debugPrint) console.log('color set...');
}