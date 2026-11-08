'use strict';

const activationPrefix = '010400040004';
const activationSuffix = '00000000000028';
const readyEvent = 'INK_NFC_MIFARE_COMPAT_READY';
let enabled = true;
let matches = 0;

const library = Process.getModuleByName('libstnfc_nci_jni.so');
const exported = library.enumerateExports();

function symbol(part) {
    const matches = exported.filter(entry => entry.name.includes(part));
    if (matches.length !== 1) throw new Error('Ambiguous native symbol: ' + part);
    return matches[0].address;
}

function bytesToHex(address, length) {
    return Array.from(new Uint8Array(address.readByteArray(length)), value => value.toString(16).padStart(2, '0')).join('').toUpperCase();
}

const readPending = new NativeFunction(symbol('getNumDiscNtfEv'), 'int', ['pointer']);
const writePending = new NativeFunction(symbol('setNumDiscNtfEi'), 'void', ['pointer', 'int']);
const hook = Interceptor.attach(symbol('createNativeNfcTag'), {
    onEnter(args) {
        if (!enabled) return;
        const activation = bytesToHex(args[1], 17);
        const pendingBefore = readPending(args[0]);
        if (!activation.startsWith(activationPrefix) || !activation.endsWith(activationSuffix) || pendingBefore !== 1) return;
        const targetUid = activation.substring(12, 20);
        writePending(args[0], 0);
        matches++;
        send({event: 'MIFARE_COMPAT_APPLIED', uid: targetUid, matches, pendingBefore, pendingAfter: readPending(args[0])});
    }
});

send(readyEvent);
setTimeout(() => {
    enabled = false;
    hook.detach();
    send('INK_NFC_MIFARE_COMPAT_EXPIRED');
}, 240000);
