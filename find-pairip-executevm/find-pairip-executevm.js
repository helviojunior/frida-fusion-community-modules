/*
Script and technique based on Yayınlayan byteria study
Original blog: https://blog.byterialab.com/reversing-googles-new-vm-based-integrity-protection-pairip/
Original Source code: https://gist.github.com/Ahmeth4n/8b0a21228fc2437864bb58b9402180ad
*/

const PAIRIP_DATA = {
    RegisterNativesOffset: 0
}

function hookNative() {

    const moduleHandle = Process.findModuleByName('libpairipcore.so');
    if (!moduleHandle) {
        fusion_sendMessage("E", "libpairipcore.so not found!");
        return;
    }

    if (RN_HOOK_OFFSET != null && RN_HOOK_OFFSET != undefined && Number.isInteger(RN_HOOK_OFFSET)) PAIRIP_DATA.RegisterNativesOffset = RN_HOOK_OFFSET;

    if (PAIRIP_DATA.RegisterNativesOffset !== 0) {
        hookRegisterNatives(moduleHandle, PAIRIP_DATA.RegisterNativesOffset);
    }


    if (PAIRIP_DATA.RegisterNativesOffset == 0) {

        const jniOnLoad = moduleHandle.findExportByName("JNI_OnLoad");
        if (!jniOnLoad) {
            fusion_sendMessage("E", "JNI_OnLoad not found!");
            return;
        }

        fusion_sendMessage("W", "JNI_OnLoad found: " + jniOnLoad);

        fusion_sendKeyValueData("libpairipcore.so!JNI_OnLoad", [
            {key: "JNI_OnLoad", value: jniOnLoad}
        ]);


        var hook3 = Interceptor.attach(jniOnLoad, {
            onEnter: function(args) {
                fusion_sendMessage("D", "JNI_OnLoad called");
                
                let frames;
                try {
                    frames = Thread.backtrace(this.context, Backtracer.ACCURATE);
                } catch (e) {
                    frames = Thread.backtrace(this.context, Backtracer.FUZZY);
                }

                const pretty = fusion_formatBacktrace(frames);

                fusion_sendKeyValueData("libpairipcore.so!JNI_OnLoad!call", [
                    {key: "JavaVM_pointer", value: String(args[0])},
                    {key: "reserved", value: String(args[1])},
                    {key: "context", value: String(this.context)},
                    {key: "backtrace", value: pretty}, // <— pilha simbólica
                    {key: "backtrace_raw", value: frames.map(String)}  // <— opcional: endereços puros
                ]);

                startStalker(this.threadId, Process.getModuleByName('libpairipcore.so'));
            },
            onLeave: function(retval) {
                fusion_sendMessage("I", `JNI_OnLoad return value: ${retval}`);
                stopStalker(this.threadId);
                hook3.detach();
            }
        });
    }
    

}


function startStalker(threadId, targetModule){

    Stalker.follow(threadId, {
        events: { call: true },
        transform: function(iterator){
            var instruction;
            while(((instruction = iterator.next()) != null)){
                if (PAIRIP_DATA.RegisterNativesOffset !== 0) { iterator.keep(); continue; }

                if(instruction.address <= targetModule.base.add(targetModule.size) && 
                   instruction.address >= targetModule.base){
                    var offset = instruction.address.sub(targetModule.base);
                    var l1DebugText = `${offset}: ${instruction.toString()}`;
                    
                    if (instruction.mnemonic.startsWith('bl') || instruction.mnemonic.startsWith('b.')) {
                        const targetAddr = instruction.address;
                        iterator.putCallout(function(context) {
                            var l2DebugText = `    x8=${context.x8.toString(16)}`;
                            l2DebugText += `\n    x0=${context.x0.toString(16)}`;

                            var moduleDetails = Process.findModuleByAddress(context.x8);
                            if (moduleDetails) {

                                var symbol = DebugSymbol.fromAddress(context.x8);
                                if (symbol && symbol.name && symbol.name.indexOf("0x") == -1) {
                                    if (String(symbol.name).includes("RegisterNatives")){

                                        var l3DebugText = `    Module: ${moduleDetails.name}`;
                                        l3DebugText += `\n    Base: ${moduleDetails.base}`;
                                        l3DebugText += `\n    Offset in module: 0x${context.x8.sub(moduleDetails.base).toString(16)}`;
                                        l3DebugText += `\n    Symbol: ${symbol.name}`;

                                        fusion_sendMessage("I", `${l1DebugText}\n${l2DebugText}\n${l3DebugText}`);

                                        if (PAIRIP_DATA.RegisterNativesOffset == 0) {

                                            fusion_sendKeyValueData("libpairipcore.so!RegisterNatives", [
                                                {key: "Offset", value: String(offset)},
                                                {key: "Module", value: String(moduleDetails.name)},
                                                {key: "ModuleBase", value: String(moduleDetails.base)},
                                                {key: "ModuleOffset", value: context.x8.sub(moduleDetails.base).toString(16)}
                                            ]);


                                            /*
                                            fusion_sendMessage("I", `RegisterNatives offset found! Locking thread!`);
                                                              

                                            const t0 = Date.now();
                                            while (true) {
                                                Thread.sleep(0.005); // 5 ms
                                                if (Date.now() - t0 > 30000) break; // timeout 1s (ajuste se precisar)
                                            }*/

                                            try { Stalker.unfollow(threadId); Stalker.garbageCollect(); } catch (_) {}

                                        }

                                    }
                                }
                            }
                        });
                    }
                
                }
                iterator.keep();
            }
        }
    });
}

function hookRegisterNatives(moduleHandle, offset){

    if (!moduleHandle) {
        fusion_sendMessage("E", "libpairipcore.so not found!");
        return;
    }

    const registerNativesAddress = moduleHandle.base.add(offset)

    PAIRIP_DATA.RegisterNativesOffset = fusion_normalizePtr(offset);
    PAIRIP_DATA.RegisterNativesAddress = registerNativesAddress;

    fusion_sendMessage("I", `Hooking RegisterNatives at ${PAIRIP_DATA.RegisterNativesOffset}, offset ${PAIRIP_DATA.RegisterNativesAddress}`);

    Interceptor.attach(registerNativesAddress, {
        onEnter: function(args) {
            var callText = "";
            callText += "RegisterNatives called\n";
            callText += `    JNIEnv*: ${this.context.x0}\n`;
            callText += `    jclass: ${this.context.x1}\n`;
            callText += `    JNINativeMethod*: ${this.context.x2}\n`;
            callText += `    nMethods: ${this.context.x3}\n`;

            const nMethods = this.context.x3.toInt32();
            const methods = this.context.x2;
            
            for(let i = 0; i < nMethods; i++) {
                const methodInfo = methods.add(i * Process.pointerSize * 3);
                const name = methodInfo.readPointer().readCString();
                const sig = methodInfo.add(Process.pointerSize).readPointer().readCString();
                const fnPtr = methodInfo.add(Process.pointerSize * 2).readPointer();
                const ghidraOffset = ptr(fnPtr).sub(moduleHandle.base).add(0x00100000);

                if (name == "executeVM") {

                    callText += `    Method[${i}]:\n`;
                    callText += `        name: ${name}\n`;
                    callText += `        signature: ${sig}\n`;
                    callText += `        fnPtr: ${fnPtr}\n`;
                    callText += `        Ghidra offset: 0x${ghidraOffset.toString(16)}\n`;

                    callText += `\n${name} function's memory dump:\n`;
                    const dumpSize = 128;
                    const dumpData = Memory.readByteArray(fnPtr, dumpSize);
                    var b64Dump = "";
                    if (dumpData !== null) {
                      const u8 = new Uint8Array(dumpData); // “byte array” típico
                      b64Dump = fusion_bytesToBase64(u8);
                    }
                    callText += hexdump(dumpData, {
                        offset: 0,
                        length: dumpSize,
                        header: true,
                        ansi: false
                    });
                    fusion_sendMessage("D", callText);

                    let frames;
                    try {
                        frames = Thread.backtrace(this.context, Backtracer.ACCURATE);
                    } catch (e) {
                        frames = Thread.backtrace(this.context, Backtracer.FUZZY);
                    }

                    const pretty = fusion_formatBacktrace(frames);

                    fusion_sendKeyValueData("libpairipcore.so!RegisterNatives!call!executeVM", [
                        {key: "Name", value: `${name}`},
                        {key: "Signature", value: `${sig}`},
                        {key: "Offset", value: `0x${ghidraOffset.toString(16)}`},
                        {key: "MemoryDump", value: b64Dump},
                        {key: "Description", value: callText},
                        {key: "backtrace", value: pretty}, // <— pilha simbólica
                        {key: "backtrace_raw", value: frames.map(String)}  // <— opcional: endereços puros
                    ]);

                    
                }

            }
        },
        onLeave: function(retval) {
            fusion_sendMessage("D", "RegisterNatives finished, return value is:" + retval);
        }
    });
}

function stopStalker(threadId){
    Stalker.unfollow(threadId);
    Stalker.flush();
}

var libnative_loaded = 0;
var do_dlopen = null;
var call_ctor = null;

Process.findModuleByName('linker64').enumerateSymbols().forEach(function (sym) {
    if (sym.name.indexOf('do_dlopen') >= 0) {
        do_dlopen = sym.address;
    } else if (sym.name.indexOf('call_constructor') >= 0) {
        call_ctor = sym.address;
    }
});

try{
    Interceptor.attach(do_dlopen, function () {
        var libraryPath = this.context.x0.readCString();
        if (libraryPath.indexOf('libpairipcore.so') > -1) {
            fusion_sendMessage("I", `libpairipcore.so loaded.`);
            
            Interceptor.attach(call_ctor, function () {
                if (libnative_loaded == 0) {
                    var native_mod = Process.findModuleByName('libpairipcore.so');
                    fusion_sendMessage("I", `libpairipcore.so loaded @${native_mod.base}`);
                    fusion_sendKeyValueData("libpairipcore.so!load", [
                        {key: "Base", value: `${native_mod.base}`}
                    ]);

                    Interceptor.detachAll();

                    hookNative();
                }
                libnative_loaded = 1;
            });
        }
    });
} catch (err) {
    fusion_sendMessage("D", `${err}`);
}

