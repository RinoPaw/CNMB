/*
 * CNMB 12.5.5: passive Java-side DEC dialog call-stack tracer.
 * This hooks activity launch routing solely to log the call stack when
 * the target launches com.a.b.c.DECMsgDialog. It never modifies returned
 * detection values, intent extras, or app state.
 * IMPORTANT: injection may itself trigger app anti-instrumentation checks.
 */
'use strict';

if (!Java.available) {
  console.log('[CNMB] Java runtime unavailable');
} else {
  Java.perform(function () {
    const Instrumentation = Java.use('android.app.Instrumentation');
    const Log = Java.use('android.util.Log');
    const Exception = Java.use('java.lang.Exception');
    const target = 'com.a.b.c.DECMsgDialog';
    let reported = false;
    let hooks = 0;

    function dumpDecMethods() {
      try {
        const groups = Java.enumerateMethods('com.a.b.c.*!*/s');
        let count = 0;
        for (const group of groups) {
          for (const klass of group.classes) {
            if (klass.name.indexOf('DEC') < 0 &&
                klass.name.indexOf('DeviceEnvironmentCheck') < 0) continue;
            console.log('[CNMB] class ' + klass.name);
            for (const method of klass.methods) {
              // Print signatures only: no arguments or return values.
              console.log('    ' + method);
              if (++count >= 120) {
                console.log('[CNMB] method listing truncated at 120');
                return;
              }
            }
          }
        }
        console.log('[CNMB] DEC method signatures listed: ' + count);
      } catch (error) {
        console.log('[CNMB] method enumeration error: ' + error);
      }
    }

    for (const overload of Instrumentation.execStartActivity.overloads) {
      const index = overload.argumentTypes.findIndex(function (arg) {
        return arg.className === 'android.content.Intent';
      });
      if (index < 0) continue;
      overload.implementation = function () {
        try {
          const intent = arguments[index];
          if (intent !== null) {
            const component = intent.getComponent();
            if (component !== null && String(component.getClassName()) === target) {
              if (!reported) {
                reported = true;
                console.log('[CNMB] DECMsgDialog launch intercepted');
                console.log('[CNMB] Java stack:\n' + Log.getStackTraceString(Exception.$new()));
                // Run after the current JNI/Java hook has returned.
                setImmediate(function () { Java.perform(dumpDecMethods); });
              }
            }
          }
        } catch (error) {
          console.log('[CNMB] instrumentation observer error: ' + error);
        }
        return overload.apply(this, arguments);
      };
      hooks++;
    }
    console.log('[CNMB] Instrumentation.execStartActivity overloads traced: ' + hooks);
    console.log('[CNMB] Waiting for ' + target + ' (no detection bypass)');
  });
}
