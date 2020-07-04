using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ChromeIPCSniffer
{
    public static class FunctionExtensions
    {
        // returns true if the call went to completion successfully, false otherwise
        public static bool RunWithAbort(this Action action, int milliseconds) => RunWithAbort(action, new TimeSpan(0, 0, 0, 0, milliseconds));
        public static bool RunWithAbort(this Action action, TimeSpan delay)
        {
            if (action == null)
                throw new ArgumentNullException(nameof(action));

            var source = new CancellationTokenSource(delay);
            var success = false;
            var handle = IntPtr.Zero;
            var fn = new Action(() =>
            {
                //using (source.Token.Register(() => ))
                {
                    action();
                    success = true;
                }
            });

            handle = CreateThread(IntPtr.Zero, IntPtr.Zero, fn, IntPtr.Zero, 0, out var id);
            WaitForSingleObject(handle, 100 + (int)delay.TotalMilliseconds);
            //TerminateThread(handle, 0);
            CloseHandle(handle);
            return success;
        }

        // returns what's the function should return if the call went to completion successfully, default(T) otherwise
        public static T RunWithAbort<T>(this Func<T> func, int milliseconds) => RunWithAbort(func, new TimeSpan(0, 0, 0, 0, milliseconds));
        public static T RunWithAbort<T>(this Func<T> func, TimeSpan delay)
        {
            if (func == null)
                throw new ArgumentNullException(nameof(func));

            var source = new CancellationTokenSource(delay);
            var item = default(T);
            var handle = IntPtr.Zero;
            var fn = new Action(() =>
            {
                using (source.Token.Register(() => TerminateThread(handle, 0)))
                {
                    item = func();
                }
            });

            handle = CreateThread(IntPtr.Zero, IntPtr.Zero, fn, IntPtr.Zero, 0, out var id);
            WaitForSingleObject(handle, 100 + (int)delay.TotalMilliseconds);
            CloseHandle(handle);
            return item;
        }

        [DllImport("kernel32")]
        private static extern bool TerminateThread(IntPtr hThread, int dwExitCode);

        [DllImport("kernel32")]
        private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, IntPtr dwStackSize, Delegate lpStartAddress, IntPtr lpParameter, int dwCreationFlags, out int lpThreadId);

        [DllImport("kernel32")]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32")]
        private static extern int WaitForSingleObject(IntPtr hHandle, int dwMilliseconds);
    }
}
