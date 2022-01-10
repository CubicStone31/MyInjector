//using System;
//using System.Collections.Generic;
//using System.Linq;
//using System.Text;
//using System.Threading.Tasks;
//using System.Runtime.InteropServices;

//namespace MyInjector.Injection
//{
//    public static class Native
//    {
//        [DllImport("kernel32.dll", SetLastError = true)]
//        public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

//        [DllImport("kernel32.dll", SetLastError = true)]
//        [return: MarshalAs(UnmanagedType.Bool)]
//        public static extern bool CloseHandle(IntPtr hObject);

//        [DllImport("kernel32.dll")]
//        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

//        [DllImport("kernel32.dll", SetLastError = true)]
//        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

//        [DllImport("kernel32.dll")]
//        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);
//    }

//    public class HandleWrapper : IDisposable
//    {
//        public HandleWrapper(IntPtr handle)
//        {
//            HandleValue = handle;
//        }

//        public void Dispose()
//        {
//            if (IsValid)
//                Native.CloseHandle(HandleValue);
//        }

//        public IntPtr HandleValue { get; private set; } = IntPtr.Zero;

//        public bool IsValid
//        {
//            get
//            {
//                if (HandleValue == IntPtr.Zero || HandleValue.ToInt64() == -1)
//                {
//                    return false;
//                }
//                return true;
//            }
//        }
//    }


//    public static class InjectionOperation
//    {
//        public static HandleWrapper OpenProcessHandle(int pid, uint access)
//        {
//            var handle = Native.OpenProcess(access, false, pid);
//            return new HandleWrapper(handle);
//        }

//        public static HandleWrapper StealProcessHandle(int pid, uint access)
//        {
//            throw new NotImplementedException();
//        }

//        public static bool WriteProcessMemory(IntPtr handle, IntPtr address, byte[] data, out IntPtr bytesWritten)
//        {
//           return Native.WriteProcessMemory(handle, address, data, data.Length, out bytesWritten);
//        }

//        public static bool ReadProcessMemory(IntPtr handle, IntPtr address, int length, out byte[] result, out IntPtr bytesRead)
//        {
//            result = new byte[length];
//            return Native.ReadProcessMemory(handle, address, result, length, out bytesRead);
//        }

//        public static HandleWrapper CreateRemoteThread(IntPtr handle, IntPtr startAddress, IntPtr param, bool suspended, out IntPtr threadId)
//        {
//            var threadHandle = Native.CreateRemoteThread(handle, 0, 0, startAddress, param, (uint)(suspended ? 4 : 0), out threadId);
//            return new HandleWrapper(threadHandle);
//        }
//    }
//}
