using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;

namespace MyInjector.Injection
{
    public class InjectionNode
    {
        public string Name { get; set; }
        public CandidateMethod[] Candidates { get; set; }
        public int DefaultCandidate { get; set; } = 0;
    }

    public class CandidateMethod
    { 
        public string Name { get; set; }
        public string Description { get; set; }
    }

    public class MajorMethod : CandidateMethod
    {
        public InjectionNode[] MinorNodes { get; set; }
    }

    public class MajorNode : InjectionNode
    { 
        public MajorMethod[] MajorCandidates
        {
            get
            {
                List<MajorMethod> ret = new List<MajorMethod>();
                foreach (var method in Candidates)
                {
                    ret.Add(method as MajorMethod);
                }
                return ret.ToArray();
            }
        }
    }

    public static class InjectionMethodManager
    {
        public static MajorNode MajorNode
        {
            get
            {
                if (_majorNode is null)
                {
                    InitNodes();
                }
                return _majorNode;
            }
        }

        public static void InitNodes()
        {
            CandidateMethod ProcessAccess_OpenProcess = new CandidateMethod
            {
                Name = "OpenProcess",
                Description = "Get process handle by OpenProcess()."
            };
            CandidateMethod ProcessAccess_StealToken = new CandidateMethod
            {
                Name = "Duplicate Handle",
                Description = "Get process handle by duplicate a handle from another process."
            };
            CandidateMethod ProcessAccess_Kernel = new CandidateMethod
            {
                Name = "Kernel",
                Description = "Access to target process by the assistance from kernel module."
            };
            InjectionNode Node_ProcessAccess = new InjectionNode
            {
                Name = "Process Access",
                Candidates = new CandidateMethod[] { ProcessAccess_OpenProcess, ProcessAccess_StealToken, ProcessAccess_Kernel }
            };

            CandidateMethod EntryPoint_LoadLibrary = new CandidateMethod
            {
                Name = "LoadLibrary",
                Description = "Entry point: LoadLibrary()."
            };
            CandidateMethod EntryPoint_LdrLoadDll = new CandidateMethod
            {
                Name = "LdrLoadDll",
                Description = "Entry point: LdrLoadDll()."
            };
            CandidateMethod EntryPoint_ManualLoad = new CandidateMethod
            {
                Name = "Manual Load",
                Description = "Entry point: a shell code that load the target dll manually."
            };
            InjectionNode Node_EntryPoint = new InjectionNode
            {
                Name = "Entry Point",
                Candidates = new CandidateMethod[] { EntryPoint_LoadLibrary, EntryPoint_LdrLoadDll, EntryPoint_ManualLoad }
            };

            CandidateMethod GainExecution_RemoteThread = new CandidateMethod
            {
                Name = "CreateRemoteThread",
                Description = "Gain execution using API CreateRemoteThread()."
            };
            CandidateMethod GainExecution_APC = new CandidateMethod
            {
                Name = "QueueUserAPC",
                Description = "Gain execution using API QueueUserAPC()."
            };
            CandidateMethod GainExecution_InstrumentCallback = new CandidateMethod
            {
                Name = "InstrumentCallback",
                Description = "Gain execution by windows's InstrumentCallback."
            };
            InjectionNode Node_GainExecution = new InjectionNode
            {
                Name = "Gain Execution",
                Candidates = new CandidateMethod[] { GainExecution_RemoteThread, GainExecution_APC, GainExecution_InstrumentCallback }
            };

            MajorMethod Major_Common = new MajorMethod
            {
                Name = "Regular",
                Description = "Execute a piece of code in target process's context and load our image.",
                MinorNodes = new InjectionNode[] { Node_ProcessAccess, Node_EntryPoint, Node_GainExecution }
            };
            MajorMethod Major_SetWindowHook = new MajorMethod
            {
                Name = "SetWindowsHook",
                Description = "Injection using API SetWindowsHookEx().",
                MinorNodes = null
            };
            MajorMethod Major_IME = new MajorMethod
            {
                Name = "IME",
                Description = "Injection using Windows Input Method Editor(IME)."
            };
            _majorNode = new MajorNode
            {
                Name = "Method",
                Candidates = new CandidateMethod[] { Major_Common, Major_SetWindowHook, Major_IME }
            };
        }

        public static bool PerformInjection(List<Tuple<InjectionNode, int>> method, int pid, bool isX64, string dllPath, Action<string> logger)
        {
            var isFilePe64 = IsPEFile64(dllPath);
            if (isX64 != isFilePe64)
            {
                logger.Invoke(string.Format("[!] Target process is {0}, but dll file is {1}", isX64 ? "64bit" : "32bit", isFilePe64 ? "64bit" : "32bit"));
                return false;
            }

            string arguments = string.Format("{0} \"{1}\" ", pid, dllPath);
            foreach (var selection in method)
            {
                string name = selection.Item1.Candidates[selection.Item2].Name;
                arguments += string.Format("\"{0}\" ", name);
            }

            var proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "NativeAgent_" + (isX64 ? "x64" : "x86"),
                    Arguments = arguments,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                }
            };
            proc.Start();
            while (!proc.StandardOutput.EndOfStream)
            {
                string output = proc.StandardOutput.ReadLine();
                logger.Invoke(output);
            }
            // proc.WaitForExit();
            if (proc.ExitCode == 0)
            {
                return true;
            }
            logger.Invoke(string.Format("[!] Injection exits with code {0}", proc.ExitCode));
            return false;
        }

        private static bool IsPEFile64(string filePath)
        {
            // See http://www.microsoft.com/whdc/system/platform/firmware/PECOFF.mspx
            // Offset to PE header is always at 0x3C.
            // The PE header starts with "PE\0\0" =  0x50 0x45 0x00 0x00,
            // followed by a 2-byte machine type field (see the document above for the enum).
            //
            FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read);
            BinaryReader br = new BinaryReader(fs);
            fs.Seek(0x3c, SeekOrigin.Begin);
            Int32 peOffset = br.ReadInt32();
            fs.Seek(peOffset, SeekOrigin.Begin);
            UInt32 peHead = br.ReadUInt32();
            if (peHead != 0x00004550) // "PE\0\0", little-endian
                throw new Exception("Can't find PE header");
            var machineType = br.ReadUInt16();
            br.Close();
            fs.Close();
            if (machineType == 0x8664) // x86_64
            {
                return true;
            }
            if (machineType == 0x14c) // i386
            {
                return false;
            }
            throw new Exception("Target is not a supported PE file.");
        }
        
        private static MajorNode _majorNode = null;
    }
}


