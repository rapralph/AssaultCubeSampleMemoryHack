using System.Diagnostics;
using System.Runtime.InteropServices;

namespace AssaultCube
{
    internal class Program
    {

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern UIntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        const uint PROCESS_ALL_ACCESS = (0x1F0FFF);


        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(
        UIntPtr hProcess,
        UIntPtr lpBaseAddress,
        [Out] byte[] lpBuffer,
        int dwSize,
        ref int lpNumberOfBytesRead);


        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(
        UIntPtr hProcess,
        UIntPtr lpBaseAddress,
        [Out] byte[] lpBuffer,
        int dwSize,
        ref int lpNumberOfBytesRead);


        static void Main(string[] args)
        {

            //AMMO
            uint[] ammoOffsets = { 0x364, 0x14, 0x0 };
            SetNewValue("ac_client", "ac_client.exe", 80000, ammoOffsets);


            //HP
            uint[] hpOffsets = { 0xEC };
            SetNewValue("ac_client", "ac_client.exe", 5999, hpOffsets);

        }



        private static int GetProcID(string processName) 
        {
            Process[] processes = Process.GetProcesses();
            
            return processes.Where(a => a.ProcessName.Equals(processName)).FirstOrDefault().Id;

        }

        private static IntPtr GetModuleBaseAddress(int processId, string moduleName) 
        {

            Process process = Process.GetProcessById(processId);

            return process.Modules.Cast<ProcessModule>().FirstOrDefault(a => a.ModuleName.Equals(moduleName)).BaseAddress;

        }


        private static UIntPtr FindDMAAddy(UIntPtr hProcess, UIntPtr dynamicPtrBaseAddr, uint[] offSets, out long memoryVal) 
        {

            UIntPtr addr = dynamicPtrBaseAddr;
            var buffer = new byte[4];
            var lpNumberOfBytesRead = 0;
           
            ReadProcessMemory(hProcess, addr, buffer, buffer.Length, ref lpNumberOfBytesRead);
            UIntPtr newValue = (UIntPtr)BitConverter.ToUInt32(buffer, 0);

            foreach (uint val in offSets)
            {
               
                    addr = UIntPtr.Add(newValue, (int)val);
                    ReadProcessMemory(hProcess, addr, buffer, buffer.Length, ref lpNumberOfBytesRead);
                    newValue = (UIntPtr)BitConverter.ToUInt32(buffer, 0);
            }


            memoryVal = (long)newValue;
            return addr;
        }


        private static void SetNewValue(string processName, string moduleName,  int newValue, uint[] offSets) {

            long value = 0;
            int lpNumberOfBytesRead = 0;

            var procId = GetProcID(processName);
            var moduleBaseAddr = (UIntPtr)(long)GetModuleBaseAddress(procId, moduleName);

            UIntPtr hProcess = (UIntPtr)0;
            hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, (uint)procId);


            UIntPtr dynamicPtrBaseAddr = UIntPtr.Add(moduleBaseAddr, 0x17E254);

            UIntPtr ammoAddr = FindDMAAddy(hProcess, dynamicPtrBaseAddr, offSets, out value);


            byte[] ammoByte = BitConverter.GetBytes(newValue);
            WriteProcessMemory(hProcess, ammoAddr, ammoByte, ammoByte.Length, ref lpNumberOfBytesRead);

        }


    }
}