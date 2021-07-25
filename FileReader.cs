using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace CVE_2021_36934
{
    //https://gist.github.com/PaulStovell/1696375
    public class FileReader
    {
        public byte[] Read(string fileName)
        {
            var overlapped = new OVERLAPPED();
            overlapped.hEvent = IntPtr.Zero;
            overlapped.OffsetHigh = 0;
            overlapped.Offset = 0;
            overlapped.Pointer = IntPtr.Zero;
            overlapped.Internal = 0;
            overlapped.InternalHigh = 0;

            
            var handle = FileFunctions.CreateFile(fileName, (uint)EFileAccess.GenericRead, (uint)EFileShare.Read, IntPtr.Zero, (uint)ECreationDisposition.OpenExisting, (uint)(EFileAttributes.Overlapped | EFileAttributes.NoBuffering), IntPtr.Zero);
            FileFunctions.GetFileSizeEx(handle, out long lpFileSize);
            //Console.WriteLine(lpFileSize);

            var buffer = new byte[lpFileSize];

            var operation = new PendingReadOperation();
            operation.Buffer = buffer;
            ReadFileCompletionDelegate c = operation.Complete;

            var read = FileFunctions.ReadFileEx(handle, buffer, (uint)buffer.Length, ref overlapped, c);

            //Console.WriteLine(read);
            //Console.WriteLine(Marshal.GetLastWin32Error());

            return buffer;
        }

        public class PendingReadOperation
        {
            public byte[] Buffer;
            public Action<string> Callback;

            public PendingReadOperation()
            {

            }

            public void Complete(uint dwerr, uint dwNumberOfBytesTransfered, ref OVERLAPPED overlapped)
            {
                //Console.WriteLine("XXX");
                //Console.WriteLine("  " + (int)overlapped.InternalHigh);
                //Console.WriteLine("  " + overlapped.Internal);
                //
                //// For some reason, under a debugger this is always 768, and without a debugger it is -1/uint.max
                //Console.WriteLine("  " + (int)dwNumberOfBytesTransfered);
            }
        }
    }

    [StructLayout(LayoutKind.Explicit, Size = 20)]
    public struct OVERLAPPED
    {
        [FieldOffset(0)]
        public uint Internal;

        [FieldOffset(4)]
        public uint InternalHigh;

        [FieldOffset(8)]
        public uint Offset;

        [FieldOffset(12)]
        public uint OffsetHigh;

        [FieldOffset(8)]
        public IntPtr Pointer;

        [FieldOffset(16)]
        public IntPtr hEvent;
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate void ReadFileCompletionDelegate(uint dwErr, uint cbBytesRead, ref OVERLAPPED overlapped);

    public static class FileFunctions
    {
        [DllImport("kernel32.dll")]
        public static extern bool ReadFileEx(IntPtr hFile, [Out] byte[] lpBuffer, uint nNumberOfBytesToRead, [In] ref OVERLAPPED lpOverlapped, ReadFileCompletionDelegate lpCompletionRoutine);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        public static extern IntPtr CreateFile(
              string lpFileName,
              uint dwDesiredAccess,
              uint dwShareMode,
              IntPtr SecurityAttributes,
              uint dwCreationDisposition,
              uint dwFlagsAndAttributes,
              IntPtr hTemplateFile
              );

        [DllImport("kernel32.dll")]
        public static extern uint SleepEx(uint dwMilliseconds, bool bAlertable);
        [DllImport("kernel32.dll")]
        public static extern bool GetFileSizeEx(IntPtr hFile, out long lpFileSize);
    }

    [Flags]
    public enum EFileAccess : uint
    {
        Delete = 0x10000,
        ReadControl = 0x20000,
        WriteDAC = 0x40000,
        WriteOwner = 0x80000,
        Synchronize = 0x100000,

        StandardRightsRequired = 0xF0000,
        StandardRightsRead = ReadControl,
        StandardRightsWrite = ReadControl,
        StandardRightsExecute = ReadControl,
        StandardRightsAll = 0x1F0000,
        SpecificRightsAll = 0xFFFF,

        AccessSystemSecurity = 0x1000000,       // AccessSystemAcl access type

        MaximumAllowed = 0x2000000,         // MaximumAllowed access type

        GenericRead = 0x80000000,
        GenericWrite = 0x40000000,
        GenericExecute = 0x20000000,
        GenericAll = 0x10000000
    }

    [Flags]
    public enum EFileShare : uint
    {
        None = 0x00000000,
        Read = 0x00000001,
        Write = 0x00000002,
        Delete = 0x00000004
    }

    public enum ECreationDisposition : uint
    {
        New = 1,
        CreateAlways = 2,
        OpenExisting = 3,
        OpenAlways = 4,
        TruncateExisting = 5
    }

    [Flags]
    public enum EFileAttributes : uint
    {
        Readonly = 0x00000001,
        Hidden = 0x00000002,
        System = 0x00000004,
        Directory = 0x00000010,
        Archive = 0x00000020,
        Device = 0x00000040,
        Normal = 0x00000080,
        Temporary = 0x00000100,
        SparseFile = 0x00000200,
        ReparsePoint = 0x00000400,
        Compressed = 0x00000800,
        Offline = 0x00001000,
        NotContentIndexed = 0x00002000,
        Encrypted = 0x00004000,
        Write_Through = 0x80000000,
        Overlapped = 0x40000000,
        NoBuffering = 0x20000000,
        RandomAccess = 0x10000000,
        SequentialScan = 0x08000000,
        DeleteOnClose = 0x04000000,
        BackupSemantics = 0x02000000,
        PosixSemantics = 0x01000000,
        OpenReparsePoint = 0x00200000,
        OpenNoRecall = 0x00100000,
        FirstPipeInstance = 0x00080000
    }
}
