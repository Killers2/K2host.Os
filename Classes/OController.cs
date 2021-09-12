/*
' /====================================================\
'| Developed Tony N. Hyde (www.k2host.co.uk)            |
'| Projected Started: 2017-11-01                        | 
'| Use: General  (Inspired from Open Source)            |
' \====================================================/
*/
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace K2host.Os.Classes
{

    public class OController
    {

        public enum RestartOptions
        {
            LogOff = 0,
            PowerOff = 8,
            Reboot = 2,
            ShutDown = 1,
            Suspend = -1,
            Hibernate = -2,
        }

        public class PrivilegeException : Exception
        {

            public PrivilegeException()
                : base()
            {
            }

            public PrivilegeException(string message)
                : base(message)
            {
            }

        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct LUID
        {
            public int LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct LUID_AND_ATTRIBUTES
        {
            public LUID pLuid;
            public int Attributes;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct TOKEN_PRIVILEGES
        {
            public int PrivilegeCount;
            public LUID_AND_ATTRIBUTES Privileges;
        }

        private const int TOKEN_ADJUST_PRIVILEGES = 0x20;
        private const int TOKEN_QUERY = 0x8;
        private const int SE_PRIVILEGE_ENABLED = 0x2;
        private const int FORMAT_MESSAGE_FROM_SYSTEM = 0x1000;
        private const int EWX_FORCE = 4;

        [DllImport("kernel32", EntryPoint = "LoadLibraryA", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr LoadLibrary(string lpLibFileName);

        [DllImport("kernel32", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
        private static extern int FreeLibrary(IntPtr hLibModule);

        [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("powrprof", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
        private static extern int SetSuspendState(int Hibernate, int ForceCritical, int DisableWakeEvent);

        [DllImport("advapi32", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
        private static extern int OpenProcessToken(IntPtr ProcessHandle, int DesiredAccess, ref IntPtr TokenHandle);

        [DllImport("advapi32", EntryPoint = "LookupPrivilegeValueA", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        private static extern int LookupPrivilegeValue(string lpSystemName, string lpName, ref LUID lpLuid);

        [DllImport("advapi32", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
        private static extern int AdjustTokenPrivileges(IntPtr TokenHandle, int DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, int BufferLength, ref TOKEN_PRIVILEGES PreviousState, ref int ReturnLength);

        [DllImport("user32", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
        private static extern int ExitWindowsEx(int uFlags, int dwReserved);

        [DllImport("kernel32", EntryPoint = "FormatMessageA", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        private static extern int FormatMessage(int dwFlags, IntPtr lpSource, int dwMessageId, int dwLanguageId, StringBuilder lpBuffer, int nSize, int Arguments);

        public static void ExitWindows(RestartOptions how, bool force)
        {
            switch (how)
            {
                case RestartOptions.Suspend:
                    SuspendSystem(false, force);
                    break;
                case RestartOptions.Hibernate:
                    SuspendSystem(true, force);
                    break;
                default:
                    ExitWindows(Convert.ToInt32(how), force);
                    break;
            }
        }

        protected static void ExitWindows(int how, bool force)
        {

            EnableToken("SeShutdownPrivilege");

            if (force)
                how |= EWX_FORCE;

            if (ExitWindowsEx(how, 0) == 0)
                throw new PrivilegeException(FormatError(Marshal.GetLastWin32Error()));

        }

        protected static void EnableToken(string privilege)
        {

            if ((Environment.OSVersion.Platform != PlatformID.Win32NT) || (!CheckEntryPoint("advapi32.dll", "AdjustTokenPrivileges")))
                return;

            IntPtr tokenHandle = default;
            LUID privilegeLUID = default;
            TOKEN_PRIVILEGES newPrivileges = default;
            TOKEN_PRIVILEGES tokenPrivileges = default;

            if (OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref tokenHandle) == 0)
                throw new PrivilegeException(FormatError(Marshal.GetLastWin32Error()));

            if (LookupPrivilegeValue("", privilege, ref privilegeLUID) == 0)
                throw new PrivilegeException(FormatError(Marshal.GetLastWin32Error()));

            tokenPrivileges.PrivilegeCount = 1;
            tokenPrivileges.Privileges.Attributes = SE_PRIVILEGE_ENABLED;
            tokenPrivileges.Privileges.pLuid = privilegeLUID;

            int retLength = 4 + (12 * newPrivileges.PrivilegeCount);

            if (AdjustTokenPrivileges(tokenHandle, 0, ref tokenPrivileges, 4 + (12 * tokenPrivileges.PrivilegeCount), ref newPrivileges, ref retLength) == 0)
                throw new PrivilegeException(FormatError(Marshal.GetLastWin32Error()));

        }

        protected static void SuspendSystem(bool hibernate, bool force)
        {

            if (!CheckEntryPoint("powrprof.dll", "SetSuspendState"))
                throw new PlatformNotSupportedException("The SetSuspendState method is not supported on this system!");

            _ = SetSuspendState(Convert.ToInt32((hibernate ? 1 : 0)), Convert.ToInt32((force ? 1 : 0)), 0);

        }

        protected static bool CheckEntryPoint(string library, string method)
        {
            IntPtr libPtr = LoadLibrary(library);
            if (!libPtr.Equals(IntPtr.Zero))
            {
                if (!GetProcAddress(libPtr, method).Equals(IntPtr.Zero))
                {
                    _ = FreeLibrary(libPtr);
                    return true;
                }
                _ = FreeLibrary(libPtr);
            }
            return false;
        }

        protected static string FormatError(int number)
        {
            try
            {
                StringBuilder buffer = new(255);
                _ = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, IntPtr.Zero, number, 0, buffer, buffer.Capacity, 0);
                return buffer.ToString();
            }
            catch
            {
                return "Unspecified error [" + number.ToString() + "]";
            }
        }

    }

}
