using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace ChromeIPCSniffer
{
    class ElevationUtils
    {
        public static bool HasAdminRights()
        {
            // request elevation
            WindowsPrincipal pricipal = new WindowsPrincipal(WindowsIdentity.GetCurrent());
            bool hasAdministrativeRight = pricipal.IsInRole(WindowsBuiltInRole.Administrator);
            if (!hasAdministrativeRight)
            {
                return false;

                // request admin rights in run time

                //string currentPath = Assembly.GetExecutingAssembly().Location;
                //ProcessStartInfo processInfo = new ProcessStartInfo();
                //processInfo.Verb = "runas";
                //processInfo.FileName = currentPath;
                //try
                //{
                //    Process.Start(processInfo);
                //    Environment.Exit(1);
                //    return true;
                //}
                //catch
                //{
                //    //Probably the user canceled the UAC window
                //}
                //return false;
            }

            return true;
        }
    }
}
