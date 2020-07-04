using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;

namespace ChromeIPCSniffer.Extensions
{
    public static class ServiceControllerExtension
    {
        public static string GetImagePath(this ServiceController service)
        {
            string registryPath = @"SYSTEM\CurrentControlSet\Services\" + service.ServiceName;
            RegistryKey keyHKLM = Registry.LocalMachine;

            RegistryKey key = keyHKLM.OpenSubKey(registryPath); ;

            string value = key.GetValue("ImagePath").ToString();
            if (value.StartsWith(@"\??"))
            {
                value = value.Substring(4);
            }
            key.Close();
            return Environment.ExpandEnvironmentVariables(value);
        }
    }
}
