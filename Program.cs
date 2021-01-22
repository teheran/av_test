using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.ServiceProcess;

namespace AVTest
{
    class Program
    {
        static void Main(string[] args)
        {
            GetAntivirusServices().ToList().ForEach(av =>
            {
                Console.WriteLine($"Antivirus Service: {av.Name}");
                Console.WriteLine($"\tProduct: {av.Product}");
                Console.WriteLine($"\tVendor: {av.Vendor}");
                Console.WriteLine($"\tVersion: {av.Version}");
                Console.WriteLine($"\tStatus: [{av.Status}]");
                Console.WriteLine($"\t...");
            });
        }

        static IEnumerable<(string Name, string Version, string Status, string Vendor, string Product)> GetAntivirusServices()
        {
            // будем делать через реестр, т.к. нам нужен атрибут Group
            using (RegistryKey svcRoot = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services", RegistryKeyPermissionCheck.ReadSubTree))
            {
                foreach (var svcName in svcRoot.GetSubKeyNames())
                {
                    using (var svc = svcRoot.OpenSubKey(svcName))
                    {
                        var DependOnServices = svc.GetValue("DependOnService") as string[];
                        if (DependOnServices != null && DependOnServices.Contains("FltMgr", StringComparer.OrdinalIgnoreCase))
                        {
                            var Group = svc.GetValue("Group") as string;
                            if (string.Compare(Group, "FSFilter Anti-Virus", StringComparison.OrdinalIgnoreCase) == 0)
                            {
                                var driverImagePath = svc.GetValue("ImagePath") as string;
                                var driverImageFullPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), driverImagePath);
                                var driverFileVersionInfo = File.Exists(driverImageFullPath) ? FileVersionInfo.GetVersionInfo(driverImageFullPath) : null;

                                using (ServiceController sc = new ServiceController(svcName))
                                {
                                    yield
                                        return (
                                            Name: sc.DisplayName,
                                            Version: driverFileVersionInfo?.FileVersion,
                                            Status: sc.Status.ToString().ToUpper(),
                                            Vendor: driverFileVersionInfo?.CompanyName,
                                            Product: driverFileVersionInfo?.ProductName
                                        );
                                };
                            }
                        }
                    }
                }
            }
        }
    }
}
