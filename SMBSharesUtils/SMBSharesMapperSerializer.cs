using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;

namespace SMBSharesUtils
{
	public class SMBSharesMapperSerializer
	{
		public static void SerializeHosts(Dictionary<string, SMBHost> hosts, string outFile)
		{
			var serializer = new DataContractSerializer(hosts.GetType());
			try
			{
				using (FileStream stream = File.Create(outFile + "_SMBHosts.xml"))
				{
					serializer.WriteObject(stream, hosts);
				}
			}
			catch (Exception e)
			{
				Console.WriteLine("[-] Error on serializing results (" + e.Message + ").");
			}
		}

		public static Dictionary<string, SMBHost> DeserializeHosts(string inFile)
		{
			var serializer = new DataContractSerializer(typeof(Dictionary<string, SMBHost>));
			Dictionary<string, SMBHost> hosts = null;
			try
			{
				using (FileStream stream = File.OpenRead(inFile))
				{
					hosts = (Dictionary<string, SMBHost>)serializer.ReadObject(stream);
				}
			}
			catch (Exception e)
			{
				Console.WriteLine("[-] Error on deserializing results (" + e.Message + ").");
			}
			return hosts;
		}
	}
}
