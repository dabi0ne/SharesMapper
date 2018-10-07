using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Linq;

namespace SMBSharesUtils
{
	[Serializable]
	public class SMBHost
	{
		[DataMember]
		public string hostname;
		[DataMember]
		public string ip;
		[DataMember]
		public DateTime scanDateTime;
		[DataMember]
		public int scanRecursiveLevel;

		[DataMember]
		public Dictionary<string, SMBScanResult> hostSharesScanResult;

		public SMBHost()
		{
			this.scanDateTime = DateTime.UtcNow;
			this.hostSharesScanResult = new Dictionary<string, SMBScanResult>();
		}
	}

	[Serializable]
	public class SMBScanResult
	{
		[DataMember]
		public SMBShareACL shareACL;
		[DataMember]
		public Dictionary<string, ScanDirectoryResult> shareSubDirectories;

		public SMBScanResult()
		{

		}
	}

	[Serializable]
	public class ScanDirectoryResult
	{
		[DataMember]
		public SMBShareDirectoryACL shareDirectoryACL;
		[DataMember]
		public Dictionary<string, ScanDirectoryResult> shareDirectorySubDirectories;

		public ScanDirectoryResult()
		{

		}
	}

	[Serializable]
	public class SMBShareACL
	{
		[DataMember]
		public HostShare share;

		[DataMember]
		public DateTime discoveryDateTime;

		[DataMember]
		public Dictionary<string, Dictionary<string, string>> shareACL;

		[DataMember]
		public Dictionary<DateTime, Dictionary<string, Dictionary<string, string>>> shareACLEvolution;

		public SMBShareACL()
		{
			this.discoveryDateTime = DateTime.UtcNow;
			this.shareACLEvolution = new Dictionary<DateTime, Dictionary<string, Dictionary<string, string>>>();
		}

		public SMBShareACL(HostShare share, Dictionary<string, Dictionary<string, string>> shareACL)
		{
			this.discoveryDateTime = DateTime.UtcNow;
			this.share = share;
			this.shareACL = shareACL;
			this.shareACLEvolution = new Dictionary<DateTime, Dictionary<string, Dictionary<string, string>>>();
		}

		public SMBShareACL(HostShare share, Dictionary<string, Dictionary<string, string>> shareACL, Dictionary<DateTime, Dictionary<string, Dictionary<string, string>>> ShareACLEvolution)
		{
			this.discoveryDateTime = DateTime.UtcNow;
			this.share = share;
			this.shareACL = shareACL;
			this.shareACLEvolution = ShareACLEvolution;
		}

		public void AddShareACL(Dictionary<string, Dictionary<string, string>> ShareACL)
		{
			this.shareACLEvolution.Add(DateTime.UtcNow, ShareACL);
		}
	}

	[Serializable]
	public class SMBShareDirectoryACL
	{
		[DataMember]
		public string shareDirectory;
		[DataMember]
		public DateTime discoveryDateTime;
		[DataMember]
		public Dictionary<string, Dictionary<string, string>> directoryACL;
		[DataMember]
		public Dictionary<DateTime, Dictionary<string, Dictionary<string, string>>> directoryACLEvolution;

		public SMBShareDirectoryACL()
		{
			this.discoveryDateTime = DateTime.UtcNow;
			this.directoryACLEvolution = new Dictionary<DateTime, Dictionary<string, Dictionary<string, string>>>();
		}

		public SMBShareDirectoryACL(string shareDirectory, Dictionary<string, Dictionary<string, string>> directoryACL)
		{
			this.discoveryDateTime = DateTime.UtcNow;
			this.shareDirectory = shareDirectory;
			this.directoryACL = directoryACL;
			this.directoryACLEvolution = new Dictionary<DateTime, Dictionary<string, Dictionary<string, string>>>();
		}

		public SMBShareDirectoryACL(string shareDirectory, Dictionary<string, Dictionary<string, string>> directoryACL, Dictionary<DateTime, Dictionary<string, Dictionary<string, string>>> DirectoryACLEvolution)
		{
			this.discoveryDateTime = DateTime.UtcNow;
			this.shareDirectory = shareDirectory;
			this.directoryACL = directoryACL;
			this.directoryACLEvolution = DirectoryACLEvolution;
		}

		public void AddDirectoryACL(Dictionary<string, Dictionary<string, string>> DirectoryACL)
		{
			this.directoryACLEvolution.Add(DateTime.UtcNow, DirectoryACL);
		}
	}

	public static class Data
	{

		public static void MergeScanResult(string scan1DataFile, string scan2DataFile, string outDataFile)
		{
			SMBSharesMapperSerializer.SerializeHosts(MergeScanResult(SMBSharesMapperSerializer.DeserializeHosts(scan1DataFile), SMBSharesMapperSerializer.DeserializeHosts(scan2DataFile)), outDataFile);
		}

		public static Dictionary<string,SMBHost> MergeScanResult(Dictionary<string, SMBHost> scan1, Dictionary<string, SMBHost> scan2)
		{
			string key = "";

			Console.WriteLine("[*][" + DateTime.Now + "] Starting merge of " + scan2.Count + " hosts with " + scan1.Count + " hosts.");

			foreach(KeyValuePair<string, SMBHost> host in scan2)
			{
				Console.WriteLine("[*][" + DateTime.Now + "] Merging " + host.Key + " shares");
				key = (scan1.ContainsKey(host.Value.hostname) ? host.Value.hostname : null) ?? (scan1.ContainsKey(host.Value.ip) ? host.Value.ip : null);
				
				if (key != null)
				{
					if (scan1[key].scanDateTime > host.Value.scanDateTime)
					{
						scan1[key].scanDateTime = host.Value.scanDateTime;
					}

					if (scan1[key].scanRecursiveLevel < host.Value.scanRecursiveLevel)
					{
						scan1[key].scanRecursiveLevel = host.Value.scanRecursiveLevel;
					}

					foreach (KeyValuePair<string, SMBScanResult> share in host.Value.hostSharesScanResult)
					{
						if (scan1[key].hostSharesScanResult.ContainsKey(share.Key))
						{
							scan1[key].hostSharesScanResult[share.Key].shareACL.shareACLEvolution.Add(share.Value.shareACL.discoveryDateTime, share.Value.shareACL.shareACL);
							if (share.Value.shareACL.shareACLEvolution.Count > 0)
							{
								scan1[key].hostSharesScanResult[share.Key].shareACL.shareACLEvolution.Concat(share.Value.shareACL.shareACLEvolution);
							}

							MergeDirectoryScanResult(scan1[key].hostSharesScanResult[share.Key].shareSubDirectories, share.Value.shareSubDirectories);
						}
						else
						{
							scan1[key].hostSharesScanResult.Add(share.Key, share.Value);
						}
					}
				}
				else
				{
					scan1.Add(host.Key, host.Value);
				}

			}
			Console.WriteLine("[+][" + DateTime.Now + "] Merge done.");
			return scan1;
		}

		private static void MergeDirectoryScanResult(Dictionary<string, ScanDirectoryResult> scan1, Dictionary<string, ScanDirectoryResult> scan2)
		{
			foreach (KeyValuePair<string, ScanDirectoryResult> scanDirectoryResult in scan2)
			{
				if (scan1.ContainsKey(scanDirectoryResult.Key))
				{
					scan1[scanDirectoryResult.Key].shareDirectoryACL.directoryACLEvolution.Add(scanDirectoryResult.Value.shareDirectoryACL.discoveryDateTime, scanDirectoryResult.Value.shareDirectoryACL.directoryACL);

					if (scanDirectoryResult.Value.shareDirectoryACL.directoryACLEvolution.Count > 0)
					{
						scan1[scanDirectoryResult.Key].shareDirectoryACL.directoryACLEvolution.Concat(scanDirectoryResult.Value.shareDirectoryACL.directoryACLEvolution);
					}

					MergeDirectoryScanResult(scan1[scanDirectoryResult.Key].shareDirectorySubDirectories, scanDirectoryResult.Value.shareDirectorySubDirectories);
				}
				else
				{
					scan1.Add(scanDirectoryResult.Key, scanDirectoryResult.Value);
				}
			}
		}
	}

}
