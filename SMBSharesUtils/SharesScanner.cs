using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Runtime.Serialization;
using System.Threading;
using System.Net;

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
		public Dictionary<string,ScanDirectoryResult> shareSubDirectories;

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
		public Dictionary<string,ScanDirectoryResult> shareDirectorySubDirectories;

		public ScanDirectoryResult()
		{

		}
	}

	public class SharesScanner
	{
		/// <summary>
		/// Print target's SMB shares and their ACL
		/// </summary>
		/// <param name="hostname"></param>
		public static void PreviewHostShares(string hostname)
		{

			List<SMBShareACL> sharesACL = ShareACLUtils.GetSharesACL(GetNetShare.EnumNetShares(hostname));

			foreach (SMBShareACL shareACL in sharesACL)
			{
				ShareACLUtils.PrintShareAccesses(shareACL);
			}
		}

		public static Dictionary<string, SMBHost> ScanCIDR(string cidr)
		{

			Dictionary<string, SMBHost> results = new Dictionary<string, SMBHost>();
			string[] ip_cidr = cidr.Split('/');
			string hostname = "";

			int subnetMask = 0;
			Int32.TryParse(ip_cidr[1], out subnetMask);
			subnetMask = 32 - subnetMask;

			int IPCount = (int)Math.Pow(2, subnetMask) - 2;
			uint intIP = (uint)IPAddress.NetworkToHostOrder((int)IPAddress.Parse(ip_cidr[0]).Address);
			intIP = intIP & ~((uint)Math.Pow(2, subnetMask) - 1);

			for (int i = 1; i <= IPCount; i++)
			{
				hostname = IPAddress.Parse(intIP.ToString()).ToString();
				if (!((intIP & 0x000000FF) == 0x000000FF || (intIP & 0x000000FF) == 0x00000000))
				{
					if (Config.Debug) { Console.WriteLine("[*][" + DateTime.Now.ToString() + "] Scanning shares of " + hostname); }

					try
					{
						results.Add(hostname, ScanHost(hostname));
					}
					catch (Exception e)
					{
						if (Config.Debug) { Console.WriteLine("[-][" + DateTime.Now.ToString() + "] Error on scanning  " + hostname + " : " + e.ToString()); }
					}
				}
				intIP = intIP + 1;
			}

			return results;
		}

		/// <summary>
		/// Scan IP/CIDR hosts SMB shares' ACL
		/// </summary>
		/// <param name="cidr"></param>
		/// <returns></returns>
		public static Dictionary<string, SMBHost> MTScanCIDR(string cidr)
		{

			Dictionary<string, SMBHost> results = new Dictionary<string, SMBHost>();
			string[] ip_cidr = cidr.Split('/');
			
			string hostname = "";

			int subnetMask = 0;
			Int32.TryParse(ip_cidr[1], out subnetMask);
			subnetMask = 32 - subnetMask;

			int IPCount = (int)Math.Pow(2, subnetMask) - 2;
			List<string> hostnames = new List<string>();
			uint intIP = (uint)IPAddress.NetworkToHostOrder((int)IPAddress.Parse(ip_cidr[0]).Address);
			intIP = intIP & ~((uint)Math.Pow(2, subnetMask) - 1);

			for (int i = 1; i <= IPCount; i++)
			{
				hostname = IPAddress.Parse(intIP.ToString()).ToString();
				if (!((intIP & 0x000000FF) == 0x000000FF || (intIP & 0x000000FF) == 0x00000000))
				{
					hostnames.Add(hostname);
				}
				intIP = intIP + 1;
			}

			if (IPCount > 0)
			{
				results = MTScanHosts(hostnames.ToArray());
			}

			return results;
		}


		/// <summary>
		/// Load hostnames from the file and scan their SMB shares
		/// </summary>
		/// <param name="filePath"></param>
		/// <returns></returns>
		public static Dictionary<string, SMBHost> ScanHosts(string filePath)
		{
			if (File.Exists(filePath))
			{
				return ScanHosts(File.ReadAllLines(filePath));
			}

			Console.WriteLine("[-] File not found.");
			return new Dictionary<string, SMBHost>();

		}

		/// <summary>
		/// Scan hostnames SMB shares
		/// </summary>
		/// <param name="hostnames"></param>
		/// <returns></returns>
		public static Dictionary<string, SMBHost> ScanHosts(string[] hostnames)
		{
			Dictionary<string, SMBHost> results = new Dictionary<string, SMBHost>();
			
			if (hostnames.Length > 0)
			{
				foreach (string hostname in hostnames)
				{ 
					if (Config.Debug) { Console.WriteLine("[*][" + DateTime.Now.ToString() + "] Scanning shares of " + hostname); }
						
					try
					{
						results.Add(hostname, ScanHost(hostname));
					}
					catch (Exception e)
					{
						if (Config.Debug) { Console.WriteLine("[-][" + DateTime.Now.ToString() + "] Error on scanning  " + hostname + " : " + e.ToString()); }
					}
				}
			}

			return results;
		}

		/// <summary>
		/// Load hostnames from file and perform multi-thread SMB shares scan
		/// </summary>
		/// <param name="filePath"></param>
		/// <returns></returns>
		public static Dictionary<string, SMBHost> MTScanHosts(string filePath)
		{
			if (File.Exists(filePath))
			{
				 return MTScanHosts(File.ReadAllLines(filePath));
			}

			Console.WriteLine("[-] File not found.");
			return new Dictionary<string, SMBHost>();

		}

		/// <summary>
		/// Perform a multi-thread SMB shares scan on hostnames
		/// </summary>
		/// <param name="hostnames"></param>
		/// <returns></returns>
		public static Dictionary<string, SMBHost> MTScanHosts(string[] hostnames)
		{
			Object resultLock = new Object();
			List<Thread> threads = new List<Thread>();

			Dictionary<string, SMBHost> results = new Dictionary<string, SMBHost>();
			int counter = 1;
			IPAddress ip;
			Queue<string> targets = new Queue<string>();
			Dictionary<int, int> threadsTryJoinAttemps = new Dictionary<int, int>();
			List<string> scannedHosts = new List<string>();

			void doScan(string host)
			{
				try
				{
					if (Config.Debug) { Console.WriteLine("[*][" + DateTime.Now.ToString() + "] Starting thread for " + host); }
					SMBHost TscanResults = ScanHost(host);
					lock (resultLock)
					{
						results.Add(host, TscanResults);
					}
				}
				catch (Exception e)
				{
					Console.WriteLine("[-][" + DateTime.Now.ToString() + "] Failed to scan " + host);
					if (Config.Debug) { Console.WriteLine("[!][THEAD][Exception] " + e.Message); }
				}
				return;
			}

			bool TryJoinThread(Thread t)
			{
				try
				{
					bool joinResult = t.Join(Config.ThreadJoinTimeout);
					int threadJoinAttempts = 0;
					if (!joinResult)
					{
						if (threadsTryJoinAttemps.TryGetValue(t.ManagedThreadId, out threadJoinAttempts))
						{
							if (threadJoinAttempts > Config.ThreadJoinMaxAttempts)
							{
								if (Config.Debug) { Console.WriteLine("Thread " + t.ManagedThreadId.ToString() + " will be asked to abort"); }
								t.Abort();
								return true;
							}
							else
							{
								threadsTryJoinAttemps[t.ManagedThreadId] = threadJoinAttempts + 1;
							}
						}
						else
						{
							if (Config.Debug) { Console.WriteLine("Creating new entry for the thread " + t.ManagedThreadId.ToString()); }
							threadsTryJoinAttemps.Add(t.ManagedThreadId, 1);
						}
					}
					return joinResult;
				}
				catch (Exception)
				{
					return false;
				}
			}

			Console.WriteLine("[*][" + DateTime.Now.ToString() + "] Starting mutli-threaded scan ...");
			if (hostnames.Length > 0)
			{
				
					foreach (string target in hostnames)
					{
						
						if (Config.Debug) { Console.WriteLine("Scanning host number " + counter.ToString() + " (" + target + ")"); }
						counter++;
						try
						{
							ip = IPAddress.Parse(target);
						}
						catch (FormatException)
						{
							if ((Config.TryResolveHostName && !TryResolveHostName(target)))
							{
								Console.WriteLine("[-][" + DateTime.Now.ToString() + "] Could not resolve " + target);
								continue;
							}
						}

						try
						{
							if (Config.Debug) { Console.WriteLine("[*][" + DateTime.Now.ToString() + "] Scanning shares of " + target); }
							while (threads.Count >= Config.MaxThreads)
							{
								Console.Write("[*][" + DateTime.Now.ToString() + "] Running threads count : " + threads.Count.ToString() + "    \r");
								if (Config.Debug) { Console.WriteLine("[*][" + DateTime.Now.ToString() + "] Waiting for a place to create a new thread ..."); }
								threads.RemoveAll(TryJoinThread);
							}

							if (!scannedHosts.Contains(target))
							{
								targets.Enqueue(target);
								Thread thread = new Thread(() => doScan(targets.Dequeue()))
								{
									Name = target,
									IsBackground = true
								};
								threads.Add(thread);
								thread.Start();

								scannedHosts.Add(target);
							}
								
						}
						catch (Exception e)
						{
							if (Config.Debug) { Console.WriteLine("[-][" + DateTime.Now.ToString() + "] Error on scanning  " + target + " : " + e.ToString()); }
						}
						
					}
				
			}

			Console.WriteLine("[*][" + DateTime.Now.ToString() + "] Waiting for the remaining threads ...");
			do
			{
				Console.Write("[*][" + DateTime.Now.ToString() + "] Remaining threads : " + threads.Count.ToString() + "    \r");
				threads.RemoveAll(TryJoinThread);
			} while (threads.Count > 0);

			return results;
		}

		public static bool TryResolveHostName(string hostname)
		{
			try
			{
				Dns.GetHostEntry(hostname);
			}
			catch (Exception)
			{
				return false;
			}
			return true;
		}

		/// <summary>
		/// Scan host's SMB shares
		/// </summary>
		/// <param name="hostname">Target to scan.</param>
		/// <returns></returns>
		public static SMBHost ScanHost(string hostname)
		{
			SMBHost result = new SMBHost();
			SMBScanResult currentResult;
			HostShare[] hostShares;
			IPAddress ip = null;

			result.scanRecursiveLevel = Config.RecursiveLevel;
			result.hostname = hostname;
			try
			{
				ip = IPAddress.Parse(hostname);
				result.ip = ip.ToString();
			}
			catch (FormatException)
			{
				if ((Config.TryResolveHostName && !TryResolveHostName(hostname)))
				{
					Console.WriteLine("[-][" + DateTime.Now.ToString() + "] Could not resolve " + hostname);
					return result;
				}
				result.ip = "";
			}

			// Get target's shares
			try
			{
				if (Config.Debug) { Console.WriteLine("[*][" + DateTime.Now.ToString() + "] Getting " + hostname + " shares ..."); }
				hostShares = GetNetShare.EnumNetShares(hostname);
			}
			catch (Exception e)
			{
				if (Config.Debug) { Console.WriteLine("[-][" + DateTime.Now.ToString() + "] Error on enumerating " + hostname + " shares (" + e.ToString() + ").");}
				return result;
			}

			List<SMBShareACL> sharesACL = ShareACLUtils.GetSharesACL(hostShares);

			// Iterate over target's shares 
			foreach (SMBShareACL shareACL in sharesACL)
			{
				// Create SMBScanResult object for every shareInfo
				currentResult = new SMBScanResult { shareACL = shareACL, shareSubDirectories = new Dictionary<string, ScanDirectoryResult>() };
				
				// if the shareInfo is not IPC$ or a printer, do a recursive scan on the subdirectories
				if (IsRecursivelyScannable(currentResult.shareACL.share))
				{
					currentResult.shareSubDirectories = ScanShareDirectory(shareACL.share.ToString(), Config.RecursiveLevel).shareDirectorySubDirectories;
				}
				
				result.hostSharesScanResult.Add(shareACL.share.shareInfo.shi1_netname ,currentResult);
			}

			return result;
		}

		/// <summary>
		/// Lists all subdirectories on the shareDirectory and gets the ACL of every directory.
		/// The action is performed recursively  as long as the subRecursiveLevel is not null.
		/// </summary>
		/// <param name="shareDirectory">UNC path</param>
		/// <param name="subRecusiveLevel">How many level of subdirectories should be scanned</param>
		/// <returns>ScanDirectoryResult object</returns>
		public static ScanDirectoryResult ScanShareDirectory(string shareDirectory, int subRecusiveLevel)
		{

			if (Config.Debug) { Console.WriteLine("[*][" + DateTime.Now.ToString() + "] Scanning " + shareDirectory + " Recursive level " + subRecusiveLevel.ToString()); }
			if (subRecusiveLevel == 0)
			{
				return new ScanDirectoryResult { shareDirectoryACL = ShareACLUtils.GetShareDirectoryACL(shareDirectory), shareDirectorySubDirectories = new Dictionary<string, ScanDirectoryResult>() };
			}
			else
			{
				string[] shareDirectorySubDirectories = GetSubDirectories(shareDirectory);
				Dictionary<string, ScanDirectoryResult> shareDirecotySubDirectoriesScanResult = new Dictionary<string, ScanDirectoryResult>();
				foreach (string subDirectoy in shareDirectorySubDirectories)
				{
					shareDirecotySubDirectoriesScanResult.Add(subDirectoy.Split('\\').Last(), ScanShareDirectory(subDirectoy, subRecusiveLevel - 1));
				}
				return new ScanDirectoryResult { shareDirectoryACL = ShareACLUtils.GetShareDirectoryACL(shareDirectory), shareDirectorySubDirectories = shareDirecotySubDirectoriesScanResult };
			}
		}

		public static string[] GetSubDirectories(string shareDirectory)
		{
			try
			{
				if (Config.Debug) { Console.WriteLine("[*] Getting " + shareDirectory + " subdirectories ..."); }
				return Directory.GetDirectories(shareDirectory);
			}
			catch (Exception e)
			{
				if (Config.Debug) { Console.WriteLine("[!][GetDirectories][Exception] " + e.Message); }
				return new string[] { };
			}
		}

		/// <summary>
		/// Perform a new scan on hosts using multiple threads.
		/// </summary>
		/// <param name="hosts"></param>
		public static void MTReScanHosts(Dictionary<string, SMBHost> hosts)
		{
			List<Thread> threads = new List<Thread>();
			Dictionary<int, int> threadsTryJoinAttemps = new Dictionary<int, int>();

			bool TryJoinThread(Thread t)
			{
				try
				{
					bool joinResult = t.Join(Config.ThreadJoinTimeout);
					int threadJoinAttempts = 0;
					if (!joinResult)
					{
						if (threadsTryJoinAttemps.TryGetValue(t.ManagedThreadId, out threadJoinAttempts))
						{
							if (threadJoinAttempts > Config.ThreadJoinMaxAttempts)
							{
								if (Config.Debug) { Console.WriteLine("Thread " + t.ManagedThreadId.ToString() + " will be asked to abort"); }
								t.Abort();
								return true;
							}
							else
							{
								threadsTryJoinAttemps[t.ManagedThreadId] = threadJoinAttempts + 1;
							}
						}
						else
						{
							if (Config.Debug) { Console.WriteLine("Creating new entry for the thread " + t.ManagedThreadId.ToString()); }
							threadsTryJoinAttemps.Add(t.ManagedThreadId, 1);
						}
					}
					return joinResult;
				}
				catch (Exception)
				{
					return false;
				}
			}

			foreach (SMBHost host in hosts.Values)
			{
				if (Config.Debug) { Console.WriteLine("[*][" + DateTime.Now.ToString() + "] Scanning shares of " + host.hostname); }
				while (threads.Count >= Config.MaxThreads)
				{
					if (Config.Debug) { Console.WriteLine("[*][" + DateTime.Now.ToString() + "] Waiting for a place to create a new thread ..."); }
					threads.RemoveAll(TryJoinThread);
				}

				Thread thread = new Thread(() => ReScanHost(host))
				{
					Name = host.hostname,
					IsBackground = true
				};
				threads.Add(thread);
				thread.Start();
			}

			Console.WriteLine("[*][" + DateTime.Now.ToString() + "] Waiting for the remaining threads ...");
			do
			{
				if (Config.Debug) { Console.WriteLine("[*][" + DateTime.Now.ToString() + "] Remaining threads : " + threads.Count.ToString()); }
				threads.RemoveAll(TryJoinThread);
			} while (threads.Count > 0);
		}

		/// <summary>
		/// Perform a new scan on hosts.
		/// </summary>
		/// <param name="hosts"></param>
		public static void ReScanHosts(Dictionary<string, SMBHost> hosts)
		{
			foreach (SMBHost host in hosts.Values)
			{
				ReScanHost(host);
			}
		}

		/// <summary>
		/// Append new hosts from file to a previous scan result
		/// </summary>
		/// <param name="hosts">Hosts dictionary</param>
		/// <param name="path">Path to file containing a list of hostnames</param>
		/// <param name="resolveHostName">If it's true, try to resolve hostname before insert</param>
		public static void AppendHosts(Dictionary<string, SMBHost> hosts, string path, bool resolveHostName = false)
		{
			try
			{
				AppendHosts(hosts, File.ReadAllLines(path), resolveHostName);
			}
			catch (Exception e)
			{
				Console.WriteLine("[-] Could not import hosts from the file (" + e.Message + ").");	
			}
		}

		/// <summary>
		/// Append new hosts to a previous scan result
		/// </summary>
		/// <param name="hosts">Hosts dictionary</param>
		/// <param name="hostnames">Array of hostnames</param>
		/// <param name="resolveHostName">If it's true, try to resolve hostname before insert</param>
		public static void AppendHosts(Dictionary<string, SMBHost> hosts, string[] hostnames, bool resolveHostName = false)
		{
			string ip = "";
			foreach (string hostname in hostnames)
			{
				try
				{
					ip = IPAddress.Parse(hostname).ToString();
				}
				catch (FormatException)
				{
					if ((resolveHostName && !TryResolveHostName(hostname)))
					{
						Console.WriteLine("[-][" + DateTime.Now.ToString() + "] Could not resolve " + hostname);
					}
					continue;
				}

				try
				{
					hosts.Add(hostname, new SMBHost { hostname = hostname, ip = ip, hostSharesScanResult = new Dictionary<string, SMBScanResult>(), scanRecursiveLevel = Config.ScanForNewSharesRecusiveLevel });
				}
				catch (ArgumentNullException)
				{
					Console.WriteLine("[-] Could not insert an empty hostname.");
				}
				catch (ArgumentException)
				{
					Console.WriteLine("[!] The host " + hostname + " is already in the list.");
				}
			}
		}

		/// <summary>
		/// Perform new scan on host
		/// </summary>
		/// <param name="host"></param>
		public static void ReScanHost(SMBHost host)
		{
			HostShare[] hostShares;
			List<string> discoveredHostShares;
			SMBScanResult currentResult;

			// If the recursive level is not set in the Config class, we use the level used for the first scan
			if (Config.ScanForNewSharesRecusiveLevel == -1)
			{
				Config.ScanForNewSharesRecusiveLevel = host.scanRecursiveLevel;
			}

			foreach (SMBScanResult scanResult in host.hostSharesScanResult.Values)
			{
				ReScanSMBScanResult(scanResult);
			}

			// Check whether the scan will be performed on discovered shares only or try to identify new shares.
			// The discovery operation includes only the scanned hosts. To add new hosts you should use AppendHosts method.
			if (Config.ScanForNewShares)
			{
				hostShares = GetNetShare.EnumNetShares(host.hostname);
				if (host.hostSharesScanResult.Count > 0)
				{
					discoveredHostShares = host.hostSharesScanResult.Keys.ToList();
					foreach (HostShare hostShare in hostShares)
					{
						if (!discoveredHostShares.Contains(hostShare.shareInfo.shi1_netname))
						{
							currentResult = new SMBScanResult { shareACL = ShareACLUtils.GetShareACL(hostShare), shareSubDirectories = new Dictionary<string, ScanDirectoryResult>() };
							if (IsRecursivelyScannable(currentResult.shareACL.share))
							{
								currentResult.shareSubDirectories = ScanShareDirectory(hostShare.ToString(), Config.ScanForNewSharesRecusiveLevel).shareDirectorySubDirectories;
							}
							host.hostSharesScanResult.Add(hostShare.shareInfo.shi1_netname, currentResult);
						}
					}
				}
				else
				{
					host.hostSharesScanResult = ScanHost(host.hostname).hostSharesScanResult;
				}
			}
			
		}

		/// <summary>
		/// Perform a new scan on each element of the list
		/// </summary>
		/// <param name="scanResults"></param>
		public static void ReScanSMBScanResults(List<SMBScanResult> scanResults)
		{
			scanResults.ForEach(ReScanSMBScanResult);
		}

		/// <summary>
		/// Fetch the ACL of a share (and his subdirectories) and append them to the evolution list
		/// </summary>
		/// <param name="scanResult"></param>
		public static void ReScanSMBScanResult(SMBScanResult scanResult)
		{
			scanResult.shareACL.AddShareACL(ShareACLUtils.GetShareACL(scanResult.shareACL.share.ToString()));

			if (scanResult.shareSubDirectories.Count > 0)
			{
				ReScanScanDirectoryResults(scanResult.shareSubDirectories, Config.ScanForNewSharesRecusiveLevel - 1);
			}

			
			if (Config.ScanForNewSharesRecusiveLevel > 0 && IsRecursivelyScannable(scanResult.shareACL.share))
			{
				// Get share subdirectories and check if there are new ones
				foreach (string subDirectory in GetSubDirectories(scanResult.shareACL.share.ToString()))
				{
					if (!scanResult.shareSubDirectories.ContainsKey(subDirectory.Split('\\').Last()))
					{
						// If so, then perform a scan on the new subdirectories
						scanResult.shareSubDirectories.Add(subDirectory, ScanShareDirectory(subDirectory, Config.ScanForNewSharesRecusiveLevel - 1));
					}
				}
			}
		}

		/// <summary>
		/// Fetch ACL of directory and his subdirectories recursively and append them to the Evolution list
		/// </summary>
		/// <param name="scanDirectoryResults"></param>
		public static void ReScanScanDirectoryResults(Dictionary<string, ScanDirectoryResult> scanDirectoryResults, int subRecursiveLevel = 0)
		{
			foreach (ScanDirectoryResult scanDirectoryResult in scanDirectoryResults.Values)
			{
				scanDirectoryResult.shareDirectoryACL.AddDirectoryACL(ShareACLUtils.GetShareACL(scanDirectoryResult.shareDirectoryACL.shareDirectory));
				if (scanDirectoryResult.shareDirectorySubDirectories.Count > 0)
				{
					ReScanScanDirectoryResults(scanDirectoryResult.shareDirectorySubDirectories, subRecursiveLevel - 1);
				}

				if (subRecursiveLevel > 0)
				{
					// Get current directory subdirectories and check if there are new ones 
					foreach (string subDirectory in GetSubDirectories(scanDirectoryResult.shareDirectoryACL.shareDirectory))
					{
						if (!scanDirectoryResult.shareDirectorySubDirectories.ContainsKey(subDirectory.Split('\\').Last()))
						{
							scanDirectoryResult.shareDirectorySubDirectories.Add(subDirectory.Split('\\').Last(), ScanShareDirectory(subDirectory, subRecursiveLevel - 1));
						}
					}
				}
			}
		}

		static private bool IsRecursivelyScannable(HostShare hostShare)
		{
			return (
					!(
						hostShare.shareInfo.shi1_type == (UInt16)SHARE_TYPE.STYPE_PRINTQ ||
						hostShare.shareInfo.shi1_type == (UInt16)SHARE_TYPE.STYPE_IPC ||
						Config.SharesRecursiveScanBlackList.Contains(hostShare.shareInfo.shi1_netname)
					)
				   );
		}
	}
}
