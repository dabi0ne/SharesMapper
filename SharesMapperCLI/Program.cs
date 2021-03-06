﻿using System;
using System.Collections.Generic;
using SMBSharesUtils;
using CommandLine;
using System.IO;
using System.Linq;

namespace ShareMapperCLI
{

	class Program
	{

		class CommonOptions
		{
			[Option('d', "debug", Required = false, Default = false)]
			public bool Debug { get; set; }

		}

		class DirScanMTOptions : CommonOptions
		{
			[Option('C', "dirMaxThreads", Default = 1, HelpText = "How many concurrent threads will be launched during subdirectories scan.")]
			public int DirScanMaxThreads { get; set; }

			[Option('M', "dirMaxAttemps", Default = 0, HelpText = "How many tries to join a thread before killing a directory scan thread.")]
			public int DirScanThreadJoinMaxAttempts { get; set; }

			[Option('J', "dirJoinTimeout", Default = 100, HelpText = "How much time in ms the join call will wait a directory scan thread.")]
			public int DirScanThreadJoinTimeout { get; set; }
		}

		class MTOptions : DirScanMTOptions
		{
			[Option('c', "maxThreads", Default = 1, HelpText = "How many concurrent threads will be launched to scan the hosts.")]
			public int MaxThreads { get; set; }

			[Option('m', "maxAttemps", Default = 0, HelpText = "How many tries to join a scanning host thread before killing it.")]
			public int ThreadJoinMaxAttempts { get; set; }

			[Option('j', "joinTimeout", Default = 100, HelpText = "How much time in ms the join call will wait a scanning host thread.")]
			public int ThreadJoinTimeout { get; set; }
		}

		class ScanCommonOptions : MTOptions
		{

			[Option('r', "recursiveLevel", Default = 0, HelpText = "How deep the scan should go into shares.")]
			public int RecursiveLevel { get; set; }

			[Option("dns", Default = true, HelpText = "Perform a DNS resolution on host names before scan. If the resolution fails the target will not be scanned. (If the target is an IP address the resolution will not be performed)")]
			public bool ResolveHostname { get; set; }

			[Option('o', "outReport", Default = "", HelpText = "The filename of the xlsx report.")]
			public string OutReport { get; set; }

			[Option('s', "sid", HelpText = "File that contains a list of comma separated SID,name that will be used during report generation to resolve SIDs.")]
			public string SIDFileIn { get; set; }

			[Option('x', "outData", Required = true, HelpText = "File path to save the serialized result to be used for future scan.")]
			public string OutData { get; set; }

			[Option('b', "blacklist", Default = "", Required = false, HelpText = "List of comma separated shares names to not scan recursively (or file of shares list)")]
			public string BlackList { get; set; }

			[Option('w', "whitelist", Default = "", Required = false, HelpText = "List of comma separated shares names to scan recursively (or file of shares list)")]
			public string WhiteList { get; set; }
		}

		[Verb("scanSMB", HelpText = "Perform a SMB scan.")]
		class SMBOptions : ScanCommonOptions
		{

			[Option('t', "target", Required = true, HelpText = "Targets to scan.")]
			public string Target { get; set; }

			[Option("targetType", Default = "hosts", HelpText = "Target type : hosts or file.")]
			public string TargetType { get; set; }

		}

		[Verb("rescanSMB", HelpText = "Perform a new scan on previous result.")]
		class RescanSMBOptions : ScanCommonOptions
		{

			[Option('i', "inputfile", Required = true, HelpText = "Serialized result of a SMB scan.")]
			public string InputFile { get; set; }

			[Option('n', "newshares", Default = true, HelpText = "Perform a new discovery of hosts' shares and shares' subdirectories.")]
			public bool ScanForNewShares { get; set; }

			[Option('a', "appendhosts", Default = null, HelpText = "Append the comma separated hosts to the previous result.")]
			public string AppendHosts { get; set; }

			[Option('f', "appendhostsfile", Default = null, HelpText = "Append file's hosts to the previous result.")]
			public string AppendHostsFile { get; set; }
		}

		[Verb("getSMBShares", HelpText = "Preview SMB shares of host.")]
		class GetSMBSharesOptions : CommonOptions
		{
			[Option('h', "hostname", Required = true, HelpText = "Host to scan.")]
			public string HostName { get; set; }

			[Option('a', "ACL", HelpText = "Show ACL of every share.", Default = false)]
			public bool PrintACL { get; set; }
		}

		[Verb("scanSMBShareDir", HelpText = "Scan SMB share directories.")]
		class ScanSMBShareDirOptions : DirScanMTOptions
		{
			[Option('t', "target", Required = true, HelpText = "Target to scan.")]
			public string target { get; set; }

			[Option('p', "path", Required = true, HelpText = "Share path (without host part, ex: C$\\Users\\user_1).")]
			public string Path { get; set; }

			[Option('r', "recursiveLevel", Default = 0, HelpText = "How deep the scan should go into the paths.")]
			public int RecursiveLevel { get; set; }

			[Option('o', "outReport", Required = true, Default = "", HelpText = "The filename of the xlsx report.")]
			public string OutReport { get; set; }

			[Option('s', "sid", HelpText = "File that contains a list of comma separated SID,name that will be used during report generation to resolve SIDs.")]
			public string SIDFileIn { get; set; }

			[Option("dns", Default = true, HelpText = "Perform a DNS resolution on host names before scan. If the resolution fails the target will not be scanned. (If the target is an IP address the resolution will not be performed)")]
			public bool ResolveHostname { get; set; }

		}

		[Verb("getACL", HelpText = "Get NTFS ACL.")]
		class GetACLOptions : CommonOptions
		{
			[Option('t', "target", Required = true, HelpText = "Target to scan.")]
			public string target { get; set; }

		}

		[Verb("reporter", HelpText = "Generate report of a previous scan.")]
		class ReporterOptions : CommonOptions
		{
			[Option('t', "scantype", Required = true, Default = "SMB")]
			public string ScanType { get; set; }

			[Option('i', "inputfile", HelpText = "Serialized result.", Required = true)]
			public string InputFile { get; set; }

			[Option('o', "outputfile", Required = true, HelpText = "Report filename (without extension).")]
			public string OutReport { get; set; }

			[Option('s', "sid", HelpText = "File that contains a list of comma separated SID,name that will be used during report generation to resolve SIDs.")]
			public string SIDFile { get; set; }
		}

		[Verb("mergeSMB", HelpText = "Merge two scans data into one file.")]
		class MergeSMBOptions : CommonOptions
		{

			[Option('i', "scan1", Required = true, HelpText = "Serialized result.")]
			public string InputFile { get; set; }

			[Option('m', "scan2", Required = true, HelpText = "Serialized result to merge to scan1.")]
			public string InputFile2 { get; set; }

			[Option('x', "outData", Required = true, HelpText = "File path to save the merge result.")]
			public string OutFile { get; set; }
		}

		static void SetCommonOptions(CommonOptions options)
		{
			Config.Debug = options.Debug;
		}

		static void SetScanCommonOptions(ScanCommonOptions options)
		{
			Config.TryResolveHostName = options.ResolveHostname;
			Config.RecursiveLevel = options.RecursiveLevel;

			if (options.BlackList.Length == 0)
			{
				Config.SharesRecursiveScanBlackList = new List<string>();
			}
			if (options.BlackList.Contains(",") || !File.Exists(options.BlackList))
			{
				Config.SharesRecursiveScanBlackList = new List<string>(options.BlackList.Split(','));
			}
			else
			{
				Config.SharesRecursiveScanBlackList = new List<string>(File.ReadAllLines(options.BlackList));
			}

			if (options.WhiteList.Length == 0)
			{
				Config.SharesScanWhiteList = new List<string>();
			}
			else if (options.WhiteList.Contains(",") || !File.Exists(options.WhiteList))
			{
				Config.SharesScanWhiteList = new List<string>(options.WhiteList.Split(','));
			}
			else
			{
				Config.SharesScanWhiteList = new List<string>(File.ReadAllLines(options.WhiteList));
			}

		}

		static void SetMTOptions(MTOptions options)
		{
			Config.MaxThreads = options.MaxThreads;
			Config.ThreadJoinTimeout = options.ThreadJoinTimeout;
			Config.ThreadJoinMaxAttempts = options.ThreadJoinMaxAttempts;

		}

		static void SetDirScanMTOptions(DirScanMTOptions options)
		{
			Config.DirScanMaxThreads = options.DirScanMaxThreads;
			Config.DirScanThreadJoinTimeout = options.DirScanThreadJoinTimeout;
			Config.DirScanThreadJoinMaxAttempts = options.DirScanThreadJoinMaxAttempts;
		}

		static int RunscanSMBVerb(SMBOptions options)
		{

			Dictionary<string, SMBHost> hosts = new Dictionary<string, SMBHost>();
			SetCommonOptions(options);
			SetScanCommonOptions(options);
			SetMTOptions(options);
			SetDirScanMTOptions(options);

			if (options.TargetType.ToLower() == "hosts")
			{
				if (options.MaxThreads > 1)
				{
					hosts = SharesScanner.MTScanHosts(SharesMapperUtils.AddrParser.ParseTargets(options.Target).ToArray());
				}
				else
				{
					hosts = SharesScanner.ScanHosts(SharesMapperUtils.AddrParser.ParseTargets(options.Target).ToArray());
				}
			}
			else if (options.TargetType.ToLower() == "file")
			{
				if (options.MaxThreads > 1)
				{
					hosts = SharesScanner.MTScanHosts(options.Target);
				}
				else
				{
					hosts = SharesScanner.ScanHosts(options.Target);
				}
			}
			else
			{
				throw new ArgumentException("Unknown targetType value.");
			}

			SMBSharesMapperSerializer.SerializeHosts(hosts, options.OutData);

			if (options.OutReport.Length > 0)
			{
				if (File.Exists(options.SIDFileIn))
				{
					ReportGenerator.XLSXReport.LoadSIDResolutionFile(options.SIDFileIn);
				}
				ReportGenerator.XLSXReport.GenerateSMBHostsReport(hosts, options.OutReport);
				ReportGenerator.XLSXReport.SIDCahe.Clear();
			}

			return 0;
		}

		static int RunRescanSMBVerb(RescanSMBOptions options)
		{
			Dictionary<string, SMBHost> hosts;

			SetCommonOptions(options);
			SetScanCommonOptions(options);
			SetMTOptions(options);
			SetDirScanMTOptions(options);

			Config.ScanForNewShares = options.ScanForNewShares;
			Config.ScanForNewSharesRecusiveLevel = options.RecursiveLevel;
			Config.ScanForNewSharesTryResolveHostName = options.ResolveHostname;

			if (File.Exists(options.InputFile))
			{
				hosts = SMBSharesMapperSerializer.DeserializeHosts(options.InputFile);
				if (hosts == null)
				{
					return -1;
				}

				if (options.AppendHosts != null)
				{
					SharesScanner.AppendHosts(hosts, options.AppendHosts.Split(','), Config.ScanForNewSharesTryResolveHostName);
				}

				if (options.AppendHostsFile != null)
				{
					SharesScanner.AppendHosts(hosts, options.AppendHostsFile, Config.ScanForNewSharesTryResolveHostName);
				}

				if (options.MaxThreads > 1)
				{
					SharesScanner.MTReScanHosts(hosts);
				}
				else
				{
					SharesScanner.ReScanHosts(hosts);
				}

				SMBSharesMapperSerializer.SerializeHosts(hosts, options.OutData);

				if (options.OutReport.Length > 0)
				{
					if (File.Exists(options.SIDFileIn))
					{
						ReportGenerator.XLSXReport.LoadSIDResolutionFile(options.SIDFileIn);
					}
					ReportGenerator.XLSXReport.GenerateSMBHostsReport(hosts, options.OutReport);
					ReportGenerator.XLSXReport.SIDCahe.Clear();
				}

			}

			return 0;
		}

		static int RunReporterVerb(ReporterOptions options)
		{
			if (options.ScanType.ToUpper() == "SMB")
			{
				Dictionary<string, SMBHost> hosts;
				SetCommonOptions(options);

				if (File.Exists(options.InputFile))
				{
					hosts = SMBSharesMapperSerializer.DeserializeHosts(options.InputFile);
					if (hosts == null)
					{
						return -1;
					}

					if (options.OutReport.Length > 0)
					{
						if (File.Exists(options.SIDFile))
						{
							ReportGenerator.XLSXReport.LoadSIDResolutionFile(options.SIDFile);
						}
						ReportGenerator.XLSXReport.GenerateSMBHostsReport(hosts, options.OutReport);
						ReportGenerator.XLSXReport.SIDCahe.Clear();
					}

				}
			}
			return 0;
		}

		static int RunGetSMBSharesVerb(GetSMBSharesOptions options)
		{

			SetCommonOptions(options);

			Config.PrintACL = options.PrintACL;

			SharesScanner.PreviewHostShares(options.HostName);

			return 0;
		}

		static int RunScanSMBShareDir(ScanSMBShareDirOptions options)
		{

			SetCommonOptions(options);
			SetDirScanMTOptions(options);

			Config.TryResolveHostName = options.ResolveHostname;
			Config.RecursiveLevel = options.RecursiveLevel;


			List<ScanDirectoryResult> result = new List<ScanDirectoryResult>();

			foreach (string hostname in SharesMapperUtils.AddrParser.ParseTargets(options.target))
			{

				if (Config.TryResolveHostName && !SharesScanner.TryResolveHostName(hostname))
				{
					Console.WriteLine("[-][" + DateTime.Now + "] Could not resolve " + hostname);
					continue;
				}
				result.Add(SharesScanner.ScanShareDirectory("\\\\" + hostname + "\\" + options.Path, Config.RecursiveLevel));
			}

			if (options.OutReport.Length > 0)
			{
				if (File.Exists(options.SIDFileIn))
				{
					ReportGenerator.XLSXReport.LoadSIDResolutionFile(options.SIDFileIn);
				}
				ReportGenerator.XLSXReport.GenerateSMBDirectoryScanResultReport(result, options.OutReport);
				ReportGenerator.XLSXReport.SIDCahe.Clear();
			}

			return 0;
		}

		static int RunPrintSMBACLVerb(GetACLOptions options)
		{
			SetCommonOptions(options);

			Config.PrintACL = true;

			ShareACLUtils.PrintShareAccesses(ShareACLUtils.GetShareDirectoryACL(options.target));
			return 0;
		}

		static int RunMergeSMBVerb(MergeSMBOptions options)
		{
			Data.MergeScanResult(options.InputFile, options.InputFile2, options.OutFile);
			return 0;
		}

		static void Main(string[] args)
		{

			var result = Parser.Default.ParseArguments<SMBOptions, RescanSMBOptions, ReporterOptions, MergeSMBOptions, GetSMBSharesOptions, ScanSMBShareDirOptions, GetACLOptions>(args);

			result.MapResult(
				(SMBOptions opts) => RunscanSMBVerb(opts),
				(RescanSMBOptions opts) => RunRescanSMBVerb(opts),
				(ReporterOptions opts) => RunReporterVerb(opts),
				(GetSMBSharesOptions opts) => RunGetSMBSharesVerb(opts),
				(ScanSMBShareDirOptions opts) => RunScanSMBShareDir(opts),
				(MergeSMBOptions opts) => RunMergeSMBVerb(opts),
				(GetACLOptions opts) => RunPrintSMBACLVerb(opts),
				errs => 1
			);
		}



	}
}
