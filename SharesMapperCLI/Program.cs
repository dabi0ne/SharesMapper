using System;
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

		class ScanCommonOptions : CommonOptions
		{

			[Option('r', "recursiveLevel", Default = 0, HelpText = "How deep the scan should go into shares.")]
			public int RecursiveLevel { get; set; }

			[Option("dns", Default = true, HelpText = "Perform a DNS resolution on host names before scan. If the resolution fails the target will not be scanned. (If the target is an IP address the resolution will not be performed)")]
			public bool ResolveHostname { get; set; }

			[Option('o', "outReport", Default = "", HelpText = "The filename of the xlsx report.")]
			public string OutReport { get; set; }

			[Option('s', "SID", HelpText = "File that contains a list of comma separated SID,name that will be used during report generation to resolve SIDs.")]
			public string SIDFileIn { get; set; }

			[Option('x', "outData", Required = true, HelpText = "File path to save the serialized result to be used for future scan.")]
			public string OutData { get; set; }

			[Option('c', "maxThreads", Default = 1, HelpText = "How many concurrent threads will be launched.")]
			public int MaxThreads { get; set; }

			[Option('m', "maxAttemps", Default = 20, HelpText = "How many tries to join a thread before killing.")]
			public int ThreadJoinMaxAttempts { get; set; }

			[Option('j', "joinTimeout", Default = 100, HelpText = "How much time in ms the join call will wait.")]
			public int ThreadJoinTimeout { get; set; }

			[Option('b', "blacklist", Default = "ADMIN$", HelpText = "List of comma separated shares names to not scan recursively (or file of shares list)" )]
			public string BlackList { get; set; }
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

		[Verb("getACL", HelpText = "Preview target ACL.")]
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
			Config.MaxThreads = (uint)options.MaxThreads;
			Config.TryResolveHostName = options.ResolveHostname;
			Config.RecursiveLevel = options.RecursiveLevel;

			Config.ThreadJoinTimeout = options.ThreadJoinTimeout;
			Config.ThreadJoinMaxAttempts = (uint)options.ThreadJoinMaxAttempts;

			if (options.BlackList.Contains(",") || !File.Exists(options.BlackList))
			{
				Config.SharesRecursiveScanBlackList = new List<string>(options.BlackList.Split(','));
			}
			else
			{
				Config.SharesRecursiveScanBlackList = new List<string>(File.ReadAllLines(options.BlackList));
			}

		}

		static int RunscanSMBVerb(SMBOptions options)
		{

			Dictionary<string, SMBHost> hosts = new Dictionary<string, SMBHost>();
			SetCommonOptions(options);
			SetScanCommonOptions(options);

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

		static int RunGetACLVerb(GetACLOptions options)
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

			var result = Parser.Default.ParseArguments<SMBOptions, RescanSMBOptions, ReporterOptions, MergeSMBOptions, GetSMBSharesOptions, GetACLOptions>(args);

			result.MapResult(
				(SMBOptions opts) => RunscanSMBVerb(opts),
				(RescanSMBOptions opts) => RunRescanSMBVerb(opts),
				(ReporterOptions opts) => RunReporterVerb(opts),
				(GetSMBSharesOptions opts) => RunGetSMBSharesVerb(opts),
				(GetACLOptions opts) => RunGetACLVerb(opts),
				(MergeSMBOptions opts) => RunMergeSMBVerb(opts),
				errs => 1
			);
		}

		

	}
}
