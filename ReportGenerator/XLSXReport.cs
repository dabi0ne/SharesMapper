using System;
using System.Collections.Generic;
using System.Linq;
using SMBSharesUtils;
using System.IO;

namespace ReportGenerator
{
	public class XLSXReport
	{
		
		public static Dictionary<string, string> SIDCahe = new Dictionary<string, string>();

		/// <summary>
		/// Generate an Excel file from a list of SMBScanResult.
		/// </summary>
		/// <param name="hosts">A list of SMBScanResult objects</param>
		/// <param name="filename">The name to use for the report (filename_SharesScanResult.xls)</param>
		public static void GenerateSMBHostsReport(Dictionary<string, SMBHost> hosts, string filename)
		{
			int row = 1;
			int col = 1;

			var workbook = new ClosedXML.Excel.XLWorkbook();
			var worksheet = workbook.Worksheets.Add("Scan Result");

			row = WriteHeader(worksheet, row, col);

			foreach (SMBHost host in hosts.Values)
			{
				if (host.hostSharesScanResult.Count > 0)
				{
					foreach (SMBScanResult scanResult in host.hostSharesScanResult.Values)
					{
						row = WriteShare(worksheet, scanResult.shareACL, row);
						if (scanResult.shareSubDirectories.Count > 0)
						{
							row = WriteShareDirectories(worksheet, scanResult.shareSubDirectories, row, 1, scanResult.shareACL.share.shareInfo.shi1_remark);
						}
					}
				}
				else
				{
					//TODO : write host without shares
				}
			}
			
			worksheet.Range("E2", "E" + row.ToString()).AddConditionalFormat().WhenContains("New ACE").Fill.SetBackgroundColor(ClosedXML.Excel.XLColor.Green);
			worksheet.Range("E2", "E" + row.ToString()).AddConditionalFormat().WhenContains("No change").Fill.SetBackgroundColor(ClosedXML.Excel.XLColor.Orange);
			worksheet.Range("E2", "E" + row.ToString()).AddConditionalFormat().WhenContains("ACE Removed").Fill.SetBackgroundColor(ClosedXML.Excel.XLColor.Red);
			worksheet.Range("E2", "E" + row.ToString()).AddConditionalFormat().WhenContains("No ACE").Fill.SetBackgroundColor(ClosedXML.Excel.XLColor.Gray);

			workbook.SaveAs(filename + "_ShareScanResult.xlsx");
		}

		/// <summary>
		/// Write the first row on the Excel worksheet.
		/// </summary>
		/// <param name="worksheet">An Excel worksheet object on which we write</param>
		/// <param name="row">The row number where to write</param>
		/// <param name="col">The column number where to write</param>
		/// <returns>The next empty row</returns>
		private static int WriteHeader(ClosedXML.Excel.IXLWorksheet worksheet, int row = 1, int col = 1)
		{
			
			worksheet.Cell(row, col++).Value = "Hostname";
			worksheet.Cell(row, col++).Value = "UNC Path";
			worksheet.Cell(row, col++).Value = "Remark";
			worksheet.Cell(row, col++).Value = "Level";
			worksheet.Cell(row, col++).Value = "ACE status";
			worksheet.Cell(row, col++).Value = "ACE_ID";
			worksheet.Cell(row, col++).Value = "DateTime";
			worksheet.Cell(row, col++).Value = "AccessControlType";
			worksheet.Cell(row, col++).Value = "CompactReadableFileSystemRights";
			worksheet.Cell(row, col++).Value = "ReadableFileSystemRights";
			worksheet.Cell(row, col++).Value = "ReadableIdentityReference";
			worksheet.Cell(row, col++).Value = "IdentityReference";
			worksheet.Cell(row, col++).Value = "Owner";
			worksheet.Cell(row, col++).Value = "OwnerSID";
			worksheet.Cell(row, col++).Value = "IsInherited";
			worksheet.Cell(row, col++).Value = "InheritanceFlags";
			worksheet.Cell(row, col++).Value = "PropagationFlags";
			col = 1;

			return ++row;
		}

		/// <summary>
		/// Write ACLs of a directory and his subdirectories into an Excel file.
		/// </summary>
		/// <param name="scanDirectoryResult">Object returned by an ACL scan on a UNC path</param>
		/// <param name="filename">The name to use for the report (filename_ShareScanResult.xls)</param>
		public static void GenerateSMBDirectoryScanResultReport(List<ScanDirectoryResult> scanDirectoryResults, string filename)
		{
			int row = 1;
			int col = 1;

			var workbook = new ClosedXML.Excel.XLWorkbook();
			var worksheet = workbook.Worksheets.Add("Scan Result");

			row = WriteHeader(worksheet, row, col);

			foreach(ScanDirectoryResult scanDirectoryResult in scanDirectoryResults)
			{
				WriteShareDirectories(worksheet, new Dictionary<string, ScanDirectoryResult> { { scanDirectoryResult.shareDirectoryACL.shareDirectory, scanDirectoryResult } }, row);
			}

			workbook.SaveAs(filename + "_ShareDirectoryScan.xlsx");
		}

		/// <summary>
		/// Write recursively ACL of share's subdirectories into worksheet.
		/// </summary>
		/// <param name="worksheet">Worksheet to write on</param>
		/// <param name="shareSubDirectoriesResult">A list of ScanDirectoryResult object</param>
		/// <param name="row">The row number to write on</param>
		/// <param name="level">The depth of the directory regarding the share root</param>
		/// <param name="shareRemark">A remark about the directory</param>
		/// <returns>First free row number</returns>
		private static int WriteShareDirectories(ClosedXML.Excel.IXLWorksheet worksheet, Dictionary<string, ScanDirectoryResult> shareSubDirectoriesResult, int row, int level = 0, string shareRemark = "")
		{
			bool debug = false;
			if (Environment.GetEnvironmentVariable("SMBShareMapperDebug") != null)
			{
				debug = true;
			}

			foreach (ScanDirectoryResult scanDirectoryResult in shareSubDirectoriesResult.Values)
			{
				if (debug)
				{
					Console.WriteLine("[*] Writing directory " + scanDirectoryResult.shareDirectoryACL.shareDirectory + " ACLs ...");
				}
				int col = 1;
				if (scanDirectoryResult.shareDirectoryACL.directoryACL.Count > 0)
				{
					row = InsertACL(
							worksheet,
							ExtractHostNameFromPath(scanDirectoryResult.shareDirectoryACL.shareDirectory),
							scanDirectoryResult.shareDirectoryACL.shareDirectory,
							shareRemark,
							level,
							scanDirectoryResult.shareDirectoryACL.directoryACL,
							row,
							null,
							(scanDirectoryResult.shareDirectoryACL.directoryACLEvolution.Count > 0) ? scanDirectoryResult.shareDirectoryACL.directoryACLEvolution.First().Value.Keys.ToList(): null
						);
				}
				else
				{
					worksheet.Cell(row, col++).Value = ExtractHostNameFromPath(scanDirectoryResult.shareDirectoryACL.shareDirectory);
					worksheet.Cell(row, col++).Value = scanDirectoryResult.shareDirectoryACL.shareDirectory;
					worksheet.Cell(row, col++).Value = shareRemark;
					worksheet.Cell(row, col++).Value = level;
					worksheet.Cell(row, col++).Value = "No ACE";
					worksheet.Cell(row, col++).Value = "";
					worksheet.Cell(row, col++).Value = scanDirectoryResult.shareDirectoryACL.discoveryDateTime;
					row++;
				}

				if (scanDirectoryResult.shareDirectoryACL.directoryACLEvolution.Count > 0)
				{
					row = InsertACLEvolution(
							worksheet,
							ExtractHostNameFromPath(scanDirectoryResult.shareDirectoryACL.shareDirectory),
							scanDirectoryResult.shareDirectoryACL.shareDirectory,
							shareRemark,
							level,
							scanDirectoryResult.shareDirectoryACL.directoryACLEvolution,
							row,
							scanDirectoryResult.shareDirectoryACL.directoryACL.Keys.ToList()
						);
				}

				if (scanDirectoryResult.shareDirectorySubDirectories.Count > 0)
				{
					row = WriteShareDirectories(worksheet, scanDirectoryResult.shareDirectorySubDirectories, row, level + 1);
				}
			}

			return row;
		}

		private static string ExtractHostNameFromPath(string path)
		{
			if (path.StartsWith("\\\\"))
			{
				try
				{
					return path.Split('\\')[2];
				}
				catch (Exception)
				{
					return "";
				}
			}

			return System.Environment.MachineName;
		}

		/// <summary>
		/// Write a share ACL into worksheet and the evolution of his ACL.
		/// </summary>
		/// <param name="worksheet"></param>
		/// <param name="shareACL"></param>
		/// <param name="row">Row number to start from</param>
		/// <returns>First free row number</returns>
		static int WriteShare(ClosedXML.Excel.IXLWorksheet worksheet, SMBShareACL shareACL, int row)
		{
			if (Config.Debug)
			{
				Console.WriteLine("[*] Writing share on " + row.ToString() + " " + shareACL.share.ToString() + " ACLs ...");
			}
			int col = 1;
			if (shareACL.shareACL.Count > 0)
			{
				row = InsertACL(
					worksheet,
					shareACL.share.hostname,
					shareACL.share.ToString(),
					shareACL.share.shareInfo.shi1_remark,
					0,
					shareACL.shareACL,
					row,
					null,
					(shareACL.shareACLEvolution.Count > 0) ? shareACL.shareACLEvolution.First().Value.Keys.ToList() : null
					);
			}
			else 
			{
				worksheet.Cell(row, col++).Value = shareACL.share.hostname;
				worksheet.Cell(row, col++).Value = shareACL.share.ToString();
				worksheet.Cell(row, col++).Value = shareACL.share.shareInfo.shi1_remark;
				worksheet.Cell(row, col++).Value = 0;
				worksheet.Cell(row, col++).Value = "No ACE";
				worksheet.Cell(row, col++).Value = "";
				worksheet.Cell(row, col++).Value = shareACL.discoveryDateTime;
				row++;
			}

			if (shareACL.shareACLEvolution.Count > 0)
			{
				row = InsertACLEvolution(
						worksheet,
						shareACL.share.hostname,
						shareACL.share.ToString(),
						shareACL.share.shareInfo.shi1_remark,
						0,
						shareACL.shareACLEvolution,
						row,
						shareACL.shareACL.Keys.ToList()
					);
			}
			
			return row;
		}

		/// <summary>
		/// Write ACL evolution into worksheet.
		/// </summary>
		/// <param name="worksheet"></param>
		/// <param name="hostname"></param>
		/// <param name="shareName"></param>
		/// <param name="remark"></param>
		/// <param name="level"></param>
		/// <param name="ACLEvolution"></param>
		/// <param name="row">Row number to start from</param>
		/// <param name="lastScan">List of ACE_ID of the first scan</param>
		/// <returns></returns>
		static int InsertACLEvolution(ClosedXML.Excel.IXLWorksheet worksheet, string hostname, string shareName, string remark, int level, SortedDictionary<DateTime, Dictionary<string,Dictionary<string,string>>> ACLEvolution, int row, List<string> lastScan = null)
		{
			int count = 1;
			List<string> nextScan;
			foreach (Dictionary<string, Dictionary<string, string>> acl in ACLEvolution.Values)
			{
				if (ACLEvolution.Count > count)
				{
					nextScan = ACLEvolution[ACLEvolution.Keys.ToList()[count]].Keys.ToList();
					count++;
				}
				else
				{
					nextScan = null;
				}
				row = InsertACL(
					worksheet,
					hostname,
					shareName,
					remark,
					level,
					acl,
					row,
					lastScan,
					nextScan			
					);
				lastScan = acl.Keys.ToList();
				
			}

			return row;
		}

		/// <summary>
		/// Write ACL into worksheet.
		/// </summary>
		/// <param name="worksheet"></param>
		/// <param name="hostname"></param>
		/// <param name="shareName"></param>
		/// <param name="remark"></param>
		/// <param name="level"></param>
		/// <param name="acl"></param>
		/// <param name="row">Row number to start from</param>
		/// <param name="lastScan">List of ACE_ID of the previous scan</param>
		/// <param name="nextScan">List of ACE_ID of the scan after the current one</param>
		/// <returns></returns>
		static int InsertACL(ClosedXML.Excel.IXLWorksheet worksheet, string hostname, string shareName, string remark, int level, Dictionary<string, Dictionary<string, string>> acl, int row, List<string> lastScan = null, List<string> nextScan = null)
		{
			int col = 1;

			if (acl.Count > 0)
			{
				foreach (var entry in acl)
				{
					if (Config.Debug && entry.Key != "noACE")
					{
						Console.WriteLine("[*] Writing share ACE on " + row.ToString() + " " + entry.Value["AccessControlType"] + " " + entry.Value["ReadableFileSystemRights"] + " to " + entry.Value["ReadableIdentityReference"] + " on " + shareName);
					}
					worksheet.Cell(row, col++).Value = hostname;
					worksheet.Cell(row, col++).Value = shareName;
					worksheet.Cell(row, col++).Value = remark;
					worksheet.Cell(row, col++).Value = level;

					if (entry.Key == "noACE")
					{
						worksheet.Cell(row, col++).Value = "No ACE";
						worksheet.Cell(row, col++).Value = "";
						worksheet.Cell(row, col++).Value = entry.Value["DiscoveryDateTime"];
					}
					else
					{
						if (nextScan != null  && lastScan != null)
						{
							if (lastScan.Contains(entry.Value["IdentityReference"] + "-" + entry.Value["FileSystemRights"]) && nextScan.Contains(entry.Value["IdentityReference"] + "-" + entry.Value["FileSystemRights"]))
							{
								worksheet.Cell(row, col++).Value = "No change";
							}
							else if (!lastScan.Contains(entry.Value["IdentityReference"] + "-" + entry.Value["FileSystemRights"]) && nextScan.Contains(entry.Value["IdentityReference"] + "-" + entry.Value["FileSystemRights"]))
							{
								worksheet.Cell(row, col++).Value = "New ACE";
							}
							else if (lastScan.Contains(entry.Value["IdentityReference"] + "-" + entry.Value["FileSystemRights"]) && !nextScan.Contains(entry.Value["IdentityReference"] + "-" + entry.Value["FileSystemRights"]))
							{
								worksheet.Cell(row, col++).Value = "ACE Removed ";
							}
							else
							{
								worksheet.Cell(row, col++).Value = "ACE Removed";
							}

						}
						else if (nextScan != null)
						{
							worksheet.Cell(row, col++).Value = nextScan.Contains(entry.Value["IdentityReference"] + "-" + entry.Value["FileSystemRights"]) ? "New ACE" : "ACE removed";
						}
						else if (lastScan != null)
						{
							worksheet.Cell(row, col++).Value = lastScan.Contains(entry.Value["IdentityReference"] + "-" + entry.Value["FileSystemRights"]) ? "No change" : "New ACE";
						}
						else
						{
							worksheet.Cell(row, col++).Value = "New ACE";
						}
						worksheet.Cell(row, col++).Value = entry.Value["IdentityReference"] + "-" + entry.Value["FileSystemRights"];
						worksheet.Cell(row, col++).Value = entry.Value["DiscoveryDateTime"];
						worksheet.Cell(row, col++).Value = entry.Value["AccessControlType"];
						worksheet.Cell(row, col++).Value = entry.Value["CompactReadableFileSystemRights"];
						worksheet.Cell(row, col++).Value = entry.Value["ReadableFileSystemRights"];
						worksheet.Cell(row, col++).Value = (entry.Value["ReadableIdentityReference"].StartsWith("S-1-5")) ? TranslateSid(entry.Value["ReadableIdentityReference"]) : entry.Value["ReadableIdentityReference"];
						worksheet.Cell(row, col++).Value = entry.Value["IdentityReference"];
						worksheet.Cell(row, col++).Value = (entry.Value["Owner"].StartsWith("S-1-5")) ? TranslateSid(entry.Value["Owner"]) : entry.Value["Owner"];
						worksheet.Cell(row, col++).Value = entry.Value["OwnerSID"];
						worksheet.Cell(row, col++).Value = entry.Value["IsInherited"];
						worksheet.Cell(row, col++).Value = entry.Value["InheritanceFlags"];
						worksheet.Cell(row, col++).Value = entry.Value["PropagationFlags"];
					}
					col = 1;
					row++;
				}
			}
			
			return row;
		}

		/// <summary>
		/// Import list of association SID => Human readable from the file
		/// </summary>
		/// <param name="filename"></param>
		/// <returns></returns>
		public static bool LoadSIDResolutionFile(string filename)
		{
			string line;
			string[] entry;
			try
			{ 
				using (StreamReader sr = new StreamReader(filename))
				{
					while (sr.Peek() > 0)
					{
						line = sr.ReadLine();
						entry = line.Split(new char[] { ',' }, 2);
						try
						{
							SIDCahe.Add(entry[0], entry[1]);
						}
						catch (ArgumentException)
						{}
					}
				}
				return true;
			}
			catch (Exception e)
			{
				Console.WriteLine("[-] Error on loading SID resolution file " + e.Message);
				return false;
			}
		}

		/// <summary>
		/// Return a translation of a SID if it exists on the cache.
		/// </summary>
		/// <param name="sid"></param>
		/// <returns></returns>
		private static string TranslateSid(string sid)
		{
			string dn;
			if(SIDCahe.TryGetValue(sid, out dn))
			{
				return dn;
			}
			return sid;
		}
	}
}
