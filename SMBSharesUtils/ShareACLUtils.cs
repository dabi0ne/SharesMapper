using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.Serialization;

namespace SMBSharesUtils
{

	/// <summary>
	/// </summary>
	public class ShareACLUtils
	{
		public static Dictionary<string, string> SidCache = new Dictionary<string, string>();
	
		/// <summary>
		/// Pretty print SMBShareACL object
		/// </summary>
		/// <param name="shareACL"></param>
		public static void PrintShareAccesses(SMBShareACL shareACL)
		{
			PrintShareAccesses(new SMBShareDirectoryACL { shareDirectory = shareACL.share.ToString(), directoryACL = shareACL.shareACL });
		}

		/// <summary>
		/// Pretty print SMBShareDirectoryACL object
		/// </summary>
		/// <param name="shareDirectoryACL"></param>
		public static void PrintShareAccesses(SMBShareDirectoryACL shareDirectoryACL)
		{
			Console.WriteLine(shareDirectoryACL.shareDirectory);
			if (Config.PrintACL)
			{
				foreach (var aclEntry in shareDirectoryACL.directoryACL)
				{
					if (aclEntry.Key == "noACE")
					{
						break;
					}
					Console.WriteLine("\t\\_____ " + aclEntry.Value["ReadableIdentityReference"]);

					Console.WriteLine("\t|     \\_______________ SID               : " + aclEntry.Value["IdentityReference"]);
					Console.WriteLine("\t|     |_______________ AccessControlType : " + aclEntry.Value["AccessControlType"]);
					Console.WriteLine("\t|     |_______________ FileSystemRights  : " + aclEntry.Value["CompactReadableFileSystemRights"]);
					Console.WriteLine("\t|     |_______________ IsInherited       : " + aclEntry.Value["IsInherited"]);
					Console.WriteLine("\t|     |_______________ InheritanceFlags  : " + aclEntry.Value["InheritanceFlags"]);
					Console.WriteLine("\t|     \\_______________ PropagationFlags  : " + aclEntry.Value["PropagationFlags"]);
					Console.WriteLine("\t|");
				}
				Console.WriteLine("\t*");
			}
		}

		/// <summary>
		/// Get share ACL
		/// </summary>
		/// <param name="path"></param>
		/// <returns></returns>
		public static Dictionary<string, Dictionary<string, string>> GetShareACL(string path)
		{
			AuthorizationRuleCollection acl = null;
			string currentUser;
			string ownerSID = null;
			bool error = false;
			var shareRights = new Dictionary<string, Dictionary<string, string>>();

			try
			{
				if (Config.Debug) { Console.WriteLine("[*] Getting " + path + " AccessRules ..."); }
				acl = Directory.GetAccessControl(path).GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));
			}
			catch (UnauthorizedAccessException)
			{
				if (Config.Debug) { Console.WriteLine("[-][" + DateTime.Now.ToString() + "] Unable to read " + path + " access rules."); }
				error = true;
			}
			catch
			{
				error = true;
			}

			if (!error)
			{
				try
				{
					ownerSID = Directory.GetAccessControl(path).GetOwner(typeof(System.Security.Principal.SecurityIdentifier)).ToString();
				}
				catch (Exception e)
				{
					Console.WriteLine("[-][" + DateTime.Now.ToString() + "] Error on getting " + path + "owner (" + e.Message + ").");
				}
			
				foreach (FileSystemAccessRule ace in acl)
				{
					try
					{
						if (!SidCache.TryGetValue(ace.IdentityReference.Value, out currentUser))
						{
							currentUser = (Config.TryResolveSID) ? ConvertSidToName(ace.IdentityReference.Value) : throw new IdentityNotMappedException();
							SidCache.Add(ace.IdentityReference.Value, currentUser);
						}
					}
					catch (IdentityNotMappedException)
					{
						currentUser = ace.IdentityReference.ToString();
					}

					try
					{
						shareRights.Add(
							ace.IdentityReference.Value.ToString() + "-" + ((UInt32)ace.FileSystemRights).ToString(),
							new Dictionary<string, string> {
							{ "CompactReadableFileSystemRights", ConvertFileSystemRights((UInt32)ace.FileSystemRights, true) },
							{ "ReadableFileSystemRights", ConvertFileSystemRights((UInt32)ace.FileSystemRights, false) },
							{ "FileSystemRights", ((UInt32)ace.FileSystemRights).ToString() },
							{ "AccessControlType", ace.AccessControlType.ToString() },
							{ "IdentityReference", ace.IdentityReference.Value },
							{ "ReadableIdentityReference", currentUser },
							{ "IsInherited", ace.IsInherited.ToString() },
							{ "InheritanceFlags", ace.InheritanceFlags.ToString() },
							{ "PropagationFlags", ace.PropagationFlags.ToString() },
							{ "OwnerSID", ownerSID },
							{ "Owner", (Config.TryResolveSID) ? ConvertSidToName(ownerSID) : ownerSID },
							{ "DiscoveryDateTime", DateTime.UtcNow.ToString() }
							}
						);
					} catch (ArgumentException e)
					{
						if (Config.Debug)
						{
							Console.WriteLine("[!] " + e.Message);
						}
					}
				}
			}
			// if no ACE where found, we add only a DateTime with the specific key noACE. This is useful to get for iterative scans.
			if (shareRights.Count == 0)
			{
				shareRights.Add("noACE",
							new Dictionary<string, string> {
								{ "DiscoveryDateTime", DateTime.UtcNow.ToString() }
							});
			}
			return shareRights;
		}

		public static SMBShareDirectoryACL GetShareDirectoryACL(string shareDirectory)
		{
			return new SMBShareDirectoryACL { shareDirectory = shareDirectory, directoryACL = GetShareACL(shareDirectory) };
		}

		public static SMBShareACL GetShareACL(HostShare share)
		{
			if (share.shareInfo.shi1_type == (UInt16)SHARE_TYPE.STYPE_IPC || share.shareInfo.shi1_type == (UInt16)SHARE_TYPE.STYPE_PRINTQ)
			{
				if (Config.Debug) { Console.WriteLine("[*][" + DateTime.Now.ToString() + "] The shareInfo " + share.ToString() + " will not be scanned"); }
				return new SMBShareACL { share = share, shareACL = new Dictionary<string, Dictionary<string, string>>() };
			}
			return new SMBShareACL { share = share, shareACL = GetShareACL(share.ToString()) };
		}

		public static List<SMBShareACL> GetSharesACL(HostShare[] shares)
		{

			var sharesACL = new List<SMBShareACL>();

			foreach (HostShare share in shares)
			{
				sharesACL.Add(GetShareACL(share));
			}

			return sharesACL;
		}

		public static string ConvertSidToName(string sid)
		{
			switch (sid)
			{
				case "S-1-0": return "Null Authority";
				case "S-1-0-0": return "Nobody";
				case "S-1-1": return "World Authority";
				case "S-1-1-0": return "Everyone";
				case "S-1-2": return "Local Authority";
				case "S-1-2-0": return "Local";
				case "S-1-2-1": return "Console Logon ";
				case "S-1-3": return "Creator Authority";
				case "S-1-3-0": return "Creator Owner";
				case "S-1-3-1": return "Creator Group";
				case "S-1-3-2": return "Creator Owner Server";
				case "S-1-3-3": return "Creator Group Server";
				case "S-1-3-4": return "Owner Rights";
				case "S-1-4": return "Non-unique Authority";
				case "S-1-5": return "NT Authority";
				case "S-1-5-1": return "Dialup";
				case "S-1-5-2": return "Network";
				case "S-1-5-3": return "Batch";
				case "S-1-5-4": return "Interactive";
				case "S-1-5-6": return "Service";
				case "S-1-5-7": return "Anonymous"; 
				case "S-1-5-8": return "Proxy";
				case "S-1-5-9": return "Enterprise Domain Controllers";
				case "S-1-5-10": return "Principal Self";
				case "S-1-5-11": return "Authenticated Users";
				case "S-1-5-12": return "Restricted Code";
				case "S-1-5-13": return "Terminal Server Users";
				case "S-1-5-14": return "Remote Interactive Logon";
				case "S-1-5-15": return "This Organization ";
				case "S-1-5-17": return "This Organization ";
				case "S-1-5-18": return "Local System";
				case "S-1-5-19": return "NT Authority";
				case "S-1-5-20": return "NT Authority";
				case "S-1-5-80-0": return "All Services ";
				case "S-1-5-32-544": return "BUILTIN\\Administrators";
				case "S-1-5-32-545": return "BUILTIN\\Users";
				case "S-1-5-32-546": return "BUILTIN\\Guests";
				case "S-1-5-32-547": return "BUILTIN\\Power Users";
				case "S-1-5-32-548": return "BUILTIN\\Account Operators";
				case "S-1-5-32-549": return "BUILTIN\\Server Operators";
				case "S-1-5-32-550": return "BUILTIN\\Print Operators";
				case "S-1-5-32-551": return "BUILTIN\\Backup Operators";
				case "S-1-5-32-552": return "BUILTIN\\Replicators";
				case "S-1-5-32-554": return "BUILTIN\\Pre-Windows 2000 Compatible Access";
				case "S-1-5-32-555": return "BUILTIN\\Remote Desktop Users";
				case "S-1-5-32-556": return "BUILTIN\\Network Configuration Operators";
				case "S-1-5-32-557": return "BUILTIN\\Incoming Forest Trust Builders";
				case "S-1-5-32-558": return "BUILTIN\\Performance Monitor Users";
				case "S-1-5-32-559": return "BUILTIN\\Performance Log Users";
				case "S-1-5-32-560": return "BUILTIN\\Windows Authorization Access Group";
				case "S-1-5-32-561": return "BUILTIN\\Terminal Server License Servers";
				case "S-1-5-32-562": return "BUILTIN\\Distributed COM Users";
				case "S-1-5-32-569": return "BUILTIN\\Cryptographic Operators";
				case "S-1-5-32-573": return "BUILTIN\\Event Log Readers";
				case "S-1-5-32-574": return "BUILTIN\\Certificate Service DCOM Access";
				case "S-1-5-32-575": return "BUILTIN\\RDS Remote Access Servers";
				case "S-1-5-32-576": return "BUILTIN\\RDS Endpoint Servers";
				case "S-1-5-32-577": return "BUILTIN\\RDS Management Servers";
				case "S-1-5-32-578": return "BUILTIN\\Hyper-V Administrators";
				case "S-1-5-32-579": return "BUILTIN\\Access Control Assistance Operators";
				case "S-1-5-32-580": return "BUILTIN\\Access Control Assistance Operators";
				default:
					try
					{
						return (new SecurityIdentifier(sid)).Translate(typeof(NTAccount)).Value;
					} catch
					{
						return sid;
					}
			}
		}

		public static string ConvertFileSystemRights(UInt32 FSR, bool compact = false)
		{
			// Resource https://msdn.microsoft.com/en-us/library/aa394063.aspx
			//			https://docs.microsoft.com/fr-fr/windows/desktop/SecAuthZ/access-mask
			//			https://technet.microsoft.com/fr-fr/library/bb967286.aspx
			Dictionary<UInt32, string> accessMasks = new Dictionary<uint, string>()
			{
				{ 0x80000000, "GenericRead" },
				{ 0x40000000, "GenericWrite" },
				{ 0x20000000, "GenericExecute" },
				{ 0x10000000, "GenericAll" },
				{ 0x02000000, "MaximumAllowed" },
				{ 0x01000000, "AccessSystemSecurity" },
				{ 0x00100000, "Synchronize" },
				{ 0x00080000, "WriteOwner" },
				{ 0x00040000, "WriteDAC" },
				{ 0x00020000, "ReadControl" },
				{ 0x00010000, "Delete" },
				{ 0x00000100, "WriteAttributes" },
				{ 0x00000080, "ReadAttributes" },
				{ 0x00000040, "DeleteChild" },
				{ 0x00000020, "Execute/Traverse" },
				{ 0x00000010, "WriteExtendedAttributes" },
				{ 0x00000008, "ReadExtendedAttributes" },
				{ 0x00000004, "AppendData/AddSubdirectory" },
				{ 0x00000002, "WriteData/AddFile" },
				{ 0x00000001, "ReadData/ListDirectory" }
			};

			Dictionary<UInt32, string> simplePermissions = new Dictionary<uint, string>()
			{
				{ 0x1f01ff, "FullControl" },
				{ 0x0301bf, "Modify" },
				{ 0x0200a9, "ReadAndExecute" },
				{ 0x02019f, "ReadAndWrite" },
				{ 0x020089, "Read" },
				{ 0x000116, "Write" }
			};


			List<string> permissions = new List<string>();

			foreach (UInt32 permission in simplePermissions.Keys)
			{
				if ((FSR & permission) == permission)
				{
					permissions.Add(simplePermissions[permission]);
					if (compact)
					{
						FSR = FSR & (UInt32)(~permission);
					}
				}
			}

			foreach (UInt32 accessMask in accessMasks.Keys)
			{
				if ((int)(FSR & accessMask) > 0)
				{
					permissions.Add(accessMasks[accessMask]);
				}
			}

			return String.Join(", ", permissions);
		}
	}
}

