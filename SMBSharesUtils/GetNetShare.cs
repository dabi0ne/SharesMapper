using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Runtime.Serialization;

namespace SMBSharesUtils
{

	public enum SHARE_TYPE
	{
		STYPE_DISKTREE = 0,
		STYPE_PRINTQ = 1,
		STYPE_DEVICE = 2,
		STYPE_IPC = 3,
		STYPE_CLUSTER_FS = 0x02000000,
		STYPE_CLUSTER_SOFS = 0x04000000,
		STYPE_CLUSTER_DFS = 0x08000000
	}

	#region External Structures
	[Serializable]
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	public class ShareInfo
	{
		[DataMember]
		public string shi1_netname;
		[DataMember]
		public UInt16 shi1_type;
		[DataMember]
		public string shi1_remark;

		public ShareInfo()
		{

		}

		public ShareInfo(string sharename, UInt16 sharetype, string remark)
		{
			this.shi1_netname = sharename;
			this.shi1_type = sharetype;
			this.shi1_remark = remark;
		}

		public override string ToString()
		{
			return Encoding.UTF8.GetString(Encoding.UTF8.GetBytes(shi1_netname));
		}
	}

	[Serializable]
	public class HostShare
	{
		[DataMember]
		public ShareInfo shareInfo;
		[DataMember]
		public string hostname;

		public HostShare()
		{

		}

		public HostShare(ShareInfo shareInfo, string hostname)
		{
			this.shareInfo = shareInfo;
			this.hostname = hostname;
		}

		public override string ToString()
		{
			return "\\\\" + this.hostname + "\\" + this.shareInfo.ToString();
		}
	}

	#endregion

	// source : https://www.pinvoke.net/default.aspx/netapi32.NetShareEnum
	public class GetNetShare
	{

		

		#region External Calls
		[DllImport("Netapi32.dll", SetLastError = true)]
		static extern int NetApiBufferFree(IntPtr Buffer);
		[DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
		private static extern int NetShareEnum(
			 StringBuilder ServerName,
			 int level,
			 ref IntPtr bufPtr,
			 uint prefmaxlen,
			 ref int entriesread,
			 ref int totalentries,
			 ref int resume_handle
			 );
		#endregion

		const uint MAX_PREFERRED_LENGTH = 0xFFFFFFFF;
		const int NERR_Success = 0;
		private enum NetError : uint
		{
			NERR_Success = 0,
			NERR_BASE = 2100,
			NERR_UnknownDevDir = (NERR_BASE + 16),
			NERR_DuplicateShare = (NERR_BASE + 18),
			NERR_BufTooSmall = (NERR_BASE + 23),
		}
		private enum SHARE_TYPE : uint
		{
			STYPE_DISKTREE = 0,
			STYPE_PRINTQ = 1,
			STYPE_DEVICE = 2,
			STYPE_IPC = 3,
			STYPE_SPECIAL = 0x80000000,
		}
		public static HostShare[] EnumNetShares(string Server)
		{
			List<HostShare> ShareInfos = new List<HostShare>();
			int entriesread = 0;
			int totalentries = 0;
			int resume_handle = 0;
			int nStructSize = Marshal.SizeOf(typeof(ShareInfo));
			IntPtr bufPtr = IntPtr.Zero;
			StringBuilder server = new StringBuilder(Server);
			int ret = NetShareEnum(server, 1, ref bufPtr, MAX_PREFERRED_LENGTH, ref entriesread, ref totalentries, ref resume_handle);
			
			if (ret == NERR_Success)
			{
				IntPtr currentPtr = bufPtr;
				for (int i = 0; i < entriesread; i++)
				{
					ShareInfo shi1 = (ShareInfo)Marshal.PtrToStructure(currentPtr, typeof(ShareInfo));

					ShareInfos.Add(new HostShare(shi1, Server));
					currentPtr += nStructSize;
				}
				NetApiBufferFree(bufPtr);
				return ShareInfos.ToArray();
			}
			else
			{
				throw new ShareEnumException("ERROR=" + ret.ToString());

			}
		}
	}

	public class ShareEnumException : Exception
	{

		public ShareEnumException()
		{

		}

		public ShareEnumException(string msg) : base(msg)
		{

		}
	}
}
