using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace SharesMapperUtils
{
	public static class AddrParser
	{
		public static HashSet<string> ParseTargets(string input)
		{

			HashSet<string> result = new HashSet<string>();
			string[] targets = input.Split(' ');
			int cidr_count = 0;
			foreach (string target in targets)
			{
				// check if target contains letter then consider it as hostname
				if (target.Count(char.IsLetter) > 1)
				{
					result.Add(target);
				}
				else
				{ 
					cidr_count = target.Count(c => c == '/');
					if (cidr_count > 1)
					{
						throw new Exception("Invalid target syntax : " + target);
					}
					else if (cidr_count == 1)
					{
						result.UnionWith(ParseCIDR(target));
					}
					else
					{
						result.UnionWith(ParseRange(target));
					}
				}
			}

			return result;
		}

		public static HashSet<string> ParseCIDR(string target)
		{
			HashSet<string> result = new HashSet<string>();

			string[] IPCidr = target.Split('/');
			string hostname = "";

			int subnetMask = 0;
			Int32.TryParse(IPCidr[1], out subnetMask);
			subnetMask = 32 - subnetMask;
			int IPCount = (int)Math.Pow(2, subnetMask);
			uint uintIP = 0;

			foreach (string address in ParseRange(IPCidr[0], true))
			{
				uintIP = (uint)IPAddress.NetworkToHostOrder((int)IPAddress.Parse(address).Address);
				uintIP = uintIP & ~((uint)Math.Pow(2, subnetMask) - 1);

				for (int i = 1; i <= IPCount; i++)
				{
					hostname = IPAddress.Parse(uintIP.ToString()).ToString();
					if (!((uintIP & 0x000000FF) == 0x000000FF || (uintIP & 0x000000FF) == 0x00000000))
					{
						result.Add(hostname);
					}
					uintIP = uintIP + 1;
				}
			}

			return result;
		}

		public static HashSet<string> ParseRange(string target, bool cidr = false)
		{
			HashSet<string> result = new HashSet<string>();

			int RangeCount = 0;
			string[] IPStart = target.Split('.');
			string[] IPEnd = new string[4];

			string IPStrByte = "";
			byte RStartByte = 0;
			byte REndByte = 0;
			string[] tmp = new string[2];

			if (IPStart.Length != 4)
			{
				throw new Exception("IP format error.");
			}

			for (int i = 0; i < IPStart.Length; i++)
			{
				IPStrByte = IPStart[i];
				RangeCount = IPStrByte.Count(c => c == '-');
				if (RangeCount > 1)
				{
					throw new Exception("Range syntax error : too many '-'.");
				}
				else if (RangeCount == 1)
				{
					tmp = IPStrByte.Split('-');

					RStartByte = Convert.ToByte(tmp[0]);
					REndByte = Convert.ToByte(tmp[1]);

					if (
						(
							(i != 3 && RStartByte >= 0)
							||
							(i == 3 && (RStartByte > 0 || cidr))
						)
						&&
						RStartByte < 255 && REndByte > 0 && REndByte < 255 && RStartByte <= REndByte
					)
					{
						IPStart[i] = tmp[0];
						IPEnd[i] = tmp[1];
					}
					else
					{
						throw new Exception("Invalid range.");
					}

				}
				else
				{
					REndByte = Convert.ToByte(IPStrByte);
					if (
						(
							(i != 3 && REndByte >= 0)
							||
							(i == 3 && (REndByte > 0 || cidr)) 
						)
						&& REndByte < 255
					)
					{
						IPEnd[i] = IPStrByte;
					}
					else
					{
						throw new Exception("Invalid target : " + target);
					}

				}
			}

			byte[] IPStartBytes = new byte[] { Convert.ToByte(IPStart[0]), Convert.ToByte(IPStart[1]), Convert.ToByte(IPStart[2]), Convert.ToByte(IPStart[3]) };
			byte[] IPEndBytes = new byte[] { Convert.ToByte(IPEnd[0]), Convert.ToByte(IPEnd[1]), Convert.ToByte(IPEnd[2]), Convert.ToByte(IPEnd[3]) };


			for (byte b1 = IPStartBytes[0]; b1 <= IPEndBytes[0]; b1++)
			{
				for (byte b2 = IPStartBytes[1]; b2 <= IPEndBytes[1]; b2++)
				{
					for (byte b3 = IPStartBytes[2]; b3 <= IPEndBytes[2]; b3++)
					{
						for (byte b4 = IPStartBytes[3]; b4 <= IPEndBytes[3]; b4++)
						{
							result.Add(b1.ToString() + "." + b2.ToString() + "." + b3.ToString() + "." + b4.ToString());
						}
					}
				}
			}

			return result;
		}
	}
}
