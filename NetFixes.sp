#pragma semicolon 1
#pragma newdecls required

#include <sourcemod>
#include <dhooks>

Address TempAddress, GetAddress;

char IpLog[PLATFORM_MAX_PATH];

float LogCheck;

ConVar EnableIpLog;

public Plugin myinfo =
{
	name		= "[L4D2] Fix Net Pack Attack",
	author		= "Neko Channel & 昔洛",
	description 	= "Fix SB DOS Attack | 修复小字节网络包服务端攻击",
	version		= "1.8",
	url		= "https://github.com/himenekocn/L4D2-Fix-Net-Pack-Attack"
};

public void OnPluginStart()
{
	char HostPort[6];
	GetConVarString(FindConVar("hostport"), HostPort, sizeof(HostPort));

	BuildPath(Path_SM, IpLog, sizeof(IpLog), "logs/NetDosIPLog_S%s.log", HostPort[4]);

	EnableIpLog = CreateConVar("net_enabledosiplog", "0", "1 = Enable ip attack log , 0 = Disable ip attack log", _, true, 0.0, true, 1.0);

	GameData hGameData = new GameData("NetFixes");

	if (hGameData == null)
		SetFailState("Failed to load NetFixes gamedata.");

	DynamicDetour hNET_ReceiveDatagramDetour = DynamicDetour.FromConf(hGameData, "NET_ReceiveDatagram");
	if (!hNET_ReceiveDatagramDetour.Enable(Hook_Pre, NET_ReceiveDatagram_Pre))
		SetFailState("Failed to setup detour for NET_ReceiveDatagram_Pre");
	
	// NET_QueuePacket Detour (Fix SB DOS) 其他游戏请自行寻签名
	DynamicDetour hNET_QueuePacketDetour = DynamicDetour.FromConf(hGameData, "NET_QueuePacket");
	if (!hNET_QueuePacketDetour.Enable(Hook_Pre, NET_QueuePacket))
		SetFailState("Failed to setup detour for NET_QueuePacket");

	if (hGameData.GetOffset("OS"))
	{
		DynamicDetour hRecvfromDetour = DynamicDetour.FromConf(hGameData, "CSteamSocketMgr_recvfrom");
		if (!hRecvfromDetour.Enable(Hook_Post, CSteamSocketMgr_recvfrom))
			SetFailState("Failed to setup detour for CSteamSocketMgr_recvfrom");
	}
	else
	{
		Address recvfrom = GameConfGetAddress(hGameData, "g_SocketMgr");

		if (recvfrom == Address_Null)
			SetFailState("Failed to get address of recvfrom");

		DynamicHook hRecvfromDetour = DHookCreate(6, HookType_Raw, ReturnType_Int, ThisPointer_Ignore, CSteamSocketMgr_recvfrom);

		if (hRecvfromDetour == INVALID_HANDLE)
			SetFailState("Failed to create detour for hRecvfromDetour");

		hRecvfromDetour.AddParam(HookParamType_Int);
		hRecvfromDetour.AddParam(HookParamType_CharPtr);
		hRecvfromDetour.AddParam(HookParamType_Int);
		hRecvfromDetour.AddParam(HookParamType_Int);
		hRecvfromDetour.AddParam(HookParamType_Int);
		hRecvfromDetour.AddParam(HookParamType_Int);

		if (DHookRaw(hRecvfromDetour, true, recvfrom) == INVALID_HOOK_ID)
			SetFailState("Failed to raw detour for hRecvfromDetour");
	}

	delete hGameData;
}

public MRESReturn NET_QueuePacket(DHookReturn hReturn, DHookParam hParams)
{
	hReturn.Value = true;
	return MRES_Supercede;
}

public MRESReturn CSteamSocketMgr_recvfrom(DHookReturn hReturn, DHookParam hParams)
{
	if (TempAddress == Address_Null)
		return MRES_Ignored;

	int NetPackType = LoadFromAddress(TempAddress, NumberType_Int32);

	if (NetPackType == -2 || NetPackType == -3)
		StoreToAddress(TempAddress, 0, NumberType_Int32);

	return MRES_Ignored;
}

public MRESReturn NET_ReceiveDatagram_Pre(DHookReturn hReturn, DHookParam hParams)
{
	GetAddress = DHookGetParam(hParams, 2);

	if (TempAddress == Address_Null)
		return MRES_Ignored;
	
	TempAddress = LoadFromAddress(GetAddress + view_as<Address>(24), NumberType_Int32);

	if(!EnableIpLog.BoolValue)
		return MRES_Ignored;

	int NetPackType = LoadFromAddress(TempAddress, NumberType_Int32);

	if ((NetPackType == -2 || NetPackType == -3) && LogCheck + 5 < GetGameTime())
	{
		char TempIP[512], TempType[512];
		Format(TempIP, sizeof TempIP, "%d.%d.%d.%d", view_as<int>(LoadFromAddress(GetAddress + view_as<Address>(4), NumberType_Int8)), view_as<int>(LoadFromAddress(GetAddress + view_as<Address>(5), NumberType_Int8)), view_as<int>(LoadFromAddress(GetAddress + view_as<Address>(6), NumberType_Int8)), view_as<int>(LoadFromAddress(GetAddress + view_as<Address>(7), NumberType_Int8)));

		switch (NetPackType)
		{
			case -2: Format(TempType, sizeof TempType, "FEFF");
			case -3: Format(TempType, sizeof TempType, "FDFF");
		}

		LogToFile(IpLog, "[NET] 收到来自 %s 的 %s 攻击", TempIP, TempType);

		LogCheck = GetGameTime();
	}

	return MRES_Ignored;
}
