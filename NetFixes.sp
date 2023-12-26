#pragma semicolon 1
#pragma newdecls required

#include <sourcemod>
#include <dhooks>

Address TempAddress = Address_Null;

public Plugin myinfo =
{
	name		= "[L4D2] Fix Net pack attack",
	author		= "Neko Channel & 昔洛",
	description = "Fix SB DOS Attack | 修复小字节网络包服务端攻击",
	version		= "1.5",
	url			= "https://github.com/himenekocn/L4D2-Fix-Net-Pack-Attack"
};

public void OnPluginStart()
{
	GameData hGameData = new GameData("NetFixes");

	if (hGameData == null)
		SetFailState("Failed to load NetFixes gamedata.");

	DynamicDetour hNET_ReceiveDatagramDetour = DynamicDetour.FromConf(hGameData, "NET_ReceiveDatagram");
	if (!hNET_ReceiveDatagramDetour.Enable(Hook_Pre, NET_ReceiveDatagram_Pre))
		SetFailState("Failed to setup detour for NET_ReceiveDatagram_Pre");

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

public MRESReturn CSteamSocketMgr_recvfrom(DHookReturn hReturn, DHookParam hParams)
{
	int DataSize = DHookGetReturn(hReturn);

	if (DataSize > 0 && DataSize < 12 && TempAddress != Address_Null)
	{
		int type = LoadFromAddress(TempAddress, NumberType_Int32);

		if (type == -2 || type == -3)
			StoreToAddress(TempAddress, 0, NumberType_Int32);
	}

	return MRES_Ignored;
}

public MRESReturn NET_ReceiveDatagram_Pre(DHookReturn hReturn, DHookParam hParams)
{
	TempAddress = LoadFromAddress(DHookGetParam(hParams, 2) + view_as<Address>(24), NumberType_Int32);

	return MRES_Ignored;
}