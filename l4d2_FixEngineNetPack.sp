#include <sourcemod>
#include <dhooks>
#include <sdktools>

/**
 * 需要混淆编译器，防止反编译寻找额外漏洞
 */

/**
 * 1.0 修复 FD FE 短包炸服
 * 2.0 修复 FE FD长包炸服（无法合理判断 FD 合法性，一刀切）
 */

#define LMP_VERSION "2.0"

public Plugin:myinfo =
{
    name = "[L4D2] l4d2 fix net pack attack",
    author = "昔洛",
    description = "修复小字节网络包服务端攻击",
    version = LMP_VERSION,
    url = "qq1047504736"
}

new Handle:g_ddUTILNET_ReceiveDatagram;
new Handle:g_ddUTILNET_Recvfrom;
new Handle:g_sdkcall_FindOrCreateSplitPacketEntry;
public OnPluginStart()
{

	new Handle:gdLMP = INVALID_HANDLE;
	gdLMP = LoadGameConfigFile("l4d2_FixEngineNetPack");

	if (gdLMP == INVALID_HANDLE)
	{
		SetFailState("Unable to load the \"l4d2_fixnetprint\" gamedata file.");
	}

	g_ddUTILNET_ReceiveDatagram = DHookCreateFromConf(gdLMP, "LMPDetour_ReceiveDatagram");

	if (g_ddUTILNET_ReceiveDatagram == INVALID_HANDLE)
	{
		CloseHandle(gdLMP);
		SetFailState("Failed to detour: LMPDetour_ReceiveDatagram");
	}

	if (!DHookEnableDetour(g_ddUTILNET_ReceiveDatagram,false, mreUTILReceiveDatagramPre))
	{
		LogError("Failed to enable the pre-hook detour for the \"LMPDetour_ReceiveDatagram\" function.");
	}

	if (!DHookEnableDetour(g_ddUTILNET_ReceiveDatagram,true, mreUTILReceiveDatagramPost))
	{
		LogError("Failed to enable the pre-hook detour for the \"LMPDetour_ReceiveDatagram\" function.");
	}

	new OS = GameConfGetOffset(gdLMP,"OS");
	// linux
	if(OS==1)
	{
		g_ddUTILNET_Recvfrom = DHookCreateFromConf(gdLMP, "LMPDetour_recvfrom");
		if (g_ddUTILNET_Recvfrom == INVALID_HANDLE)
		{
			CloseHandle(gdLMP);
			SetFailState("Failed to detour: g_ddUTILNET_Recvfrom");
		}

		if (!DHookEnableDetour(g_ddUTILNET_Recvfrom,false, mreUTILRecvfromPre))
		{
			LogError("Failed to enable the pre-hook detour for the \"g_ddUTILNET_Recvfrom\" function.");
		}

		if (!DHookEnableDetour(g_ddUTILNET_Recvfrom,true, mreUTILRecvfromPost))
		{
			LogError("Failed to enable the pre-hook detour for the \"g_ddUTILNET_Recvfrom\" function.");
		}
	}
	else
	{
		// win
		new Address:recvfrom = GameConfGetAddress( gdLMP, "g_SocketMgr");
		if( recvfrom == Address_Null )
		{
			SetFailState( "Couldn't get address of recvfrom" );
			CloseHandle(gdLMP);
		}
		g_ddUTILNET_Recvfrom = DHookCreate(6, HookType_Raw, ReturnType_Int, ThisPointer_Ignore, mreUTILRecvfromPost);
		if (g_ddUTILNET_Recvfrom == INVALID_HANDLE)
		{
			CloseHandle(gdLMP);
			SetFailState("Failed to DHookCreate: g_ddUTILNET_Recvfrom");
		}
		DHookAddParam(g_ddUTILNET_Recvfrom, HookParamType_Int);
		DHookAddParam(g_ddUTILNET_Recvfrom, HookParamType_CharPtr);
		DHookAddParam(g_ddUTILNET_Recvfrom, HookParamType_Int);
		DHookAddParam(g_ddUTILNET_Recvfrom, HookParamType_Int);
		DHookAddParam(g_ddUTILNET_Recvfrom, HookParamType_Int);
		DHookAddParam(g_ddUTILNET_Recvfrom, HookParamType_Int);
		if (DHookRaw(g_ddUTILNET_Recvfrom, true, recvfrom) == INVALID_HOOK_ID)
		{
			CloseHandle(gdLMP);
			SetFailState("Failed to DHookRaw: g_ddUTILNET_Recvfrom");
		}
	}

	/* 预测试代码，暂时无用
	StartPrepSDKCall(SDKCall_Static);
    
    if (!PrepSDKCall_SetFromConf(gdLMP, SDKConf_Signature, "NET_FindOrCreateSplitPacketEntry"))
    {
        CloseHandle(gdLMP);
        SetFailState("Failed to get NET_FindOrCreateSplitPacketEntry");
    }
    
    PrepSDKCall_AddParameter(SDKType_PlainOldData, SDKPass_Pointer);
    PrepSDKCall_AddParameter(SDKType_PlainOldData, SDKPass_Pointer);
    PrepSDKCall_SetReturnInfo(SDKType_PlainOldData, SDKPass_Plain);
    
    g_sdkcall_FindOrCreateSplitPacketEntry = EndPrepSDKCall();
	if(g_sdkcall_FindOrCreateSplitPacketEntry == INVALID_HANDLE)
	{
		CloseHandle(gdLMP);
        SetFailState("Failed to get g_sdkcall_FindOrCreateSplitPacketEntry");
	}
    Address addr = SDKCall(g_sdkcall_FindOrCreateSplitPacketEntry, 0, 0);
	*/
	CloseHandle(gdLMP);
}

// new index=0;
new Address:g_v5 = Address_Null;

public MRESReturn:mreUTILReceiveDatagramPre(Handle:hReturn,Handle:hParams)
{
	new Address:address = DHookGetParam(hParams,2);
	new Address:v5 = Address:LoadFromAddress(address+Address:24,NumberType_Int32);
	g_v5 = v5;
	// if(index<24)
	// 	PrintToServer("-------------------call for recvDatagram Pre %d",index++);
	return MRES_Ignored;
}
public MRESReturn:mreUTILReceiveDatagramPost(Handle:hReturn,Handle:hParams)
{
	new Address:address = DHookGetParam(hParams,2);
	new Address:v5 = Address:LoadFromAddress(address+Address:24,NumberType_Int32);
	new type = (LoadFromAddress(Address:v5,NumberType_Int32));
	new length = (LoadFromAddress(Address:address + Address:64,NumberType_Int32));
	if(length==8 && type==-2)
	{
		for(new i=4;i<8;i++)
		{
			// PrintToServer("%d",view_as<int>(LoadFromAddress(address+i,NumberType_Int8)));
		}
	}
	// if(index<24)
	// 	PrintToServer("-------------------call for recvDatagram post %d v5:%d",index++,type);
	// PrintToServer("-------------------call for recvDatagram post head:%d",type);
	return MRES_Ignored;
}

public MRESReturn:mreUTILRecvfromPre(Handle:hReturn,Handle:hParams)
{
	// char buffer[256];
	// hParams.GetString(2,buffer,256);

	// if(index<24)
	// PrintToServer("+++++++++++++++++++call for recvfromPre %d value:%d",index++,hReturn.Value);
	return MRES_Ignored;
}

public MRESReturn:mreUTILRecvfromPost(Handle:hReturn,Handle:hParams)
{
	new value = DHookGetReturn(hReturn);
	// if(index<24)
		// PrintToServer("+++++++++++++++++++call for recvfromPost %d value:%d",index++,value);

	// g_v5 -> (*((_DWORD *)a2 + 6))
	if(g_v5 != Address_Null)
	{
		new bool:shouldFix = false;
		new type = LoadFromAddress(Address:g_v5,NumberType_Int32);
		new bool:checkType1 = value > 0 && value < 12;
		if(type==-2)
		{
			new bool:checkType2 = (LoadFromAddress(Address:g_v5+Address:(10 * 4),NumberType_Int32) - 564) > 624;	// 0x270u
			new bool:checkType3 = (LoadFromAddress(Address:g_v5+Address:(8 * 4),NumberType_Int32) >> 8) > 403;	// 0x193u
			if(checkType1 || checkType2 || checkType3)
			{
				shouldFix = true;
			}
		} else if ( type==-3) {
			shouldFix = true;	// 无法判断 -3 合法行，禁用 FDFFFFFF
		}
		if(shouldFix)
		{
			StoreToAddress(Address:g_v5, 0, NumberType_Int32);	// 垃圾包data数据清空，Value 自动处理丢弃
		}
	}

	return MRES_Ignored;
}