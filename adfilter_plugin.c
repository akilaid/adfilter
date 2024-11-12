/*===================================================================*\
||///////////////////////////////////////////////////////////////////||
||/////  _  \ |    |/ _|   |    |//////  _  \/////|   |/\_ ____ \////||
||////  /_\  \|      < |   |    |/////  /_\  \////|   |//| |  |  \///||
||///    |    \    |  \|   |    |////    |    \///|   |//| |__|   \//||
||//\____|__  /____|__ \___|_______ \____|__  ////|___|//_______  ///||
||//////////\/////////\////////////\////////\///////////////////\////||
||===================================================================||
||            LICENSED UNDER THE MIT LICENSE - OPEN SOURCE           ||
\*===================================================================*/

#include "../pinc.h"
#include "adfilter.h"

PCL int OnInit(){	// Funciton called on server initiation

	CensorMessages_Init();

	return 0;
}
PCL void OnMessageSent(char *message, int slot, qboolean *show, int mode){
	CensorMessages(message);
}
PCL void OnInfoRequest(pluginInfo_t *info){	// Function used to obtain information about the plugin
    // Memory pointed by info is allocated by the server binary, just fill in the fields

    // =====  MANDATORY FIELDS  =====
    info->handlerVersion.major = PLUGIN_HANDLER_VERSION_MAJOR;
    info->handlerVersion.minor = PLUGIN_HANDLER_VERSION_MINOR;	// Requested handler version

    // =====  OPTIONAL  FIELDS  =====
    info->pluginVersion.major = 1;
    info->pluginVersion.minor = 0;	// Plugin version
    strncpy(info->fullName,"ImplaZa IP Censoring Plugin by Akilaid",sizeof(info->fullName)); //Full plugin name
    strncpy(info->shortDescription,"A plugin designed to filter and block unwanted advertisements and spam in the in-game chat.",sizeof(info->shortDescription)); // Short plugin description
    strncpy(info->longDescription,"ImplaZa IP Censoring Plugin helps maintain a clean and enjoyable gaming environment by preventing server advertisers and spammers from flooding the in-game chat. It automatically detects and censors unwanted messages, ensuring a smoother experience for players.\n\nCopyright (c) 2024 akilaid",sizeof(info->longDescription));
}
