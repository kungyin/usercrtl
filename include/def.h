#ifndef _DEF_H_
#define _DEF_H_

//#define USERCTL_DIRPATH "."
//#define USERCTL_FILEPATH USERCTL_DIRPATH"/uc.txt"
#define USERCTL_SPLITE ","

#define CMD_ADDUSER         "add"
#define CMD_REMOVEUSER      "remove"
#define CMD_PRINTUSER       "printuser"
#define CMD_PRINTGROUP      "printgroup"
#define CMD_PRINTGROUPMEM   "printmember"
#define CMD_VERSION         "--version"

#define ETC_PATH            "/etc"
#define PASSWD_FILEPATH     "/etc/passwd"
#define GROUP_FILEPATH      "/etc/group"
#define SHADOW_FILEPATH     "/etc/shadow"

#define SAMBA_MULTICALL_FILE "/usr/local/samba/sbin/samba_multicall"
#define SAMBA_EXECUTABLE_PASSWD_FILE "/usr/local/samba/sbin/smbpasswd"
#define SAMBA_PASSWD_FILE "/etc/samba/smbpasswd"

#define MAX_STRING_SIZE     1<<8
//#define MAX_ARRAY_SIZE      1<<10
#define GID_START           1000
#define UID_START           1000

#endif
