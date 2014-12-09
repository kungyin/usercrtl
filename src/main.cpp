#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#include <pwd.h>
#include <grp.h>
#include <shadow.h>
#include <unistd.h>
#include <crypt.h>
#include <errno.h>

#include <iostream>
#include <fstream>
#include <string>

#include "def.h"

#if 0
    struct passwd {
        char   *pw_name;       /* username */
        char   *pw_passwd;     /* user password */
        uid_t   pw_uid;        /* user ID */
        gid_t   pw_gid;        /* group ID */
        char   *pw_gecos;      /* real name */
        char   *pw_dir;        /* home directory */
        char   *pw_shell;      /* shell program */
    };

    struct group {
        char   *gr_name;       /* group name */
        char   *gr_passwd;     /* group password */
        gid_t   gr_gid;        /* group ID */
        char  **gr_mem;        /* group members */
    };

    struct spwd {
        char *sp_namp;     /* Login name */
        char *sp_pwdp;     /* Encrypted password */
        long  sp_lstchg;   /* Date of last change
                              (measured in days since
                              1970-01-01 00:00:00 +0000 (UTC)) */
        long  sp_min;      /* Min # of days between changes */
        long  sp_max;      /* Max # of days between changes */
        long  sp_warn;     /* # of days before password expires
                              to warn user to change it */
        long  sp_inact;    /* # of days after password expires
                              until account is disabled */
        long  sp_expire;   /* Date when account expires
                              (measured in days since
                              1970-01-01 00:00:00 +0000 (UTC)) */
        unsigned long sp_flag;  /* Reserved */
    };
#endif

using namespace std;

void newAll(struct passwd &, struct group &, struct group &, struct spwd &);
void deleteAll(struct passwd *, struct group *, struct group *, struct spwd *);

void usage()
{

	fprintf(stderr, "userctl, "
		"usage:\n"
        "userctl add $(filename)\n"
		"userctl remove $(filename)\n"
        "userctl printgroup\n"
        "userctl printmember $(groupname)\n"
		//"userctl export\n"
        "\n"    
	);
}

static int i64c(int i)
{
	if (i <= 0)
		return ('.');
	if (i == 1)
		return ('/');
	if (i >= 2 && i < 12)
		return ('0' - 2 + i);
	if (i >= 12 && i < 38)
		return ('A' - 12 + i);
	if (i >= 38 && i < 63)
		return ('a' - 38 + i);
	return ('z');
}

static char *crypt_make_salt()
{
	time_t now;
	static unsigned long x;
	static char result[3];

	time(&now);
	x += now + getpid();
	result[0] = i64c(((x >> 18) ^ (x >> 6)) & 077);
	result[1] = i64c(((x >> 12) ^ x) & 077);
	result[2] = '\0';
	return result;
}

/* return value:
   true: is a link
   false: is not a link */
bool getFilePath(string sourcePath, string &targetPath, string &targetTempPath) {

    bool ret = false;
    char buf[MAX_STRING_SIZE];
    memset(buf, 0, sizeof(buf));
    ssize_t count = readlink(sourcePath.c_str(), buf, sizeof(buf));

    if (count == -1) {
        targetPath = sourcePath;
        targetTempPath = sourcePath + ".tmp";
        ret = false;
    }
    else {
        targetPath = buf;
        targetTempPath = string(buf) + ".tmp";
        ret = true;
    }

    return ret;
}

/* 
   return value:
   0: failed
   1: added
   2: modified
*/
int addUser(struct passwd *pUser) {
	FILE *fto;
	struct passwd *pwp, pws;
	int iStatus = 1;

    string passwdFile, tmpFile;
    getFilePath(PASSWD_FILEPATH, passwdFile, tmpFile);

    fto = fopen(tmpFile.c_str(), "w"); 
	if (fto) {
        setpwent();
        for(; (pwp = getpwent()) != NULL;) {
            if (strcmp(pwp->pw_name, pUser->pw_name) == 0) {
                *pwp = *pUser;
                iStatus = 2;
            }
            putpwent(pwp, fto);
        }

        if (iStatus == 1) {
            pws = *pUser;
            putpwent(&pws, fto);
        }

        endpwent();
		fclose(fto);
		rename(tmpFile.c_str(), passwdFile.c_str());
	}
    else 
        return 0;

    return iStatus;
}

/* 
   return value:
   0: failed
   1: removed
   2: not found
*/
int removeUser(struct passwd *pUser) {
	FILE *fto;
	struct passwd *pwp;
	int iStatus = 2;

    string passwdFile, tmpFile;
    getFilePath(PASSWD_FILEPATH, passwdFile, tmpFile);

	fto = fopen(tmpFile.c_str(), "w");
	if (fto) {
		for(setpwent(); (pwp = getpwent()) != NULL;) {
			if (strcmp(pwp->pw_name, pUser->pw_name) == 0) {
				iStatus = 1;
                continue;
			}
			putpwent(pwp, fto);
		}

        endpwent();
		fclose(fto);
		rename(tmpFile.c_str(), passwdFile.c_str());
	}
    else
        return 0;

    return iStatus;
}

/* 
   return value:
   0: failed
   1: added
   2: modified
*/
int addToGroup(struct group *pUserGroup) {
	FILE *fto;
	struct group *gwp, gws;
	int iStatus = 1;

    string groupFile, tmpFile;
    getFilePath(GROUP_FILEPATH, groupFile, tmpFile);

	fto = fopen(tmpFile.c_str(), "w");
	if (fto) {
        setgrent();
        for(; (gwp = getgrent()) != NULL;) {
            char *pNeedTobeClean = NULL;

            if (strcmp(gwp->gr_name, pUserGroup->gr_name) == 0) {
                if (pUserGroup->gr_mem) {
                    bool bFound = false;

                    char **ptr = gwp->gr_mem; 
                    if (ptr) {
                        while (*ptr != NULL) {
                            if (strcmp(*ptr, pUserGroup->gr_mem[0]) == 0) {
                                bFound = true;
                            }
                            ptr++;
                        }
                    }

                    if (!bFound) {
                        int i = ptr - gwp->gr_mem;
                        gwp->gr_mem[i] = new char[strlen(pUserGroup->gr_mem[0]) + 1]; 
                        strcpy(gwp->gr_mem[i], pUserGroup->gr_mem[0]);

                        gwp->gr_mem[i+1] = NULL;
                        pNeedTobeClean = gwp->gr_mem[i];
                    }
                }
                iStatus = 2;
            }
            putgrent(gwp, fto);

            if (pNeedTobeClean) 
                delete[] pNeedTobeClean;
        }

        if (iStatus == 1) {
            gws = *pUserGroup;
            putgrent(&gws, fto);
        }

        endgrent();
		fclose(fto);
        rename(tmpFile.c_str(), groupFile.c_str());
	}
    else 
        return 0;

    return iStatus;
}

/* 
   return value:
   0: failed
   1: removed
   2: not found
*/
bool removeFromGroup(struct group *pUserGroup) {
	FILE *fto;
	struct group *gwp;
	int iStatus = 2;

    string groupFile, tmpFile;
    getFilePath(GROUP_FILEPATH, groupFile, tmpFile);

	fto = fopen(tmpFile.c_str(), "w");
	if (fto) {
		for(setgrent(); (gwp = getgrent()) != NULL;) {
			if (strcmp(gwp->gr_name, pUserGroup->gr_name) == 0) {
				iStatus = 1;
                continue;
			}

            int index = -1;

            char **ptr = gwp->gr_mem;
            if (ptr) {
                while (*ptr != NULL) {
                    if (strcmp(*ptr, pUserGroup->gr_name) == 0) {
                        index = ptr - gwp->gr_mem;
                    }
                    ptr++;
                }
            }

            int iArrSize = ptr - gwp->gr_mem;

            if (index != -1) {
                struct group newGroup = { 
                    new char[MAX_STRING_SIZE], 
                    new char[MAX_STRING_SIZE], 
                    0, 
                    NULL
                };
                strcpy(newGroup.gr_name, gwp->gr_name);
                strcpy(newGroup.gr_passwd, gwp->gr_passwd);
                newGroup.gr_gid = gwp->gr_gid;
                newGroup.gr_mem = new char*[iArrSize];
                //cout << "iArrSize : " << iArrSize << endl; 
                for (int j=0; j<iArrSize; j++) 
                    newGroup.gr_mem[j] = NULL;

                int newIdx = -1;
                for (int j=0; j<iArrSize; j++) {
                    if (j==index)
                        continue;

                    newIdx = (j > index) ? j - 1 : j;
                    newGroup.gr_mem[newIdx] = new char[strlen(gwp->gr_mem[j]) + 1];
                    strcpy(newGroup.gr_mem[newIdx], gwp->gr_mem[j]);
                }
                newGroup.gr_mem[newIdx+1] = NULL;
               
                putgrent(&newGroup, fto);
                deleteAll(NULL, NULL, &newGroup, NULL);
            }
            else
                putgrent(gwp, fto);
		}

        endgrent();

		fclose(fto);
		rename(tmpFile.c_str(), groupFile.c_str());
	}
    else 
        return 0;

    return iStatus;
}

void printGroupList() {
	FILE *fto;
	struct group *gwp;

	fto = fopen(GROUP_FILEPATH, "r");
	if (fto) {
        setgrent();
        for(; (gwp = getgrent()) != NULL;) {
            cout << gwp->gr_name << endl;
        }
        endgrent();
		fclose(fto);
	}
}

void printGroupMemberList(string groupName) {
    FILE *fto;
    struct group *gwp;

    fto = fopen(GROUP_FILEPATH, "r");
    if (fto) {
        setgrent();
        for(; (gwp = getgrent()) != NULL;) {
            if (strcmp(gwp->gr_name, groupName.c_str()) == 0) {
                if (gwp->gr_mem) {
                    char **ptr = gwp->gr_mem;
                    while (*ptr != NULL) {
                        cout << *ptr << endl;
                        ptr++;
                    }
                }
                break;
            }
        }
        endgrent();
        fclose(fto);
    }
}

/* 
   return value:
   0: failed
   1: added
   2: modified
*/
int addToShadow(struct spwd *pUserShadow) {
	FILE *fto;
	struct spwd *spwp, spws;
	int iStatus = 1;

    string shadowFile, tmpFile;
    getFilePath(SHADOW_FILEPATH, shadowFile, tmpFile);

	fto = fopen(tmpFile.c_str(), "w");
	if (fto) {
        setspent();
        for(; (spwp = getspent()) != NULL;) {
            if (strcmp(spwp->sp_namp, pUserShadow->sp_namp) == 0) {
                *spwp = *pUserShadow;
                iStatus = 2;
            }
            putspent(spwp, fto);
        }

        if (iStatus == 1) {
            spws = *pUserShadow;
            spws.sp_inact = -1;
            putspent(&spws, fto);
        }

        endspent();
		fclose(fto);
		rename(tmpFile.c_str(), shadowFile.c_str());
	}
    else 
        return 0;

    return iStatus;
}

/* 
   return value:
   0: failed
   1: removed
   2: not found
*/
int removeFromShadow(struct spwd *pUserShadow) {
	FILE *fto;
	struct spwd *spwp;
	int iStatus = 2;

    string shadowFile, tmpFile;
    getFilePath(SHADOW_FILEPATH, shadowFile, tmpFile);

	fto = fopen(tmpFile.c_str(), "w");
	if (fto) {
		for(setspent(); (spwp = getspent()) != NULL;) {
			if (strcmp(spwp->sp_namp, pUserShadow->sp_namp) == 0) {
				iStatus = 1;
                continue;
			}
			putspent(spwp, fto);
		}

        endspent();
		fclose(fto);
		rename(tmpFile.c_str(), shadowFile.c_str());
	}
    else
        return 0;

    return iStatus;
}

bool checkSmbEnv() {

    struct stat buf;
    if( stat(SAMBA_PASSWD_FILE, &buf) == -1 ) {
        cout << "Create file: " << SAMBA_PASSWD_FILE << endl;
        fstream smbFileStream;
        smbFileStream.open(SAMBA_PASSWD_FILE, fstream::out);
        if (smbFileStream.is_open()) 
            smbFileStream.close();
    }

    if( stat(SAMBA_EXECUTABLE_PASSWD_FILE, &buf) == -1 ) {
        if( stat(SAMBA_MULTICALL_FILE, &buf) == -1 ) {
            cout << "Could not find file: " << SAMBA_MULTICALL_FILE << endl;
            return false;
        }
        cout << "Link file: " << SAMBA_EXECUTABLE_PASSWD_FILE << endl;
        link(SAMBA_MULTICALL_FILE, SAMBA_EXECUTABLE_PASSWD_FILE);
    }

    return true;
}

int createSmbUser(struct passwd *pUser, string uncryptPasswd) {

    if (checkSmbEnv()) {
        char cmd[MAX_STRING_SIZE];
        sprintf(cmd, 
                "printf \"%s\n%s\n\" | %s -s -a %s", 
                uncryptPasswd.c_str(), 
                uncryptPasswd.c_str(), 
                SAMBA_EXECUTABLE_PASSWD_FILE, 
                pUser->pw_name);
        system(cmd);
        return 0;
    }
    else 
        return -1;
}

int removeSmbUser(struct passwd *pUser) {
    if (checkSmbEnv()) {
        char cmd[MAX_STRING_SIZE];
        sprintf(cmd, "%s -x %s",SAMBA_EXECUTABLE_PASSWD_FILE, pUser->pw_name);
        system(cmd);
        return 0;
    }
    else
        return -1;
}


string getNextField(string str) {
    size_t pos = str.find(USERCTL_SPLITE);
    return str.substr(0, pos);
}

int getUid(char *username) {
    struct passwd pwd;
    struct passwd *result;
    char *buf;
    long bufsize;
    int s;

    bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize == -1)          /* Value was indeterminate */
        bufsize = 16384;        /* Should be more than enough */

    buf = (char *)malloc(bufsize);
    if (buf == NULL) {
        perror("malloc");
        return -1;
    }

    s = getpwnam_r(username, &pwd, buf, bufsize, &result);
    if (result != NULL) {
        return pwd.pw_uid;
    }

    for(int i = UID_START; i <= 65535; i++) {
        s = getpwuid_r(i, &pwd, buf, bufsize, &result);
        if (result == NULL) {
            if (s == 0)
                ;//printf("Not found\n");
            else {
                errno = s;
                perror("getpwnam_r");
                return -1;
            }
            return i;
        }
    }

    return -1;
}

int getGid(char *groupName) {
    struct group gwd;
    struct group *result;
    char *buf;
    long bufsize;
    int s;

    bufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
    if (bufsize == -1)          /* Value was indeterminate */
        bufsize = 16384;        /* Should be more than enough */

    buf = (char *)malloc(bufsize);
    if (buf == NULL) {
        perror("malloc");
        return -1;
    }

    s = getgrnam_r(groupName, &gwd, buf, bufsize, &result);
    if (result != NULL) {
        return gwd.gr_gid;
    }

    for(int i = GID_START; i <= 65535; i++) {
        s = getgrgid_r(i, &gwd, buf, bufsize, &result);
        if (result == NULL) {
            if (s == 0)
                ;//printf("Not found\n");
            else {
                errno = s;
                perror("getgrnam_r");
                return -1;
            }
            return i;
        }
    }

    return -1;
}

bool getUserFromFile(string &line, 
                     struct passwd *pUser, 
                     struct group *pUserGroup, 
                     struct spwd *pUserShadow, 
                     struct group *parentGroup, 
                     string &uncryptPasswd) {

    bool bRet = true;
    string str = line; 
    //cout << line << endl;

    strcpy(pUser->pw_name, getNextField(str).c_str());
    strcpy(pUserGroup->gr_name, pUser->pw_name);
    strcpy(pUserShadow->sp_namp, pUser->pw_name);

    str = str.substr(str.find(USERCTL_SPLITE) + 1);
    uncryptPasswd = getNextField(str);
    strcpy(pUser->pw_passwd, "x");
    strcpy(pUserGroup->gr_passwd, "x");
    strcpy(pUserShadow->sp_pwdp, crypt(uncryptPasswd.c_str(), crypt_make_salt()));

    int uid = getUid(pUser->pw_name);
    if (uid > 0) 
        pUser->pw_uid = uid;
    else
        bRet = false; 
    
    str = str.substr(str.find(USERCTL_SPLITE) + 1);
    string parentGrpName = getNextField(str).c_str();
    if (!parentGrpName.empty()) {
        strcpy(parentGroup->gr_name, getNextField(str).c_str());
        strcpy(parentGroup->gr_passwd, "x"); 
        parentGroup->gr_gid = getGid(parentGroup->gr_name);
        strcpy(*parentGroup->gr_mem, pUser->pw_name);
    }
    pUser->pw_gid = pUser->pw_uid;
    pUserGroup->gr_gid = pUser->pw_uid;

    str = str.substr(str.find(USERCTL_SPLITE) + 1);
    strcpy(pUser->pw_gecos, str.c_str());

    sprintf(pUser->pw_dir, "/home/homes/%s", pUser->pw_name);
    strcpy(pUser->pw_shell, "/bin/sh");

    return bRet;
}

int main(int argc, char *argv[])
{

    if (argc == 2) {
        char *cmdname = argv[1];
        if (strcmp(cmdname, CMD_PRINTGROUP) == 0) 
            printGroupList();
#ifdef GIT_VERSION
        else if (strcmp(cmdname, CMD_VERSION) == 0) 
            cout << GIT_VERSION << endl;
#endif
    }
    else if (argc == 3) {

        char *cmdname = argv[1];

        if (strcmp(cmdname, CMD_PRINTGROUPMEM) == 0) {
            printGroupMemberList(argv[2]);
            return 0;
        }

        if ( strcmp(cmdname, CMD_ADDUSER) != 0 && strcmp(cmdname, CMD_REMOVEUSER) != 0 ) {
            usage();
            return 0;
        }

        struct stat buf;
        if( stat(argv[2], &buf) == -1 ) {
            cout << "Could not find input file: " << argv[2] << endl; 
            return 0;
        }

        ifstream userCtlFile(argv[2]);
        string line;

        if (userCtlFile.is_open())
        {
            struct passwd user;
            struct group userGroup;
            struct spwd userShadow;
            struct group parentGroup;
            string uncryptPasswd;

            if (strcmp(cmdname, CMD_ADDUSER) == 0) {
                while ( getline (userCtlFile, line) && !userCtlFile.eof() ) {
                    newAll(user, userGroup, parentGroup, userShadow);
                    if(getUserFromFile(line, &user, &userGroup, &userShadow, &parentGroup, uncryptPasswd)) {
                        addToGroup(&parentGroup);
                        addUser(&user);
                        //addToGroup(&userGroup);
                        addToShadow(&userShadow);
    //                  if( mkdir(user->pw_dir, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) != 0 )
    //                      perror("Could not create home folder");
                        createSmbUser(&user, uncryptPasswd);
                    }

                    deleteAll(&user, &userGroup, &parentGroup, &userShadow);
                }
            }
            else if (strcmp(cmdname, CMD_REMOVEUSER) == 0) {
                while ( getline (userCtlFile, line) && !userCtlFile.eof() ) {
                    newAll(user, userGroup, parentGroup, userShadow);
                    if(getUserFromFile(line, &user, &userGroup, &userShadow, &parentGroup, uncryptPasswd)) {
                        removeUser(&user);
                        removeFromGroup(&userGroup);
                        removeFromShadow(&userShadow);
    //                  if (rmdir(user->pw_dir) != 0)
    //                      perror("Could not remove home folder");
                        removeSmbUser(&user);
                    }
                    deleteAll(&user, &userGroup, &parentGroup, &userShadow);
                }
            }

            userCtlFile.close();
        }
        else 
            cout << "Userctrl could not initialized, input file: " << argv[2] << endl; 

    }
    else
        usage();

	return 0;
}

void newAll(struct passwd &user, 
            struct group &userGroup, 
            struct group &parentGroup, 
            struct spwd &userShadow) {

    user = { 
        new char[MAX_STRING_SIZE], 
        new char[MAX_STRING_SIZE], 
        0, 
        0, 
        new char[MAX_STRING_SIZE], 
        new char[MAX_STRING_SIZE], 
        new char[MAX_STRING_SIZE] 
    };

    userGroup = { 
        new char[MAX_STRING_SIZE], 
        new char[MAX_STRING_SIZE], 
        0, 
        NULL 
    };

    userShadow = { 
        new char[MAX_STRING_SIZE], 
        new char[MAX_STRING_SIZE], 
        16392, 
        0, 
        99999, 
        7,
        -1,
        -1,
        -1
    };

    parentGroup = { 
        new char[MAX_STRING_SIZE], 
        new char[MAX_STRING_SIZE], 
        0, 
        new char*[2]
    };
    parentGroup.gr_mem[0] = new char[MAX_STRING_SIZE];
    parentGroup.gr_mem[1] = NULL;

}

void deleteAll(struct passwd *pUser, 
               struct group *pUserGroup, 
               struct group *pParentGroup, 
               struct spwd *pUserShadow) {

    if (pUser) {
        if (pUser->pw_name) {
            delete[] pUser->pw_name;
        }
        if (pUser->pw_passwd) {
            delete[] pUser->pw_passwd;
        }
        if (pUser->pw_gecos) {
            delete[] pUser->pw_gecos;
        }
        if (pUser->pw_dir) {
            delete[] pUser->pw_dir;
        }
        if (pUser->pw_shell) {
            delete[] pUser->pw_shell;
        }
    }

    if (pUserGroup) {
        if (pUserGroup->gr_name) {
            delete[] pUserGroup->gr_name;
        }
        if (pUserGroup->gr_passwd) {
            delete[] pUserGroup->gr_passwd;
        }
    }

    if (pParentGroup) {
        if (pParentGroup->gr_name) {
            delete[] pParentGroup->gr_name;
        }
        if (pParentGroup->gr_passwd) {
            delete[] pParentGroup->gr_passwd;
        }

        char **ptr = pParentGroup->gr_mem; 
        if (ptr) {
            while (*ptr != NULL) {
                delete[] *ptr;
                ptr++;
            }
        }

        if (pParentGroup->gr_mem) {
            delete[] pParentGroup->gr_mem;
        }
    }

    if (pUserShadow) {
        if (pUserShadow->sp_namp) {
            delete[] pUserShadow->sp_namp;
        }
        if (pUserShadow->sp_pwdp) {
            delete[] pUserShadow->sp_pwdp;
        } 
    }

}

