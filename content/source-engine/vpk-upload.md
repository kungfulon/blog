---
title: "Source Engine Exploitation: (Un)restricted file upload strikes again"
date: 2022-01-27T16:58:00+07:00
draft: false
---

## Introduction

This post will cover the exploitation chain I used to attack Source 1 Dedicated Servers. I have verified the exploit against these games:

- Left 4 Dead
- Left 4 Dead 2
- Counter-Strike: Global Offensive

## Source Engine file system

Source Engine allows games to "mount" multiple directories as the file search path. For example, we have `a` and `b` directories. When we mount those directories to the file system, the game will access both directories under the same virtual root (like virtually merging these directories). If there are files with the same relative path in both folders, whichever is mounted first will have greater priority.

Initially, Valve used [GCF file format](https://developer.valvesoftware.com/wiki/GCF) to store game assets. It suffers from poor performance, probably [due to fragmentation](https://web.archive.org/web/20170915143435/http://nemesis.thewavelength.net/index.php?c=216). With the release of Source Engine 2013, [VPK file format](https://developer.valvesoftware.com/wiki/VPK_File_Format) was introduced to replace the old GCF file format.

Directories and VPK files are mounted by putting them into the `gameinfo.txt` file. More information on it can be found [here](https://developer.valvesoftware.com/wiki/Gameinfo.txt). As in the documentation, VPK files have to be explicitly mounted. But that changed in the L4D branch: now, when a directory is mounted, the engine will scan for `pakXX.vpk` files, with `XX` being a two-digit number from `01` to `98`, then mount them. The logic can be seen in [`CBaseFileSystem::AddSearchPath` function](https://github.com/perilouswithadollarsign/cstrike15_src/blob/master/filesystem/basefilesystem.cpp#L2671):

```cpp
void CBaseFileSystem::AddSearchPath( const char *pPath, const char *pathID, SearchPathAdd_t addType )
{
    // ...
#ifdef SUPPORT_VPK
    // scan for vpk's
    for( int i = 1 ; i < 99; i++ )
    {
        char newVPK[MAX_PATH];
        sprintf( newVPK, "%s/pak%02d_dir.vpk", pPath, i );
        // we will fopen to bypass pathing, etc
        FILE *pstdiofile = fopen( newVPK, "rb" );
        if ( pstdiofile )
        {
            fclose( pstdiofile );
            sprintf( newVPK, "%s/pak%02d.vpk", pPath, i );
            AddVPKFile( newVPK );
        }
        else
        {
            break;
        }
    }
#endif
    // ...
}
```

If users find or open a file with a relative path, the engine will always search in VPK files first. In [`CBaseFileSystem::FindFile` function](https://github.com/perilouswithadollarsign/cstrike15_src/blob/master/filesystem/basefilesystem.cpp#L4136):

```cpp
FileHandle_t CBaseFileSystem::FindFile( 
    const CSearchPath *path, 
    const char *pFileName, 
    const char *pOptions, 
    unsigned flags, 
    char **ppszResolvedFilename, 
    bool bTrackCRCs )
{
    VPROF( "CBaseFileSystem::FindFile" );

    char tempSymlinkBuffer[MAX_PATH];
    pFileName = V_FormatFilenameForSymlinking( tempSymlinkBuffer, pFileName );
    
    CFileOpenInfo openInfo( this, pFileName, path, pOptions, flags, ppszResolvedFilename, bTrackCRCs );
    bool bIsAbsolutePath = V_IsAbsolutePath( pFileName );
    if ( bIsAbsolutePath )
    {
#ifdef SUPPORT_VPK
        if ( m_VPKFiles.Count()  && ( ! V_stristr( pFileName, ".vpk" ) ) )
        {
            // FileSystemWarning( FILESYSTEM_WARNING, "***VPK: FindFile Attempting to use full path with VPK file!\n\tFile: %s\n", pFileName );
        }
#endif
        openInfo.SetAbsolutePath( "%s", pFileName );

        // Check if it's of the form C:/a/b/c/blah.zip/materials/blah.vtf
        if ( HandleOpenFromZipFile( openInfo ) )
        {
            return (FileHandle_t)openInfo.m_pFileHandle;
        }
    }
    else
    {
        // check vpk file
#ifdef SUPPORT_VPK
        for( int i = 0 ; i < m_VPKFiles.Count(); i++ )
        {
            CPackedStoreFileHandle fHandle = m_VPKFiles[i]->OpenFile( pFileName );
            if ( fHandle )
            {
                openInfo.m_pFileHandle = new CFileHandle(this);
                openInfo.m_pFileHandle->m_VPKHandle = fHandle;
                openInfo.m_pFileHandle->m_type = FT_NORMAL;
                openInfo.m_pFileHandle->m_nLength = fHandle.m_nFileSize;
                openInfo.SetResolvedFilename( openInfo.m_AbsolutePath );
        
                // Remember what was returned by the Steam filesystem and track the CRC.
                openInfo.m_bLoadedFromSteamCache = false;
                openInfo.m_bSteamCacheOnly = false;
                openInfo.m_pVPKFile = m_VPKFiles[i];
                openInfo.HandleFileCRCTracking( openInfo.m_pFileName, false );
                return ( FileHandle_t ) openInfo.m_pFileHandle;
            }
        }
#endif
        // Caller provided a relative path
        if ( path->GetPackFile() )
        {
            HandleOpenFromPackFile( path->GetPackFile(), openInfo );
            return (FileHandle_t)openInfo.m_pFileHandle;
        }
        else
        {
            openInfo.SetAbsolutePath( "%s%s", path->GetPathString(), pFileName );
        }
    }

    // now have an absolute name
    HandleOpenRegularFile( openInfo, bIsAbsolutePath );
    return (FileHandle_t)openInfo.m_pFileHandle;
}
```

## (Un)restricted file upload

Supports for file upload/download from both client and server has been supported since GoldSrc (Half-Life 1 engine). Community server owners mainly use it to serve custom content to players. In the beginning, people can freely [upload any file and use path traversal](http://aluigi.altervista.org/adv/sourceupfile-adv.txt). Since then, Valve has implemented more and more restrictions to the file upload feature: blocking `..` path traversal, blocking absolute paths, blocking & allowing file extensions, ... but it was still being exploited now and then with either bypassing the filters or abusing the engine's logic. Furthermore, there are at least two versions of the filters, one for the Source 2013 branch and one for the L4D/L4D2/CS:GO branch. I don't know why Valve used different logic for the same feature.

Server owners can prevent clients from uploading files to the server by setting `sv_allowupload` to `0`, at the cost of clients wouldn't be able to use custom sprays. CS:GO is a particular case: it doesn't allow players to use custom sprays and instead sells them as cosmetic items. This led to Valve eventually setting `sv_allowupload` to `0` by default in [an update on 2018/08/02](https://blog.counter-strike.net/index.php/2018/02/20051/).

In Source 2013 games, there is a separated directory to handle uploaded contents in `gameinfo.txt`. For example, in TF2:

```js
            // Random files downloaded from gameservers go into a seperate directory, so
            // that it's easy to keep those files segregated from the official game files
            // or customizations intentially installed by the user.
            //
            // This directory is searched LAST.  If you visit a server and download
            // a custom model, etc, we don't want that file to override the default
            // game file indefinitely (after you have left the server).  Servers CAN have
            // custom content that overrides the default game files, it just needs to be
            // packed up in the .bsp file so that it will be mounted as a map search pack.
            // The map search pack is mounted at the top of the search path list,
            // but only while you are connected that server and on that map.
            game+download   tf/download
```

But from L4D onwards, only the main game path (and DLCs) are mounted. For example, in CS:GO:

```js
        //
        // Search paths are relative to the base directory, which is where hl2.exe is found.
        //
        // |gameinfo_path| points at the directory where gameinfo.txt is.
        // We always want to mount that directory relative to gameinfo.txt, so
        // people can mount stuff in c:\mymod, and the main game resources are in
        // someplace like c:\program files\valve\steam\steamapps\<username>\half-life 2.
        //
        SearchPaths
        {
            Game                |gameinfo_path|.
            Game                csgo
        }
```

That means the default directory for uploaded contents will be the main game path.

When the engine receives a file upload request, it will check the file path using [`CNetChan::IsValidFileForTransfer` function](https://github.com/perilouswithadollarsign/cstrike15_src/blob/master/engine/net_chan.cpp#L3585):

```cpp
bool CNetChan::IsValidFileForTransfer( const char *pszFilename )
{
    if ( !pszFilename || !pszFilename[0] )
        return false;

    // No absolute paths or weaseling up the tree with ".." allowed.
    if ( !COM_IsValidPath( pszFilename ) || V_IsAbsolutePath( pszFilename ) )
        return false;

    char szTemp[MAX_PATH];
    int l = V_strlen( pszFilename );
    if ( l >= sizeof(szTemp) )
        return false;
    V_strcpy_safe( szTemp, pszFilename );
    V_FixSlashes( szTemp, '/' );
    if ( szTemp[l-1] == '/' )
        return false;

    if (
        V_stristr( pszFilename, "lua/" )
        || V_stristr( pszFilename, "gamemodes/" )
        || V_stristr( pszFilename, "scripts/" )
        || V_stristr( pszFilename, "addons/" )
        || V_stristr( pszFilename, "cfg/" )
        || V_stristr( pszFilename, "~/" )
        || V_stristr( pszFilename, "gamemodes.txt" )
        )
        return false;

    // Allow only bsp and nav file transfers to not overwrite any assets in maps directory
    if ( V_stristr( pszFilename, "maps/" ) &&
        !V_stristr( pszFilename, ".bsp" ) &&
        !V_stristr( pszFilename, ".ain" ) &&
        !V_stristr( pszFilename, ".nav" ) )
        return false;

    const char *extension = V_strrchr( pszFilename, '.' );
    if ( !extension )
        return false;

    int baseLen = V_strlen( extension );
    if ( baseLen > 4 || baseLen < 3 )
        return false;

    // are there any spaces in the extension? (windows exploit)
    const char *pChar = extension;
    while ( *pChar )
    {
        if ( V_isspace( *pChar ) )
        {
            return false;
        }

        ++pChar;
    }

    if ( !Q_strcasecmp( extension, ".cfg" ) ||
        !Q_strcasecmp( extension, ".lst" ) ||
        !Q_strcasecmp( extension, ".lmp" ) ||
        !Q_strcasecmp( extension, ".exe" ) ||
        !Q_strcasecmp( extension, ".vbs" ) ||
        !Q_strcasecmp( extension, ".com" ) ||
        !Q_strcasecmp( extension, ".bat" ) ||
        !Q_strcasecmp( extension, ".dll" ) ||
        !Q_strcasecmp( extension, ".ini" ) ||
        !Q_strcasecmp( extension, ".log" ) ||
        !Q_strcasecmp( extension, ".lua" ) ||
        !Q_strcasecmp( extension, ".nut" ) ||
        !Q_strcasecmp( extension, ".vdf" ) ||
        !Q_strcasecmp( extension, ".smx" ) ||
        !Q_strcasecmp( extension, ".gcf" ) ||
        !Q_strcasecmp( extension, ".sys" ) )
    {
        return false;
    }

    return true;
}
```

We can see that the `.vpk` extension is not blocked. Along with the fact that the engine will load `pakXX.vpk` when mounting the filesystem, we can upload `pak02.vpk` to the server, and it will be mounted when the server is restarted. This is a massive win since we can put any file inside the pack file, effectively bypassing the file extension blocklist. A crash bug can be used to force the server to restart since most servers will be using an auto-restart script.

## Code execution

Now that we have unrestricted file upload, there are many ways to achieve code execution. One can chain this with a memory corruption bug (like loading a malicious model or metadata) since the engine code is unsafe. But there is an easier way: loading an external library as a [plugin for the engine](https://developer.valvesoftware.com/wiki/Server_plugins). Looking at the blocklist, we can easily see that the`.so` extension is not blocked, so we can upload a library to the server, then use the `plugin_load` console command to load the library. We can put the command into `cfg/autoexec.cfg`, then put the file into `pak02.vpk` to automatically run it when the server restart. Note that the library must be uploaded separately since the engine does not support loading a library from a VPK file.

## Conclusion

Usually, when attacking Source Engine, people tend to find a memory corruption bug since it's written in C/C++ and uses multiple file formats (`grep -i assert` FTW). But usually, an information disclosure bug is necessary, and it is much harder to find one. The engine is complex, and there are many mechanisms hackers can abuse to their advantage. There are still more issues that I want to talk about. Unfortunately, Valve are slow in resolving the reports. I hope you enjoy this, and stay tuned for the next article.

## Timeline

- 2021/04/24: Reported to Valve's HackerOne program
- 2021/04/29: Fixed in Counter-Strike: Global Offensive
- 2021/05/04: Bounty awarded ($7500)
- 2021/??/??: Fixed in Left 4 Dead & Left 4 Dead 2
- 2022/01/26: Report marked as resolved
