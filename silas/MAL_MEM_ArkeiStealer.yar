rule MAL_EXE_ArkeiStealer_unpacked
{
        meta:
            author = "Silas Cutler"
            description = "Broad detection for unpacked Arkei Stealer. May overlap with other families"
            date = "2023-01-01"
            version = "1.0"
            hash = "1c80bf69e9bc172ce0f0eb5963d89217797a7358747eb2679da2f5cd29e2e0d6"
            DaysofYARA = "7/100"

        strings:
            $ = "%DRIVE_REMOVABLE%"
            $ = "%s\\%s\\%s\\chrome-extension_%s_0.indexeddb.leveldb"
            $ = "*%DRIVE_FIXED%*"
            $ = "*%DRIVE_REMOVABLE%*"
            $ = "Content-Disposition: form-data; name=\""
            $ = "\\History\\%s_%s.txt"
            $ = "https://steamcommunity.com/profiles/76561199445991535"
            $ = "Install date:"
            $ = "\\Downloads\\%s_%s.txt"
        condition:
                8 of them
}
