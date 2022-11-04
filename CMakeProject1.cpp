#include <winsock2.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#include <stdio.h>
#include <string.h>
#include <windows.h>



// выводит 6 байт, начиная с addr в консоль
void PrintMACaddress(BYTE* addr) {
    printf("   MAC ");
    for (int i = 0; i < 6; ++i) {
        printf("%02x%c", *addr++, (i < 5) ? '-' : '\n');
    }
}

// печатаем МАК адреса всех адаптеров
static void GetMACaddress() {
    IP_ADAPTER_INFO AdapterInfo[16];       // информация о 16 адаптерах макс
    DWORD dwBufLen = sizeof(AdapterInfo); // кол-во байт в буффере
    DWORD dwStatus = GetAdaptersInfo(AdapterInfo, &dwBufLen);
    if (dwStatus != ERROR_SUCCESS) {
        printf("GetAdaptersInfo failed. err=%d\n", GetLastError());
        return;
    }

    PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo; // информация о текущем адаптере
    while (pAdapterInfo) {
        // пока есть информация об адаптерах
        if (pAdapterInfo->Type == MIB_IF_TYPE_ETHERNET) {
            PrintMACaddress(pAdapterInfo->Address);   // печатаем MAC
        }
        break;
        //pAdapterInfo = pAdapterInfo->Next;        // переходим к информации о следующем адаптере
    }
}
//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!CPUID MBRDID
typedef struct _RawSmbiosData
{
    BYTE    Used20CallingMethod;
    BYTE    SMBIOSMajorVersion;
    BYTE    SMBIOSMinorVersion;
    BYTE    DmiRevision;
    DWORD   Length;
    BYTE    SMBIOSTableData[1];
} RAW_SMBIOS_DATA, * PRAW_SMBIOS_DATA;

typedef struct _SmbiosStructHeader
{
    BYTE Type;
    BYTE Length;
    WORD Handle;
} SMBIOS_STRUCT_HEADER, * PSMBIOS_STRUCT_HEADER;
PRAW_SMBIOS_DATA GetSmbiosData()
{
    DWORD bufferSize = 0;

    PRAW_SMBIOS_DATA smbios = NULL;

    // Get required buffer size
    bufferSize = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
    if (bufferSize) {
        smbios = (PRAW_SMBIOS_DATA)LocalAlloc(LPTR, bufferSize);
        bufferSize = GetSystemFirmwareTable('RSMB', 0, (PVOID)smbios, bufferSize);
    }

    return smbios;
}

PSMBIOS_STRUCT_HEADER GetNextStructure(PRAW_SMBIOS_DATA smbios, PSMBIOS_STRUCT_HEADER previous)
{
    PSMBIOS_STRUCT_HEADER next = NULL;
    PBYTE c = NULL;

    // Return NULL is no data found
    if (NULL == smbios)
        return NULL;

    // Return first table if previous was NULL
    if (NULL == previous)
        return (PSMBIOS_STRUCT_HEADER)(&smbios->SMBIOSTableData[0]);

    // Move to the end of the formatted structure
    c = ((PBYTE)previous) + previous->Length;

    // Search for the end of the unformatted structure (\0\0)
    while (true) {
        if ('\0' == *c && '\0' == *(c + 1)) {
            /* Make sure next table is not beyond end of SMBIOS data
             * (Thankyou Microsoft for ommitting the structure count
             * in GetSystemFirmwareTable
             */
            if ((c + 2) < ((PBYTE)smbios->SMBIOSTableData + smbios->Length))
                return (PSMBIOS_STRUCT_HEADER)(c + 2);
            else
                return NULL; // We reached the end
        }

        c++;
    }

    return NULL;
}

PSMBIOS_STRUCT_HEADER GetNextStructureOfType(PRAW_SMBIOS_DATA smbios, PSMBIOS_STRUCT_HEADER previous, DWORD type)
{
    PSMBIOS_STRUCT_HEADER next = previous;
    while (NULL != (next = GetNextStructure(smbios, next))) {
        if (type == next->Type)
            return next;
    }

    return NULL;
}

//вывод значения числового параметра таблицы SMBIOS по указанному смещению
void PrintBiosValue(PRAW_SMBIOS_DATA smbios, DWORD type, DWORD offset, DWORD size)
{
    PSMBIOS_STRUCT_HEADER head = NULL;
    PBYTE cursor = NULL;

    head = GetNextStructureOfType(smbios, head, type);
    if (NULL == head) { printf("PrintBiosValue Error!\n"); return; }

    cursor = ((PBYTE)head + offset);

    //value           
    for (int i = 0; i < size; i++) {
        printf("%02x", (unsigned int)*cursor);
        cursor++;
    }
    printf("\n");
}

void GetSmbiosString(PSMBIOS_STRUCT_HEADER table, BYTE index, LPWSTR output, int cchOutput)
{
    DWORD i = 0;
    DWORD len = 0;
    wcscpy(output, L"");

    if (0 == index) return;

    char* c = NULL;

    for (i = 1, c = (char*)table + table->Length; '\0' != *c; c += strlen(c) + 1, i++) {
        if (i == index) {
            len = MultiByteToWideChar(CP_UTF8, 0, c, -1, output, cchOutput);
            break;
        }
    }
}


//вывод значения строкового параметра таблицы SMBIOS по указанному смещению
void PrintBiosString(PRAW_SMBIOS_DATA smbios, DWORD type, DWORD offset)
{
    PSMBIOS_STRUCT_HEADER head;
    head = NULL;
    PBYTE cursor = NULL;
    WCHAR buf[1024];

    head = GetNextStructureOfType(smbios, head, type);
    if (NULL == head) { printf("PrintString Error!\n"); return; }
    cursor = ((PBYTE)head + offset);
    BYTE val = *cursor;

    GetSmbiosString((head), *cursor, buf, 1024);
    //  value           
    wprintf(L"%s\n", buf);
}


#define SMB_TABLE_BASEBOARD         2
#define SMB_TABLE_PROCESSOR         4

//!!!!!!!!!!HDD
struct DiskInfo {
    char Vendor[40];
    char SerialNumber[40];
    char ProductId[40];
    char ProductRevision[40];
    char Version[40];
    BYTE dev_type_modifier;
    BOOLEAN removable_media;
    BOOLEAN command_queuening;
    int bus_type;
    unsigned char raw_dev_properties[2];
};

bool query_physical_drive_information(HANDLE h_dev, DiskInfo* p_hddinfo_st)
{
    STORAGE_PROPERTY_QUERY storage_property_query;
    STORAGE_DESCRIPTOR_HEADER storage_desc_header;
    DWORD dwBytesReturned = 0;
    storage_property_query.PropertyId = StorageDeviceProperty,
        storage_property_query.QueryType = PropertyStandardQuery;
    if (!DeviceIoControl(h_dev, IOCTL_STORAGE_QUERY_PROPERTY, &storage_property_query, sizeof(STORAGE_PROPERTY_QUERY), &storage_desc_header, sizeof(STORAGE_DESCRIPTOR_HEADER), &dwBytesReturned, NULL))
        return false;

    const DWORD dwOutBufferSize = storage_desc_header.Size;
    unsigned char* pBuffer = (unsigned char*)calloc(dwOutBufferSize, sizeof(unsigned char));
    if (!DeviceIoControl(h_dev, IOCTL_STORAGE_QUERY_PROPERTY, &storage_property_query, sizeof(STORAGE_PROPERTY_QUERY), pBuffer, dwOutBufferSize, &dwBytesReturned, NULL))
        return false;

    STORAGE_DEVICE_DESCRIPTOR* p_dev_desc = (STORAGE_DEVICE_DESCRIPTOR*)pBuffer;
    strcpy(p_hddinfo_st->SerialNumber, (const char*)pBuffer + p_dev_desc->SerialNumberOffset);
    strcpy(p_hddinfo_st->Vendor, (const char*)pBuffer + p_dev_desc->VendorIdOffset);
    strcpy(p_hddinfo_st->ProductId, (const char*)pBuffer + p_dev_desc->ProductIdOffset);
    strcpy(p_hddinfo_st->ProductRevision, (const char*)pBuffer + p_dev_desc->ProductRevisionOffset);
    strcpy(p_hddinfo_st->Version, (const char*)pBuffer + p_dev_desc->Version);
    p_hddinfo_st->dev_type_modifier = *(BYTE*)pBuffer + p_dev_desc->DeviceTypeModifier;
    p_hddinfo_st->removable_media = *(BOOLEAN*)pBuffer + p_dev_desc->RemovableMedia;
    p_hddinfo_st->command_queuening = *(BOOLEAN*)pBuffer + p_dev_desc->CommandQueueing;
    p_hddinfo_st->bus_type = *(int*)pBuffer + p_dev_desc->BusType;
    p_hddinfo_st->raw_dev_properties[0] = (char)pBuffer + p_dev_desc->RawDeviceProperties[0];
    p_hddinfo_st->raw_dev_properties[1] = (char)pBuffer + p_dev_desc->RawDeviceProperties[1];
    return true;
}
//! !!!!!!!!!!!
//! !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

int main()
{

#if defined(linux) || defined(__linux)
    #include <sys/socket.h>
    #include <sys/ioctl.h>
    #include <linux/if.h>
    #include <netdb.h>
    printf("this is linux!\n");
    //!!!!!!!!!!!!!!!!!!!!!!!!MAC
    //! struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, "eth0");
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        int i;
        for (i = 0; i < 6; ++i)
            printf(" %02x", (unsigned char)s.ifr_addr.sa_data[i]);
        puts("\n");
        return 0;
    }
    $ lshal | grep 'system\.hardware\.serial'
    system.hardware.serial = '<serial-number>'  (string)

    //! !!

    printf("this is linux!\n");
#endif
#if defined(_WIN32) || defined (_WIN64) /*первый для обеих определён*/
    printf("this is windows!\n");   //!!!!!!!!!!!!!!!!WIN
    GetMACaddress();
    PRAW_SMBIOS_DATA data = GetSmbiosData();
    if (data == NULL) {
        printf("Can't get SMBIOS data!");
        return 1;
    }
    printf("   Motherboard: ");
    PrintBiosString(data, SMB_TABLE_BASEBOARD, 7);

    printf("   CPUID: ");
    PrintBiosValue(data, SMB_TABLE_PROCESSOR, 8, 8);  //Таблица SMBIOS содержит только 2 DWORD-значения CPUID из 4, но этого обычно достаточно

    //!!!HDD
    DiskInfo info = { 0 };
    HANDLE hDevice = CreateFileA("\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice != INVALID_HANDLE_VALUE && query_physical_drive_information(hDevice, &info)) {
        printf("   HDD: %s\n", info.SerialNumber);
    }
    //! !!!!
    printf("this is windows!\n");
#endif
#if defined(__APPLE__) && defined(__MACH__)
#include <TargetConditionals.h>
#if TARGET_IPHONE_SIMULATOR == 1
    /* iOS in Xcode simulator */
    printf("this is ios in Xcode simulator!\n");
#elif TARGET_OS_IPHONE == 1
    /* iOS */
    printf("this is ios!\n");
#elif TARGET_OS_MAC == 1
    /* macOS */
    printf("this is mac os!\n");
#endif
#endif
#if defined(ANDROID) || defined(__ANDROID__)
    printf("this is android!\n");
#endif

}

/*
#include <iostream>
#include <stdint.h>
#include <QString>

int main()
{
    std::cout << "Hello World!\n";
}
QString getMacAddress()
{
    foreach(QNetworkInterface netInterface, QNetworkInterface::allInterfaces())
    {
        // Return only the first non-loopback MAC Address
        if (!(netInterface.flags() & QNetworkInterface::IsLoopBack))
            return netInterface.hardwareAddress();
    }
    return QString();
}
*/
// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
/*
QString getMacAddress()
{
    foreach(QNetworkInterface netInterface, QNetworkInterface::allInterfaces())
    {
        // Return only the first non-loopback MAC Address
        if (!(netInterface.flags() & QNetworkInterface::IsLoopBack))
            return netInterface.hardwareAddress();
    }
    return QString();
}
*/