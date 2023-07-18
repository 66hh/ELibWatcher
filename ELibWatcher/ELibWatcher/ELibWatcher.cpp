#include "ELibWatcher.h"
#include "Utils/InlineHook.h"
#include "MinHook/MinHook.h"
#include "Utils/AnyCall.h"
#include <cstdarg>
#include <cstdint>
#include <sstream>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <set>
#include <mutex>
#include "./Utils/WindowsApi.h"
#include "./Utils/FastBinSearch.h"

typedef void(__cdecl* funcKrnlLib)(void* argCount);
funcKrnlLib gFuncKrnlnLib = NULL;

enum LibFunc
{
    未知函数,
    取字节集,
};

ELibWatcher::ELibWatcher()
{
	MH_Initialize();
}

ELibWatcher::~ELibWatcher()
{
	MH_Uninitialize();
}

ELibWatcher& ELibWatcher::Instance()
{
	static ELibWatcher gInstance;
	return gInstance;
}

#pragma pack (push, old_value)   // 保存VC++编译器结构对齐字节数。
#pragma pack (1)    // 设置为以一字节对齐。

struct MDATA_INF
{
    union
    {
        BYTE   m_byte;            // SDT_BYTE
        SHORT  m_short;            // SDT_SHORT
        INT    m_int;            // SDT_INT
        DWORD  m_uint;            // (DWORD)SDT_INT
        INT64  m_int64;            // SDT_INT64
        FLOAT  m_float;            // SDT_FLOAT
        DOUBLE m_double;        // SDT_DOUBLE
        DATE   m_date;            // SDT_DATE_TIME
        BOOL   m_bool;            // SDT_BOOL
        char* m_pText;            // SDT_TEXT,不可能为NULL。为了避免修改到常量段(m_pText有可能指向常量段区域)中的数据,只可读取而不可更改其中的内容
        LPBYTE m_pBin;            // SDT_BIN,不可能为NULL,只可读取而不可更改其中的内容。
        DWORD  m_dwSubCodeAdr;    // SDT_SUB_PTR,记录子程序代码地址。
        void* m_pCompoundData;    // 复合数据类型数据指针,指针所指向数据的格式请见 run.h 。可以直接更改其中的数据成员,但是如果需要必须首先释放该成员。
        void* m_pAryData;        // 数组数据指针,指针所指向数据的格式请见 run.h 。注意如果为文本或字节集数组,则成员数据指针可能为NULL。只可读取而不可更改其中的内容。

        //! 为指向变量地址的指针,仅当传入参数到库命令实现函数时才有用。
        BYTE* m_pByte;    // SDT_BYTE*
        SHORT* m_pShort;    // SDT_SHORT*
        INT* m_pInt;        // SDT_INT*
        DWORD* m_pUInt;    // ((DWORD)SDT_INT)*
        INT64* m_pInt64;    // SDT_INT64*
        FLOAT* m_pFloat;    // SDT_FLOAT*
        DOUBLE* m_pDouble;    // SDT_DOUBLE*
        DATE* m_pDate;    // SDT_DATE_TIME*
        BOOL* m_pBool;    // SDT_BOOL*
        char** m_ppText;    // SDT_TEXT,*m_ppText可能为NULL。注意写入新值之前必须释放前值,即：MFree (*m_ppText)。不可直接更改*m_ppText所指向的内容,只能释放原指针后换入新指针。
        LPBYTE* m_ppBin;    // SDT_BIN,*m_ppBin可能为NULL。注意写入新值之前必须释放前值,即：MFree (*m_ppBin)。不可直接更改*m_ppBin所指向的内容,只能释放原指针后换入新指针。
        DWORD* m_pdwSubCodeAdr;            // SDT_SUB_PTR,子程序代码地址变量。
        void** m_ppCompoundData;    // 复合数据类型变量。可以直接更改其中的数据成员,但是如果需要必须首先释放该成员。
        void** m_ppAryData;            // 数组数据变量,注意：1、写入新值之前必须释放原值(使用NRS_FREE_VAR通知)。2、变量如果为文本或字节集数组,则成员数据指针可能为NULL。不可直接更改*m_ppAryData所指向的内容,只能释放原指针后换入新指针。
    };
    std::uint32_t m_dtDataType;
};

#pragma pack (pop, old_value)    // 恢复VC++编译器结构对齐字节数。


thread_local std::unordered_map<unsigned int, std::shared_ptr<spdlog::logger>> threadLoggers;

std::shared_ptr<spdlog::logger> getCurrentThreadLogger()
{
    unsigned int threadId = GetCurrentThreadId();
    // 检查线程本地存储中是否存在日志器
    auto it = threadLoggers.find(threadId);
    if (it != threadLoggers.end())
    {
        return it->second;
    }
    // 创建新的日志器并存储到线程本地存储中
    std::string loggerName = "Thread-" + std::to_string(threadId);
    auto logger = std::make_shared<spdlog::logger>(loggerName, std::make_shared<spdlog::sinks::basic_file_sink_mt>(loggerName + ".log"));
    logger->flush_on(spdlog::level::info);
    threadLoggers[threadId] = logger;
    return logger;
}

const char* ByteMap[256] = {
    "00","01","02","03","04","05","06","07","08","09","0A","0B","0C","0D","0E","0F",
    "10","11","12","13","14","15","16","17","18","19","1A","1B","1C","1D","1E","1F",
    "20","21","22","23","24","25","26","27","28","29","2A","2B","2C","2D","2E","2F",
    "30","31","32","33","34","35","36","37","38","39","3A","3B","3C","3D","3E","3F",
    "40","41","42","43","44","45","46","47","48","49","4A","4B","4C","4D","4E","4F",
    "50","51","52","53","54","55","56","57","58","59","5A","5B","5C","5D","5E","5F",
    "60","61","62","63","64","65","66","67","68","69","6A","6B","6C","6D","6E","6F",
    "70","71","72","73","74","75","76","77","78","79","7A","7B","7C","7D","7E","7F",
    "80","81","82","83","84","85","86","87","88","89","8A","8B","8C","8D","8E","8F",
    "90","91","92","93","94","95","96","97","98","99","9A","9B","9C","9D","9E","9F",
    "A0","A1","A2","A3","A4","A5","A6","A7","A8","A9","AA","AB","AC","AD","AE","AF",
    "B0","B1","B2","B3","B4","B5","B6","B7","B8","B9","BA","BB","BC","BD","BE","BF",
    "C0","C1","C2","C3","C4","C5","C6","C7","C8","C9","CA","CB","CC","CD","CE","CF",
    "D0","D1","D2","D3","D4","D5","D6","D7","D8","D9","DA","DB","DC","DD","DE","DF",
    "E0","E1","E2","E3","E4","E5","E6","E7","E8","E9","EA","EB","EC","ED","EE","EF",
    "F0","F1","F2","F3","F4","F5","F6","F7","F8","F9","FA","FB","FC","FD","FE","FF"
};

inline const char* UCharToStr(unsigned char c)
{
    return ByteMap[c];
}

std::string binToHexString(unsigned char* pBin)
{
    std::string retHex;
    unsigned int binSize = *(unsigned int*)(pBin + 4);
    if (!binSize) {
        return retHex;
    }
    retHex.resize(binSize << 1);
    unsigned int index = 0;
    for (unsigned int n = 0; n < binSize; ++n) {
        const char* pHex = UCharToStr(pBin[8 + n]);
        retHex[index++] = pHex[0];
        retHex[index++] = pHex[1];
    }
    return retHex;
}

void __cdecl MyKrnlnLibHandler(MDATA_INF* pRetData, int nArgCount, MDATA_INF* pArgInf)
{
    unsigned int libFuncAddr;
    __asm {
        mov libFuncAddr, ebx;
    }
    auto logger = getCurrentThreadLogger();
    logger->info("调用核心支持库函数:{:x}", libFuncAddr);
    for (int n = 0; n < nArgCount; ++n) {
        if (pArgInf[n].m_dtDataType == 0x0) {
            logger->info("参数{}:省略", n + 1);
        }
        else if (pArgInf[n].m_dtDataType == 0x80000301) {
            logger->info("参数{},整数型:{}", n + 1, pArgInf[n].m_int);
        }
        else if (pArgInf[n].m_dtDataType == 0x80000004) {
            logger->info("参数{},文本型:{}", n + 1, pArgInf[n].m_pText);
        }
        else if (pArgInf[n].m_dtDataType == 0x80000005) {
            logger->info("参数{},字节集:{}", n + 1, binToHexString(pArgInf[n].m_pBin));
        }
        else if (pArgInf[n].m_dtDataType == 0x80000601) {
            logger->info("参数{},double型:{}", n + 1, pArgInf[n].m_double);
        }
    }
    AnyCall::invokeCdecl<void>((void*)libFuncAddr,pRetData,nArgCount,pArgInf);
    pRetData->m_dtDataType;
    logger->info("————————————\r\n");
}

void __declspec(naked) tranferKrnlnLib()
{
    __asm {
        lea     eax, dword ptr[esp + 0x8];
        sub     esp, 0xC;
        push    eax;
        push    dword ptr[esp + 0x14];
        xor eax, eax;
        mov     dword ptr[esp + 0x8], eax;
        mov     dword ptr[esp + 0xC], eax;
        mov     dword ptr[esp + 0x10], eax;
        lea     edx, dword ptr[esp + 0x8];
        push    edx;
        call    MyKrnlnLibHandler;
        mov     eax, dword ptr[esp + 0xC];
        mov     edx, dword ptr[esp + 0x10];
        mov     ecx, dword ptr[esp + 0x14];
        add     esp, 0x18;
        retn;
    }
}

void ELibWatcher::InitELibWatcher()
{
    unsigned int krnlnLibAddr = 0x0;
    //自动搜索
    unsigned int hExeMoudle = (unsigned int)GetModuleHandleA(0x0);
    if (hExeMoudle) {
        FastSearchPattern funcKrnlnLib("8D44240883EC0C50FF74241433C0894424088944240C894424108D54240852FFD38B44240C8B5424108B4C241483C418C3");
        int offset = funcKrnlnLib.searchOne((void*)hExeMoudle, GetModuleSize((unsigned int)hExeMoudle));
        if (offset >= 0) {
            krnlnLibAddr = hExeMoudle + offset;
        }

        FastSearchPattern floatToInt64("558BEC83C4F4D97DFE668B45FE80CC0C668945FCD96DFCDF7DF4D96DFE8B45F48B55F88BE55DC3");
        std::vector<unsigned int> offsetList = floatToInt64.searchAll((void*)hExeMoudle, GetModuleSize((unsigned int)hExeMoudle));
        for (unsigned int n = 0; n < offsetList.size(); ++n) {
            MH_CreateHook((LPVOID)(krnlnLibAddr), tranferKrnlnLib, (LPVOID*)&gFuncKrnlnLib);
            MH_EnableHook((LPVOID)(krnlnLibAddr));
        }
    }

    if (!krnlnLibAddr) {
        krnlnLibAddr = 0x4A40D6;
    }

    unsigned int tmpHookAddr;
	MH_CreateHook((LPVOID)(krnlnLibAddr), tranferKrnlnLib, (LPVOID*)&tmpHookAddr);
	MH_EnableHook((LPVOID)(krnlnLibAddr));
}