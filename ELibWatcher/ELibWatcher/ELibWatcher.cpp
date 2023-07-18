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
    δ֪����,
    ȡ�ֽڼ�,
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

#pragma pack (push, old_value)   // ����VC++�������ṹ�����ֽ�����
#pragma pack (1)    // ����Ϊ��һ�ֽڶ��롣

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
        char* m_pText;            // SDT_TEXT,������ΪNULL��Ϊ�˱����޸ĵ�������(m_pText�п���ָ����������)�е�����,ֻ�ɶ�ȡ�����ɸ������е�����
        LPBYTE m_pBin;            // SDT_BIN,������ΪNULL,ֻ�ɶ�ȡ�����ɸ������е����ݡ�
        DWORD  m_dwSubCodeAdr;    // SDT_SUB_PTR,��¼�ӳ�������ַ��
        void* m_pCompoundData;    // ����������������ָ��,ָ����ָ�����ݵĸ�ʽ��� run.h ������ֱ�Ӹ������е����ݳ�Ա,���������Ҫ���������ͷŸó�Ա��
        void* m_pAryData;        // ��������ָ��,ָ����ָ�����ݵĸ�ʽ��� run.h ��ע�����Ϊ�ı����ֽڼ�����,���Ա����ָ�����ΪNULL��ֻ�ɶ�ȡ�����ɸ������е����ݡ�

        //! Ϊָ�������ַ��ָ��,�������������������ʵ�ֺ���ʱ�����á�
        BYTE* m_pByte;    // SDT_BYTE*
        SHORT* m_pShort;    // SDT_SHORT*
        INT* m_pInt;        // SDT_INT*
        DWORD* m_pUInt;    // ((DWORD)SDT_INT)*
        INT64* m_pInt64;    // SDT_INT64*
        FLOAT* m_pFloat;    // SDT_FLOAT*
        DOUBLE* m_pDouble;    // SDT_DOUBLE*
        DATE* m_pDate;    // SDT_DATE_TIME*
        BOOL* m_pBool;    // SDT_BOOL*
        char** m_ppText;    // SDT_TEXT,*m_ppText����ΪNULL��ע��д����ֵ֮ǰ�����ͷ�ǰֵ,����MFree (*m_ppText)������ֱ�Ӹ���*m_ppText��ָ�������,ֻ���ͷ�ԭָ�������ָ�롣
        LPBYTE* m_ppBin;    // SDT_BIN,*m_ppBin����ΪNULL��ע��д����ֵ֮ǰ�����ͷ�ǰֵ,����MFree (*m_ppBin)������ֱ�Ӹ���*m_ppBin��ָ�������,ֻ���ͷ�ԭָ�������ָ�롣
        DWORD* m_pdwSubCodeAdr;            // SDT_SUB_PTR,�ӳ�������ַ������
        void** m_ppCompoundData;    // �����������ͱ���������ֱ�Ӹ������е����ݳ�Ա,���������Ҫ���������ͷŸó�Ա��
        void** m_ppAryData;            // �������ݱ���,ע�⣺1��д����ֵ֮ǰ�����ͷ�ԭֵ(ʹ��NRS_FREE_VAR֪ͨ)��2���������Ϊ�ı����ֽڼ�����,���Ա����ָ�����ΪNULL������ֱ�Ӹ���*m_ppAryData��ָ�������,ֻ���ͷ�ԭָ�������ָ�롣
    };
    std::uint32_t m_dtDataType;
};

#pragma pack (pop, old_value)    // �ָ�VC++�������ṹ�����ֽ�����


thread_local std::unordered_map<unsigned int, std::shared_ptr<spdlog::logger>> threadLoggers;

std::shared_ptr<spdlog::logger> getCurrentThreadLogger()
{
    unsigned int threadId = GetCurrentThreadId();
    // ����̱߳��ش洢���Ƿ������־��
    auto it = threadLoggers.find(threadId);
    if (it != threadLoggers.end())
    {
        return it->second;
    }
    // �����µ���־�����洢���̱߳��ش洢��
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
    logger->info("���ú���֧�ֿ⺯��:{:x}", libFuncAddr);
    for (int n = 0; n < nArgCount; ++n) {
        if (pArgInf[n].m_dtDataType == 0x0) {
            logger->info("����{}:ʡ��", n + 1);
        }
        else if (pArgInf[n].m_dtDataType == 0x80000301) {
            logger->info("����{},������:{}", n + 1, pArgInf[n].m_int);
        }
        else if (pArgInf[n].m_dtDataType == 0x80000004) {
            logger->info("����{},�ı���:{}", n + 1, pArgInf[n].m_pText);
        }
        else if (pArgInf[n].m_dtDataType == 0x80000005) {
            logger->info("����{},�ֽڼ�:{}", n + 1, binToHexString(pArgInf[n].m_pBin));
        }
        else if (pArgInf[n].m_dtDataType == 0x80000601) {
            logger->info("����{},double��:{}", n + 1, pArgInf[n].m_double);
        }
    }
    AnyCall::invokeCdecl<void>((void*)libFuncAddr,pRetData,nArgCount,pArgInf);
    pRetData->m_dtDataType;
    logger->info("������������������������\r\n");
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
    //�Զ�����
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