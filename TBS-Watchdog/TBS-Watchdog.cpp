// Use TBM Based Services to ensure boot system integrity via PCR 7

#include "TBS-Watchdog.h"


// Helper function to print our digest 
void PrintHex(const unsigned char* data, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

int main()
{
    TBS_CONTEXT_PARAMS2 params;
    TBS_HCONTEXT hContext = NULL;
    TBS_RESULT result = TBS_SUCCESS;
    UINT32 targetPcr = 7; // Target PCR index 7 since it tracks secure boot and device guard info 
    std::vector<BYTE> responseBuffer(1024, 0); // For our response
    UINT32 responseSize = responseBuffer.size();
    UINT32 responseCode;
    size_t digestOffset;
    BYTE* pcrDigest;    
    PCRReadCommand readCmd = { 0 }; // Command blob
 
    // Set TBS params
    params.version = TBS_CONTEXT_VERSION_TWO;    
    params.includeTpm20 = 1; // Explicitly request TPM 2.0 support

    printf("Connecting to TBS...\n");

    // Connect to TBS 
    result = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&params, &hContext);
    if (result != TBS_SUCCESS)
    {
        switch (result)
        {
        case TBS_E_BAD_PARAMETER:
            printf("ERROR; Bad parameter passed to Tbsi_Context_Create\n");
            break;
        case TBS_E_SERVICE_DISABLED:
            printf("ERROR; TBS Service is disabled on current machine\n");
            break;
        case TBS_E_SERVICE_NOT_RUNNING:
            printf("ERROR; TBS Service is not running on current machine\n");
            break;
        case TBS_E_TPM_NOT_FOUND:
            printf("ERROR; TPM not found on current machine\n");
            break;
        case TBS_E_TOO_MANY_TBS_CONTEXTS:
            printf("ERROR; Too many TBS contexts are currently open to continue\n");
            break;
        default:
            printf("ERROR; Failed Tbsi_Context_Create, error 0x%x - please make sure you are running with admin privs\n", result);
        }

        return -1;        
    }

    printf("Successfully connected to TBS service!\n");

    // Setup our PCR command blob config
    readCmd.tag = REVERSE_16(TPM_ST_NO_SESSIONS);
    readCmd.commandSize = REVERSE_32(sizeof(readCmd));
    readCmd.commandCode = REVERSE_32(TPM_CC_PCR_Read);
    readCmd.count = REVERSE_32(1);
    readCmd.hashAlg = REVERSE_16(TPM_ALG_SHA256);
    readCmd.sizeofSelect = 3;

    // Three-byte array we have to set to the corresponding PCR index 
    readCmd.pcrSelect[0] = 0;
    readCmd.pcrSelect[1] = 0;
    readCmd.pcrSelect[2] = 0;
    readCmd.pcrSelect[targetPcr / 8] |= (1 << (targetPcr % 8));

    // Submit our command 
    result = Tbsip_Submit_Command(hContext, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL, (const BYTE*)(&readCmd), sizeof(readCmd), responseBuffer.data(), &responseSize);
    if (result != TBS_SUCCESS)
    {
        switch (result)
        {
        case TBS_E_BAD_PARAMETER:
            printf("ERROR; Bad parameter passed to Tbsip_Submit_Command\n");
            break;
        case TBS_E_INTERNAL_ERROR:
            printf("ERROR; Internal TBS error occured\n");
            break;
        case TBS_E_INSUFFICIENT_BUFFER:
            printf("ERROR; Insufficient space in buffer\n");
            break;
        case TBS_E_INVALID_CONTEXT:
            printf("ERROR; Current TBS context not valid\n");
            break;
        case TBS_E_IOERROR:
            printf("ERRO; I/O error occured when communicating with TBS\n");
            break;
        default:
            printf("ERROR; Failed Tbsip_Submit_Command, error 0x%X\n", result);
        }
        
        Tbsip_Context_Close(hContext);

        return -1;
    }

    responseCode = REVERSE_32(*(UINT32*)&responseBuffer[6]);
    if (responseCode != 0) {
        printf("ERROR; TPM returned error code 0x%X\n", responseCode);
        Tbsip_Context_Close(hContext);
        return -1;
    }

    digestOffset = responseSize - 32;
    pcrDigest = &responseBuffer[digestOffset];

    printf("Dumping Contents of PCR 7...\n");

    PrintHex(pcrDigest, 32);

    printf("Closing context to TBS service...\n");

    Tbsip_Context_Close(hContext);

    return 0;
}
