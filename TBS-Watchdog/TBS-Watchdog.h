#pragma once

#include <iostream>
#include <string>
#include <vector>

#include <Windows.h>
#include <tbs.h>

// Need big-endian for some of our command fields 
#define REVERSE_16(x) ((((x) >> 8) & 0xff) | (((x) & 0xff) << 8))
#define REVERSE_32(x) ((((x) >> 24) & 0xff) | (((x) << 8) & 0xff0000) | (((x) >> 8) & 0xff00) | (((x) & 0xff) << 24))

// I have an older SDK so define these myself 
#define TBS_E_BAD_PARAMETER         0x80284002
#define TBS_E_SERVICE_DISABLED		0x80284010
#define TBS_E_SERVICE_NOT_RUNNING	0x80284008
#define TBS_E_TPM_NOT_FOUND			0x8028400F
#define TBS_E_TOO_MANY_TBS_CONTEXTS	0x80284009
#define TBS_E_INTERNAL_ERROR        0x80284001
#define TBS_E_INSUFFICIENT_BUFFER   0x80284005
#define TBS_E_INVALID_CONTEXT       0x80284004
#define TBS_E_IOERROR               0x80284006

// TPM 2.0 Constants
const UINT16 TPM_ST_NO_SESSIONS = 0x8001; // Command tag for no sessions
const UINT32 TPM_CC_PCR_Read = 0x0000017E; // Command code for PCR Read
const UINT16 TPM_ALG_SHA256 = 0x000B;     // Algorithm ID for SHA-256

// This struct can be found in section 22.4.2 'Command and Response' in the document 'Trusted Platform Module Library Part 3: Commands' (https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf)
    // Ensure compiler does not put any fluff padding 
#pragma pack(push, 1)
typedef struct _PCRReadCommand 
{
    UINT16 tag;             // TPM_ST_NO_SESSIONS
    UINT32 commandSize;     // Total size of this packet
    UINT32 commandCode;     // TPM_CC_PCR_Read
    // pcrSelectionIn parameter structure
    UINT32 count;           // Number of selection structures (always 1 here)
    UINT16 hashAlg;         // TPM_ALG_SHA256
    BYTE   sizeofSelect;    // Size of the PCR bitmap array in bytes (3 bytes covers 24 PCRs)
    BYTE   pcrSelect[3];    // Bitmask identifying which PCR to read
} PCRReadCommand;
#pragma pack(pop)
