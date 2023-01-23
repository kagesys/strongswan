/*
 * Copyright (C) 2011 Duncan Salerno
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "eap_sim_pcsc_card.h"

#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>
#include <daemon.h>

typedef struct private_eap_sim_pcsc_card_t private_eap_sim_pcsc_card_t;
typedef enum { SCARD_GSM_SIM, SCARD_UMTS_USIM } sim_types_t;


int SelectFile(SCARDHANDLE hCard, 
                const SCARD_IO_REQUEST *pioSendPci, 
                SCARD_IO_REQUEST *pioRecvPci,
                unsigned short file_id,
                unsigned char *buf, size_t *buf_len,
                sim_types_t sim_type, unsigned char *aid,
                size_t aidlen);

int ReadFile(SCARDHANDLE hCard, 
                const SCARD_IO_REQUEST *pioSendPci, 
                SCARD_IO_REQUEST *pioRecvPci,
                sim_types_t sim_type, BYTE file_size,
                BYTE *data, DWORD *len);

int GetImsi(SCARDHANDLE hCard, 
                const SCARD_IO_REQUEST *pioSendPci, 
                SCARD_IO_REQUEST *pioRecvPci, 
                sim_types_t sim_type,
                BYTE *imsi, DWORD *len,
                unsigned char *aid, size_t aidlen);

int ParseFspTempl(unsigned char *buf, size_t buf_len,
                int *ps_do, BYTE *file_len);
                
int GetAid(SCARDHANDLE hCard, 
                const SCARD_IO_REQUEST *pioSendPci, 
                SCARD_IO_REQUEST *pioRecvPci, unsigned char *aid, size_t maxlen);

int GetRecordLen(SCARDHANDLE hCard, 
                const SCARD_IO_REQUEST *pioSendPci, 
                SCARD_IO_REQUEST *pioRecvPci, 
                unsigned char recnum, unsigned char mode);           

int ReadRecord(SCARDHANDLE hCard, 
                const SCARD_IO_REQUEST *pioSendPci, 
                SCARD_IO_REQUEST *pioRecvPci,
                unsigned char *data, size_t len,
                unsigned char recnum, unsigned char mode);

/**
 * Private data of an eap_sim_pcsc_card_t object.
 */
struct private_eap_sim_pcsc_card_t {

	/**
	 * Public eap_sim_pcsc_card_t interface.
	 */
	eap_sim_pcsc_card_t public;
};

/**
 * Maximum length for an IMSI.
 */
#define SIM_IMSI_MAX_LEN 15

/**
 * Length of the status at the end of response APDUs.
 */
#define APDU_STATUS_LEN 2

/**
 * First byte of status word indicating success.
 */
#define APDU_SW1_SUCCESS 0x90

/**
 * First byte of status word indicating there is response data to be read.
 */
#define APDU_SW1_RESPONSE_DATA 0x9f

/**
 *  UMTS defines
 */
#define AKA_RAND_LEN 16
#define AKA_AUTN_LEN 16
#define AKA_AUTS_LEN 14
#define RES_MAX_LEN 16
#define IK_LEN 16
#define CK_LEN 16

#define SCARD_FILE_MF                  0x3F00
#define SCARD_FILE_GSM_DF              0x7F20
#define SCARD_FILE_UMTS_DF             0x7F50
#define SCARD_FILE_GSM_EF_IMSI         0x6F07
#define SCARD_FILE_EF_DIR              0x2F00
#define SCARD_FILE_EF_ICCID            0x2FE2
#define SCARD_FILE_EF_CK               0x6FE1
#define SCARD_FILE_EF_IK               0x6FE2

/* GSM SIM commands */
#define SIM_CMD_SELECT                 0xa0, 0xa4, 0x00, 0x00, 0x02
#define SIM_CMD_RUN_GSM_ALG            0xa0, 0x88, 0x00, 0x00, 0x10
#define SIM_CMD_GET_RESPONSE           0xa0, 0xc0, 0x00, 0x00
#define SIM_CMD_READ_BIN               0xa0, 0xb0, 0x00, 0x00
#define SIM_CMD_READ_RECORD            0xa0, 0xb2, 0x00, 0x00
#define SIM_CMD_VERIFY_CHV1            0xa0, 0x20, 0x00, 0x01, 0x08

/* USIM commands */
#define USIM_CLA                        0x00
#define USIM_CMD_READ_BIN               0x00, 0xb0, 0x00, 0x00
#define USIM_CMD_RUN_UMTS_ALG           0x00, 0x88, 0x00, 0x81, 0x22
#define USIM_CMD_GET_RESPONSE           0x00, 0xc0, 0x00, 0x00

#define SIM_RECORD_MODE_ABSOLUTE 0x04

#define USIM_FSP_TEMPL_TAG              0x62

#define USIM_TLV_FILE_DESC              0x82
#define USIM_TLV_FILE_ID                0x83
#define USIM_TLV_DF_NAME                0x84
#define USIM_TLV_PROPR_INFO             0xA5
#define USIM_TLV_LIFE_CYCLE_STATUS      0x8A
#define USIM_TLV_FILE_SIZE              0x80
#define USIM_TLV_TOTAL_FILE_SIZE        0x81
#define USIM_TLV_PIN_STATUS_TEMPLATE    0xC6
#define USIM_TLV_SHORT_FILE_ID          0x88

#define USIM_PS_DO_TAG                  0x90


/**
 * Decode IMSI EF (Elementary File) into an ASCII string
 */
static bool decode_imsi_ef(unsigned char *input, int input_len, char *output)
{
	/* Only digits 0-9 valid in IMSIs */
	static const char bcd_num_digits[] = {
		'0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', '\0', '\0', '\0', '\0', '\0', '\0'
	};
	int i;

	/* Check length byte matches how many bytes we have, and that input
	 * is correct length for an IMSI */
	if (input[0] != input_len-1 || input_len < 2 || input_len > 9)
	{
		return FALSE;
	}

	/* Check type byte is IMSI (bottom 3 bits == 001) */
	if ((input[1] & 0x07) != 0x01)
	{
		return FALSE;
	}
	*output++ = bcd_num_digits[input[1] >> 4];

	for (i = 2; i < input_len; i++)
	{
		*output++ = bcd_num_digits[input[i] & 0xf];
		*output++ = bcd_num_digits[input[i] >> 4];
	}

	*output++ = '\0';
	return TRUE;
}

METHOD(simaka_card_t, get_identity, bool,
	private_eap_sim_pcsc_card_t *this, identification_t *id)
{
        DBG1(DBG_CFG, "**AlanE** get_dentity() ");
	return NULL;
}
METHOD(simaka_card_t, get_triplet, bool,
	private_eap_sim_pcsc_card_t *this, identification_t *id,
	char rand[SIM_RAND_LEN], char sres[SIM_SRES_LEN], char kc[SIM_KC_LEN])
{
	status_t found = FALSE;
	LONG rv;
	SCARDCONTEXT hContext;
	DWORD dwReaders;
	LPSTR mszReaders;
	char *cur_reader;
	char full_nai[128];
	SCARDHANDLE hCard;
	enum { DISCONNECTED, CONNECTED, TRANSACTION } hCard_status = DISCONNECTED;

	snprintf(full_nai, sizeof(full_nai), "%Y", id);

	DBG2(DBG_IKE, "looking for triplet: %Y rand %b", id, rand, SIM_RAND_LEN);

	rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
	if (rv != SCARD_S_SUCCESS)
	{
		DBG1(DBG_IKE, "SCardEstablishContext: %s", pcsc_stringify_error(rv));
		return FALSE;
	}

	rv = SCardListReaders(hContext, NULL, NULL, &dwReaders);
	if (rv != SCARD_S_SUCCESS)
	{
		DBG1(DBG_IKE, "SCardListReaders: %s", pcsc_stringify_error(rv));
		return FALSE;
	}
	mszReaders = malloc(sizeof(char)*dwReaders);

	rv = SCardListReaders(hContext, NULL, mszReaders, &dwReaders);
	if (rv != SCARD_S_SUCCESS)
	{
		DBG1(DBG_IKE, "SCardListReaders: %s", pcsc_stringify_error(rv));
		free(mszReaders);
		return FALSE;
	}

	/* mszReaders is a multi-string of readers, separated by '\0' and
	 * terminated by an additional '\0' */
	for (cur_reader = mszReaders; *cur_reader != '\0' && found == FALSE;
		 cur_reader += strlen(cur_reader) + 1)
	{
		DWORD dwActiveProtocol = -1;
		const SCARD_IO_REQUEST *pioSendPci;
		SCARD_IO_REQUEST *pioRecvPci = NULL;
		BYTE pbRecvBuffer[64];
		DWORD dwRecvLength;
		char imsi[SIM_IMSI_MAX_LEN + 1];

		/* See GSM 11.11 for SIM APDUs */
		static const BYTE pbSelectMF[] = { 0xa0, 0xa4, 0x00, 0x00, 0x02, 0x3f, 0x00 };
		static const BYTE pbSelectDFGSM[] = { 0xa0, 0xa4, 0x00, 0x00, 0x02, 0x7f, 0x20 };
		static const BYTE pbSelectIMSI[] = { 0xa0, 0xa4, 0x00, 0x00, 0x02, 0x6f, 0x07 };
		static const BYTE pbReadBinary[] = { 0xa0, 0xb0, 0x00, 0x00, 0x09 };
		BYTE pbRunGSMAlgorithm[5 + SIM_RAND_LEN] = { 0xa0, 0x88, 0x00, 0x00, 0x10 };
		static const BYTE pbGetResponse[] = { 0xa0, 0xc0, 0x00, 0x00, 0x0c };

		/* If on 2nd or later reader, make sure we end the transaction
		 * and disconnect card in the previous reader */
		switch (hCard_status)
		{
			case TRANSACTION:
				SCardEndTransaction(hCard, SCARD_LEAVE_CARD);
				/* FALLTHRU */
			case CONNECTED:
				SCardDisconnect(hCard, SCARD_LEAVE_CARD);
				/* FALLTHRU */
			case DISCONNECTED:
				hCard_status = DISCONNECTED;
		}

		/* Copy RAND into APDU */
		memcpy(pbRunGSMAlgorithm + 5, rand, SIM_RAND_LEN);

		rv = SCardConnect(hContext, cur_reader, SCARD_SHARE_SHARED,
			SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard, &dwActiveProtocol);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardConnect: %s", pcsc_stringify_error(rv));
			continue;
		}
		hCard_status = CONNECTED;

		switch(dwActiveProtocol)
		{
			case SCARD_PROTOCOL_T0:
				pioSendPci = SCARD_PCI_T0;
				break;
			case SCARD_PROTOCOL_T1:
				pioSendPci = SCARD_PCI_T1;
				break;
			default:
				DBG1(DBG_IKE, "Unknown SCARD_PROTOCOL");
				continue;
		}

		/* Start transaction */
		rv = SCardBeginTransaction(hCard);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardBeginTransaction: %s", pcsc_stringify_error(rv));
			continue;
		}
		hCard_status = TRANSACTION;

		/* APDU: Select MF */
		dwRecvLength = sizeof(pbRecvBuffer);
		rv = SCardTransmit(hCard, pioSendPci, pbSelectMF, sizeof(pbSelectMF),
						   pioRecvPci, pbRecvBuffer, &dwRecvLength);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardTransmit: %s", pcsc_stringify_error(rv));
			continue;
		}
		if (dwRecvLength < APDU_STATUS_LEN ||
			pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN] != APDU_SW1_RESPONSE_DATA)
		{
			DBG1(DBG_IKE, "Select MF failed: %b", pbRecvBuffer,
				 (u_int)dwRecvLength);
			continue;
		}

		/* APDU: Select DF GSM */
		dwRecvLength = sizeof(pbRecvBuffer);
		rv = SCardTransmit(hCard, pioSendPci, pbSelectDFGSM, sizeof(pbSelectDFGSM),
						   pioRecvPci, pbRecvBuffer, &dwRecvLength);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardTransmit: %s", pcsc_stringify_error(rv));
			continue;
		}
		if (dwRecvLength < APDU_STATUS_LEN ||
			pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN] != APDU_SW1_RESPONSE_DATA)
		{
			DBG1(DBG_IKE, "Select DF GSM failed: %b", pbRecvBuffer,
				 (u_int)dwRecvLength);
			continue;
		}

		/* APDU: Select IMSI */
		dwRecvLength = sizeof(pbRecvBuffer);
		rv = SCardTransmit(hCard, pioSendPci, pbSelectIMSI, sizeof(pbSelectIMSI),
						   pioRecvPci, pbRecvBuffer, &dwRecvLength);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardTransmit: %s", pcsc_stringify_error(rv));
			continue;
		}
		if (dwRecvLength < APDU_STATUS_LEN ||
			pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN] != APDU_SW1_RESPONSE_DATA)
		{
			DBG1(DBG_IKE, "Select IMSI failed: %b", pbRecvBuffer,
				 (u_int)dwRecvLength);
			continue;
		}

		/* APDU: Read Binary (of IMSI) */
		dwRecvLength = sizeof(pbRecvBuffer);
		rv = SCardTransmit(hCard, pioSendPci, pbReadBinary, sizeof(pbReadBinary),
						   pioRecvPci, pbRecvBuffer, &dwRecvLength);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardTransmit: %s", pcsc_stringify_error(rv));
			continue;
		}
		if (dwRecvLength < APDU_STATUS_LEN ||
			pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN] != APDU_SW1_SUCCESS)
		{
			DBG1(DBG_IKE, "Select IMSI failed: %b", pbRecvBuffer,
				 (u_int)dwRecvLength);
			continue;
		}

		if (!decode_imsi_ef(pbRecvBuffer, dwRecvLength-APDU_STATUS_LEN, imsi))
		{
			DBG1(DBG_IKE, "Couldn't decode IMSI EF: %b",
				 pbRecvBuffer, (u_int)dwRecvLength);
			continue;
		}

		/* The IMSI could be post/prefixed in the full NAI, so just make sure
		 * it's in there */
		if (!(strlen(full_nai) && strstr(full_nai, imsi)))
		{
			DBG1(DBG_IKE, "Not the SIM we're looking for, IMSI: %s", imsi);
			continue;
		}

		/* APDU: Run GSM Algorithm */
		dwRecvLength = sizeof(pbRecvBuffer);
		rv = SCardTransmit(hCard, pioSendPci,
						   pbRunGSMAlgorithm, sizeof(pbRunGSMAlgorithm),
						   pioRecvPci, pbRecvBuffer, &dwRecvLength);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardTransmit: %s", pcsc_stringify_error(rv));
			continue;
		}
		if (dwRecvLength < APDU_STATUS_LEN ||
			pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN] != APDU_SW1_RESPONSE_DATA)
		{
			DBG1(DBG_IKE, "Run GSM Algorithm failed: %b",
				 pbRecvBuffer, (u_int)dwRecvLength);
			continue;
		}

		/* APDU: Get Response (of Run GSM Algorithm) */
		dwRecvLength = sizeof(pbRecvBuffer);
		rv = SCardTransmit(hCard, pioSendPci, pbGetResponse, sizeof(pbGetResponse),
						   pioRecvPci, pbRecvBuffer, &dwRecvLength);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardTransmit: %s", pcsc_stringify_error(rv));
			continue;
		}

		if (dwRecvLength < APDU_STATUS_LEN ||
			pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN] != APDU_SW1_SUCCESS)
		{
			DBG1(DBG_IKE, "Get Response failed: %b", pbRecvBuffer,
				 (u_int)dwRecvLength);
			continue;
		}

		/* Extract out Kc and SRES from response */
		if (dwRecvLength == SIM_SRES_LEN + SIM_KC_LEN + APDU_STATUS_LEN)
		{
			memcpy(sres, pbRecvBuffer, SIM_SRES_LEN);
			memcpy(kc, pbRecvBuffer+4, SIM_KC_LEN);
			/* This will also cause the loop to exit */
			found = TRUE;
		}
		else
		{
			DBG1(DBG_IKE, "Get Response incorrect length: %b",
				 pbRecvBuffer, (u_int)dwRecvLength);
			continue;
		}

		/* Transaction will be ended and card disconnected at the
		 * beginning of this loop or after this loop */
	}

	/* Make sure we end any previous transaction and disconnect card */
	switch (hCard_status)
	{
		case TRANSACTION:
			SCardEndTransaction(hCard, SCARD_LEAVE_CARD);
			/* FALLTHRU */
		case CONNECTED:
			SCardDisconnect(hCard, SCARD_LEAVE_CARD);
			/* FALLTHRU */
		case DISCONNECTED:
			hCard_status = DISCONNECTED;
	}

	rv = SCardReleaseContext(hContext);
	if (rv != SCARD_S_SUCCESS)
	{
		DBG1(DBG_IKE, "SCardReleaseContext: %s", pcsc_stringify_error(rv));
	}

	free(mszReaders);
	return found;
}

/*
METHOD(simaka_card_t, get_quintuplet, status_t,
	private_eap_sim_pcsc_card_t *this, identification_t *id,
	char rand[AKA_RAND_LEN], char autn[AKA_AUTN_LEN], char ck[AKA_CK_LEN],
	char ik[AKA_IK_LEN], char res[AKA_RES_MAX], int *res_len)
{
	return NOT_SUPPORTED;
}
*/



/**
  * scard_umts_auth - Run UMTS authentication command on USIM card
  * @hCard: Pointer to private data from scard_init()
  * @_rand: 16-byte RAND value from HLR/AuC
  * @autn: 16-byte AUTN value from HLR/AuC
  * @res: 16-byte buffer for RES
  * @res_len: Variable that will be set to RES length
  * @ik: 16-byte buffer for IK
  * @ck: 16-byte buffer for CK
  * @auts: 14-byte buffer for AUTS
  * Returns: 0 on success, -1 on failure, or -2 if USIM reports synchronization
  * failure
  *
  * This function performs AKA authentication using USIM card and the provided
  * RAND and AUTN values from HLR/AuC. If authentication command can be
  * completed successfully, RES, IK, and CK values will be written into provided
  * buffers and res_len is set to length of received RES value. If USIM reports
  * synchronization failure, the received AUTS value will be written into auts
  * buffer. In this case, RES, IK, and CK are not valid.
  */
METHOD(simaka_card_t, get_quintuplet, status_t,
                private_eap_sim_pcsc_card_t *this, identification_t *id,
                char rand[AKA_RAND_LEN], char autn[AKA_AUTN_LEN], char ck[AKA_CK_LEN],
                char ik[AKA_IK_LEN], char res[AKA_RES_MAX], int *res_len)

//int Scard::UmtsAuth(scard_data_t *scard, const unsigned char *_rand,
//             const unsigned char *autn,
//             unsigned char *res, size_t *res_len,
//             unsigned char *ik, unsigned char *ck, unsigned char *auts)
{
    status_t found = FALSE;
    LONG rv;
    SCARDCONTEXT hContext;
    DWORD dwReaders;
    LPSTR mszReaders;
    char *cur_reader;
    char full_nai[128];
    SCARDHANDLE hCard;
    enum { DISCONNECTED, CONNECTED, TRANSACTION } hCard_status = DISCONNECTED;
    sim_types_t sim_type;

    snprintf(full_nai, sizeof(full_nai), "%Y", id);

    DBG2(DBG_IKE, "looking for quintuplet: %Y rand %b", id, rand, AKA_RAND_LEN);

    rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
    if (rv != SCARD_S_SUCCESS)
    {
        DBG1(DBG_IKE, "SCardEstablishContext: %s", pcsc_stringify_error(rv));
        return FALSE;
    }

    rv = SCardListReaders(hContext, NULL, NULL, &dwReaders);
    if (rv != SCARD_S_SUCCESS)
    {
        DBG1(DBG_IKE, "SCardListReaders: %s", pcsc_stringify_error(rv));
        return FALSE;
    }
    mszReaders = malloc(sizeof(char)*dwReaders);

    rv = SCardListReaders(hContext, NULL, mszReaders, &dwReaders);
    if (rv != SCARD_S_SUCCESS)
    {
        DBG1(DBG_IKE, "SCardListReaders: %s", pcsc_stringify_error(rv));
        return FALSE;
    }

    /* mszReaders is a multi-string of readers, separated by '\0' and
     * terminated by an additional '\0' */
    for (cur_reader = mszReaders; *cur_reader != '\0' && found == FALSE;
         cur_reader += strlen(cur_reader) + 1)
    {
        DWORD dwActiveProtocol = -1;
        const SCARD_IO_REQUEST *pioSendPci;
        SCARD_IO_REQUEST *pioRecvPci = NULL;
        BYTE pbRecvBuffer[64];
        DWORD dwRecvLength = sizeof(pbRecvBuffer);
        char imsi[SIM_IMSI_MAX_LEN + 1];

        /* See GSM 11.11 for (U)SIM APDUs */
        BYTE pbRunUmtsAlgorithm[5 + 1 + AKA_RAND_LEN + 1 + AKA_AUTN_LEN] = {USIM_CMD_RUN_UMTS_ALG};

        BYTE pbGetResponse[5] = { USIM_CMD_GET_RESPONSE };

        /* If on 2nd or later reader, make sure we end the transaction
         * and disconnect card in the previous reader */
        switch (hCard_status)
        {
            case TRANSACTION:
                SCardEndTransaction(hCard, SCARD_LEAVE_CARD);
                /* FALLTHRU */
            case CONNECTED:
                SCardDisconnect(hCard, SCARD_LEAVE_CARD);
                /* FALLTHRU */
            case DISCONNECTED:
                hCard_status = DISCONNECTED;
        }

        /* Copy RAND/AUTN into pbRunUmtsAlgorithm APDU */
        pbRunUmtsAlgorithm[5] = AKA_RAND_LEN;
        memcpy(pbRunUmtsAlgorithm + 6, rand, AKA_RAND_LEN);
        pbRunUmtsAlgorithm[6 + AKA_RAND_LEN] = AKA_AUTN_LEN;
        memcpy(pbRunUmtsAlgorithm + 6 + AKA_RAND_LEN + 1, autn, AKA_AUTN_LEN);

        rv = SCardConnect(hContext, cur_reader, SCARD_SHARE_SHARED,
            SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard, &dwActiveProtocol);
        if (rv != SCARD_S_SUCCESS)
        {
            DBG1(DBG_IKE, "SCardConnect: %s", pcsc_stringify_error(rv));
            continue;
        }
        hCard_status = CONNECTED;

        switch(dwActiveProtocol)
        {
            case SCARD_PROTOCOL_T0:
                pioSendPci = SCARD_PCI_T0;
                break;
            case SCARD_PROTOCOL_T1:
                pioSendPci = SCARD_PCI_T1;
                break;
            default:
                DBG1(DBG_IKE, "Unknown SCARD_PROTOCOL");
                continue;
        }

        /* Start transaction */
        rv = SCardBeginTransaction(hCard);
        if (rv != SCARD_S_SUCCESS)
        {
            DBG1(DBG_IKE, "SCardBeginTransaction: %s", pcsc_stringify_error(rv));
            continue;
        }
        hCard_status = TRANSACTION;
        
        /* Determin SIM/USIM Card type */
        sim_type = SCARD_UMTS_USIM;
        DBG1(DBG_IKE, "Scard: verifying USIM support\n");

        /* Select UMTS AID from EF_DIR records */
        unsigned char aid[32];
        size_t aid_len;

        aid_len = GetAid(hCard, pioSendPci, pioRecvPci, aid, sizeof(aid));
        if (aid_len < 0) 
        {
            DBG1(DBG_IKE, "SCARD: Failed to find AID for 3G USIM app");
            continue;
        }
        
        /* Select IMSI EF */
        if (GetImsi(hCard, pioSendPci, pioRecvPci, sim_type, pbRecvBuffer, &dwRecvLength, aid, aid_len) < 0)
        {
            DBG1(DBG_IKE, "Scard GetImsi Failed");
            continue;
        }
        if (!decode_imsi_ef(pbRecvBuffer, dwRecvLength-APDU_STATUS_LEN, imsi))
        {
            DBG1(DBG_IKE, "Couldn't decode IMSI EF: %b",
                 pbRecvBuffer, (u_int)dwRecvLength);
            continue;
        }

        /* The IMSI could be post/prefixed in the full NAI, so just make sure
         * it's in there */
        if (!(strlen(full_nai) && strstr(full_nai, imsi)))
        {
            DBG1(DBG_IKE, "Not the SIM we're looking for, IMSI: %s", imsi);
            continue;
        }
        DBG3(DBG_IKE, "Found the SIM we're looking for, IMSI: %s", imsi);

        /* APDU: Run UMTS Algorithm */
        dwRecvLength = sizeof(pbRecvBuffer);
        rv = SCardTransmit(hCard, pioSendPci,
                           pbRunUmtsAlgorithm, sizeof(pbRunUmtsAlgorithm),
                           pioRecvPci, pbRecvBuffer, &dwRecvLength);
        if (rv != SCARD_S_SUCCESS)
        {
            DBG1(DBG_IKE, "SCardTransmit: %s", pcsc_stringify_error(rv));
            continue;
        }
 
        DBG3(DBG_IKE, "RunUmtsAlg returned: %b", pbRecvBuffer, dwRecvLength);

        if (dwRecvLength == 2 && pbRecvBuffer[0] == 0x98 && pbRecvBuffer[1] == 0x62) {
            DBG1(DBG_IKE, "Scard: UMTS auth failed - MAC != XMAC\n");
            continue;
        } else if (dwRecvLength == 2 && pbRecvBuffer[0] == 0x90 && pbRecvBuffer[1] == 0x00) {
            DBG3(DBG_IKE, "?RunUmtsAlg returned: 0x9000 assume length is 0x35");
            pbRecvBuffer[1] = 0x35;
        } else if (dwRecvLength != 2 || pbRecvBuffer[0] != 0x61) {
            DBG1(DBG_IKE, "Scard: unexpected response for UMTS auth request (dwRecvLength=%d pbRecvBuffer=%02x %02x)",
                   dwRecvLength, pbRecvBuffer[0], pbRecvBuffer[1]);
            continue;
        }
        
        /* Expected response length */
        pbGetResponse[4] = pbRecvBuffer[1];

        /* APDU: Get Response (of Run Umts Algorithm) */
        dwRecvLength = sizeof(pbRecvBuffer);
        rv = SCardTransmit(hCard, pioSendPci, pbGetResponse, sizeof(pbGetResponse),
                           pioRecvPci, pbRecvBuffer, &dwRecvLength);
        if (rv != SCARD_S_SUCCESS)
        {
            DBG1(DBG_IKE, "Scard: UMTS auth failed to get response");
            continue;
        }
        if (dwRecvLength < APDU_STATUS_LEN ||
            pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN] != APDU_SW1_SUCCESS)
        {
            DBG1(DBG_IKE, "Get Response failed: %b", pbRecvBuffer,
                 (u_int)dwRecvLength);
            continue;
        }
        if (dwRecvLength >= 2 + AKA_AUTS_LEN && pbRecvBuffer[0] == 0xdc &&
            pbRecvBuffer[1] == AKA_AUTS_LEN) {
                DBG1(DBG_IKE, "Scard: UMTS Synchronization-Failure");
//                memcpy(auts, pbRecvBuffer + 2, AKA_AUTS_LEN);
                continue;
        } 
        else if (dwRecvLength >= 6 + IK_LEN + CK_LEN && pbRecvBuffer[0] == 0xdb) 
        {
            DBG3(DBG_IKE, "Scard: UMTS auth success");
            BYTE *pos, *end;
            pos = pbRecvBuffer + 1;
            end = pbRecvBuffer + dwRecvLength;
        
            /* RES */
            if (pos[0] > RES_MAX_LEN || pos + pos[0] > end) {
                DBG2(DBG_IKE, "Scard: Invalid RES\n");
                continue;
            }
            *res_len = *pos++;
            memcpy(res, pos, *res_len);
            pos += *res_len;
        
            /* CK */
            if (pos[0] != CK_LEN || pos + CK_LEN > end) {
                DBG2(DBG_IKE, "Scard: Invalid CK\n");
                continue;
            }
            pos++;
            memcpy(ck, pos, CK_LEN);
            pos += CK_LEN;
        
            /* IK */
            if (pos[0] != IK_LEN || pos + IK_LEN > end) {
                DBG2(DBG_IKE, "Scard: Invalid IK\n");
                return -1;
            }
            pos++;
            memcpy(ik, pos, IK_LEN);
            pos += IK_LEN;
        
            /* This will also cause the loop to exit */
            found = SUCCESS;
        }
        else
        {
            DBG1(DBG_IKE, "Scard: UMTS auth problem with get response dwRecvLength:%d pbRecvBuffer[0]", dwRecvLength, pbRecvBuffer[0]);   
        }
    }
    /* Make sure we end any previous transaction and disconnect card */
    switch (hCard_status)
    {
        case TRANSACTION:
            SCardEndTransaction(hCard, SCARD_LEAVE_CARD);
            /* FALLTHRU */
        case CONNECTED:
            SCardDisconnect(hCard, SCARD_LEAVE_CARD);
            /* FALLTHRU */
        case DISCONNECTED:
            hCard_status = DISCONNECTED;
    }

    rv = SCardReleaseContext(hContext);
    if (rv != SCARD_S_SUCCESS)
    {
        DBG1(DBG_IKE, "SCardReleaseContext: %s", pcsc_stringify_error(rv));
    }

    free(mszReaders);
    return found;
}



METHOD(eap_sim_pcsc_card_t, destroy, void,
	private_eap_sim_pcsc_card_t *this)
{
	free(this);
}

/**
 * See header
 */
eap_sim_pcsc_card_t *eap_sim_pcsc_card_create()
{
	private_eap_sim_pcsc_card_t *this;

	INIT(this,
		.public = {
			.card = {
				.get_identity = _get_identity,
				.get_triplet = _get_triplet,
				.get_quintuplet = _get_quintuplet,
				.resync = (void*)return_false,
				.get_pseudonym = (void*)return_null,
				.set_pseudonym = (void*)nop,
				.get_reauth = (void*)return_null,
				.set_reauth = (void*)nop,
			},
			.destroy = _destroy,
		},
	);

	DBG1(DBG_CFG, "**AlanE** eap_sim_pcsc_card_create");
	return &this->public;
}


int SelectFile(SCARDHANDLE hCard, 
                const SCARD_IO_REQUEST *pioSendPci, 
                SCARD_IO_REQUEST *pioRecvPci,
                unsigned short file_id,
                unsigned char *buf, size_t *buf_len,
                sim_types_t sim_type, unsigned char *aid,
                size_t aidlen)
     {
        long ret;
        unsigned char resp[100];
        unsigned char aid_cmd[50] = { SIM_CMD_SELECT };
        unsigned char cmd[50] = { SIM_CMD_SELECT };
        int cmdlen, aid_cmdlen;
        unsigned char get_resp[5] = { SIM_CMD_GET_RESPONSE };
        DWORD len, rlen;
    
        if (sim_type == SCARD_UMTS_USIM) 
        {
             cmd[0] = USIM_CLA;
             cmd[3] = 0x04;
             aid_cmd[0] = USIM_CLA;
             aid_cmd[3] = 0x04;
             get_resp[0] = USIM_CLA;
        }
        
        DBG3(DBG_IKE, "Scard: SelectFile %04x\n", file_id);
        if (aid) 
        {
            if (5 + aidlen > sizeof(aid_cmd))
                return -1;
            aid_cmd[2] = 0x04; /* Select by AID */
            aid_cmd[4] = aidlen; /* len */
            memcpy(aid_cmd + 5, aid, aidlen);
            aid_cmdlen = 5 + aidlen;
            ret = SCardTransmit(hCard, pioSendPci, aid_cmd, aid_cmdlen, pioRecvPci, resp, &len);
//AlanE: quick hack
            get_resp[4] = resp[1];
            ret = SCardTransmit(hCard, pioSendPci, get_resp, sizeof(get_resp), pioRecvPci, buf, &rlen);
        } 
        cmd[5] = file_id >> 8;
        cmd[6] = file_id & 0xff;
        cmdlen = 7;
        len = sizeof(resp);

        ret = SCardTransmit(hCard, pioSendPci, cmd, cmdlen, pioRecvPci, resp, &len);
        if (ret != SCARD_S_SUCCESS) 
        {
            DBG1(DBG_IKE, "Scard: SCardTransmit failed (err=0x%lx)", ret);
            return -1;
        }
	if (len > 2 && resp[len-2] == 0x90 && resp[len-1] == 0x00) 
	{
            DBG1(DBG_IKE, "Scard: looks like Select returned the file\n");
            memcpy(buf, &resp, len);		
            *buf_len = len;
            return 0;
 	}
        if (len != 2) 
        {
            DBG1(DBG_IKE, "Scard: unexpected resp len %d (expected 2)\n", (int) len);
            return -1;
        }
        if (resp[0] == 0x98 && resp[1] == 0x04) 
        {
            /* Security status not satisfied (PIN_WLAN) */
           DBG1(DBG_IKE, "Scard: Security status not satisfied (PIN_WLAN)\n");
           return -1;
        }
        if (resp[0] == 0x6e) 
        {
           DBG1(DBG_IKE, "Scard: used CLA not supported");
           return -1;
        }
        if (resp[0] != 0x6c && resp[0] != 0x9f && resp[0] != 0x61) 
        {
            DBG3(DBG_IKE, "Scard: unexpected response 0x%02x (expected 0x61, 0x6c, or 0x9f)", resp[0]);
            return -1;
        }
        switch (resp[0])
        {
            /*
            * Procedure bytes '61xx' instruct the transport layer of the terminal 
            * to issue a GET RESPONSE command to the UICC.
            * P3 of the GET RESPONSE command header is set to 'xx'.
            */
            case 0x61:
                /* Normal ending of command; resp[1] bytes available */
                get_resp[4] = resp[1];
                DBG3(DBG_IKE, "Scard: trying to get response (%d bytes)\n", resp[1]);
            
                rlen = *buf_len;
                ret = SCardTransmit(hCard, pioSendPci, get_resp, sizeof(get_resp), pioRecvPci, buf, &rlen);
                if (ret == SCARD_S_SUCCESS) 
                {
                    DBG3(DBG_IKE, "Scard SelectFile: %04x\n buf: %b", file_id, buf, rlen);
                    *buf_len = resp[1] < rlen ? resp[1] : rlen;
                    return 0;
                }
                DBG3(DBG_IKE, "Scard: SCardTransmit err=0x%lx", ret);
                return -1;
                break;
            /*
            * Procedure bytes '6Cxx' instruct the transport layer of the terminal 
            * to immediately resend the previous command header
            * setting P3 = 'xx'.
            */
            case 0x6c:
                    cmd[4] = resp[1];
                    DBG3(DBG_IKE, "Scard: trying to get response (%d bytes)\n", resp[1]);
                    ret = SCardTransmit(hCard, pioSendPci, cmd, cmdlen, pioRecvPci, resp, &len);
                    if (ret == SCARD_S_SUCCESS)
                    {
                        DBG3(DBG_IKE, "Scard SelectFile: %04x\n buf: %b", file_id, buf, rlen);
                        *buf_len = resp[1] < rlen ? resp[1] : rlen;
                        return 0;
                    }
                    DBG3(DBG_IKE, "Scard: SCardTransmit err=0x%lx", ret);
                    return -1;
                    break;
        }
        return -1;
}

int ReadFile(SCARDHANDLE hCard, 
             const SCARD_IO_REQUEST *pioSendPci, 
             SCARD_IO_REQUEST *pioRecvPci,
             sim_types_t sim_type, BYTE file_size,
             BYTE *data, DWORD *len)
{
    BYTE cmd[5] = { SIM_CMD_READ_BIN /* , len */ };
    BYTE get_resp[5] = { SIM_CMD_GET_RESPONSE };
    DWORD rlen;

    long ret;

    cmd[4] = file_size;
    if (sim_type == SCARD_UMTS_USIM)
    {
        cmd[0] = USIM_CLA;
        get_resp[0] = USIM_CLA;
    }
    ret = SCardTransmit(hCard, pioSendPci, cmd, sizeof(cmd), pioRecvPci, data, len);
    if (ret != SCARD_S_SUCCESS) {
        return -1;
    }
    DBG3(DBG_IKE, "Scard ReadFile returned: %b", data, *len);
    if (*len < 2) 
    {
        DBG1(DBG_IKE, "Scard ReadFile returned invalid data len %d", *len);
        return  -1;
    }
    switch (data[*len - 2])
    {
        case 0x90:
            if (data[*len - 1 ] != 0x00) {
                DBG3(DBG_IKE, "Scard: file read returned unexpected status SW1:%02x SW2:%02x (expected 0x90 0x00)",
                       data[*len - 2], data[*len - 1]);
                return -1;
            }
            return 0;
            break;    
        /*
        * Procedure bytes '61xx' instruct the transport layer of the terminal 
        * to issue a GET RESPONSE command to the UICC.
        * P3 of the GET RESPONSE command header is set to 'xx'.
        */
        case 0x61:
           /* Normal ending of command; resp[1] bytes available */
            get_resp[4] = data[*len - 1];
            DBG3(DBG_IKE, "Scard: trying to get response (%d bytes)\n", data[*len - 1]);
        
            rlen = data[*len - 1] + 2;
            ret = SCardTransmit(hCard, pioSendPci, get_resp, sizeof(get_resp), pioRecvPci, data, &rlen);
            if (ret == SCARD_S_SUCCESS) 
            {
                DBG3(DBG_IKE, "Scard ReadFile GET_RESPONSE returned: %b", data, rlen);
                *len =  rlen;
                return 0;
            }
            DBG3(DBG_IKE, "Scard: SCardTransmit err=0x%lx", ret);
            return -1;
            break;
        /*
        * Procedure bytes '6Cxx' instruct the transport layer of the terminal 
        * to immediately resend the previous command header
        * setting P3 = 'xx'.
        */
        case 0x6c:
                cmd[4] = data[*len - 1];
                rlen = data[*len - 1] + 2;
                DBG3(DBG_IKE, "Scard: Repeating ReadFile with len %d", cmd[4]);
                ret = SCardTransmit(hCard, pioSendPci, cmd, sizeof(cmd), pioRecvPci, data, &rlen);
                if (ret == SCARD_S_SUCCESS)
                {
                    DBG3(DBG_IKE, "Scard Re-ReadFile returned: %b", data, rlen);
                    *len =  rlen;
                    return 0;
                }
                DBG3(DBG_IKE, "Scard: SCardTransmit err=0x%lx", ret);
                return -1;
                break;        
    }
    return 0;
}

int GetImsi(SCARDHANDLE hCard, 
        const SCARD_IO_REQUEST *pioSendPci, 
        SCARD_IO_REQUEST *pioRecvPci,
        sim_types_t sim_type,
        BYTE *imsi, DWORD *len,
        unsigned char *aid, size_t aidlen)
{
    unsigned char buf[100];
    size_t blen;
    BYTE file_size;

    DBG3(DBG_IKE, "Scard: reading IMSI from (GSM) EF-IMSI\n");
    blen = sizeof(buf);
    
    if (SelectFile(hCard, pioSendPci, pioRecvPci, SCARD_FILE_MF, buf, &blen, sim_type, NULL, 0) < 0)
    {
        return -1;
    }
    if (SelectFile(hCard, pioSendPci, pioRecvPci, SCARD_FILE_GSM_EF_IMSI, buf, &blen, sim_type, aid, aidlen))
    {
        return -1;
    }
    if (blen < 4) {
        DBG1(DBG_IKE, "Scard: too short (GSM) EF-IMSI header (len=%d)", blen);
        return -1;
    }
    if (sim_type == SCARD_GSM_SIM) {
        blen = (buf[2] << 8) | buf[3];
    } else {
        if (ParseFspTempl(buf, blen, NULL, &file_size))
            return -1;
    }
    if (file_size < 2 || file_size > *len) {
        DBG3(DBG_IKE, "Scard: invalid IMSI file length=%d\n",
               file_size);
        return -1;
    }
    DBG3(DBG_IKE, "Scard: IMSI file length=%d buffer len=%d\n",
           file_size, len);

    if (ReadFile(hCard, pioSendPci, pioRecvPci, sim_type, file_size, imsi, len) < 0)
    {
        DBG1(DBG_IKE, "Scard: Problem reading IMSI File\n");
        return -1;
    }
    DBG3(DBG_IKE, "Scard: GetImsi : OK %b", imsi, blen);
    return 0;
}


int ParseFspTempl(unsigned char *buf, size_t buf_len,
                 int *ps_do, BYTE *file_len)
{
        unsigned char *pos, *end;

        if (ps_do)
            *ps_do = -1;
        if (file_len)
            *file_len = -1;

        pos = buf;
        end = pos + buf_len;
        if (*pos != USIM_FSP_TEMPL_TAG) {
            DBG3(DBG_IKE, "Scard: file header did not start with FSP template tag\n");
            return -1;
        }
        pos++;
        if (pos >= end)
            return -1;
        if ((pos + pos[0]) < end)
            end = pos + 1 + pos[0];
        pos++;

        while (pos + 1 < end) {
            if (pos + 2 + pos[1] > end)
                break;

            if (pos[0] == USIM_TLV_FILE_SIZE &&
                (pos[1] == 1 || pos[1] == 2) && file_len) {
                if (pos[1] == 1)
                    *file_len = (int) pos[2];
                else
                    *file_len = ((int) pos[2] << 8) |
                        (int) pos[3];
                DBG3(DBG_IKE, "Scard: file_size=%d\n",*file_len);
            }

            if (pos[0] == USIM_TLV_PIN_STATUS_TEMPLATE &&
                pos[1] >= 2 && pos[2] == USIM_PS_DO_TAG &&
                pos[3] >= 1 && ps_do) {
                DBG3(DBG_IKE, "Scard: PS_DO=0x%02x\n", pos[4]);
                *ps_do = (int) pos[4];
            }

            pos += 2 + pos[1];

            if (pos == end)
                return 0;
        }
        return -1;
}


int GetAid(SCARDHANDLE hCard, 
           const SCARD_IO_REQUEST *pioSendPci, 
           SCARD_IO_REQUEST *pioRecvPci, unsigned char *aid, size_t maxlen)
{
   int rlen, rec;
   struct efdir {
        unsigned char appl_template_tag; /* 0x61 */
        unsigned char appl_template_len;
        unsigned char appl_id_tag;       /* 0x4f */
        unsigned char aid_len;
        unsigned char rid[5];
        unsigned char appl_code[2];     /* 0x1002 for 3G USIM */
    } *efdir;
    unsigned char buf[100];
    size_t blen;

    efdir = (struct efdir *) buf;
    blen = sizeof(buf);
    
    if (SelectFile(hCard, pioSendPci, pioRecvPci, SCARD_FILE_MF, buf, &blen, SCARD_UMTS_USIM, NULL, 0) < 0)
    {
        DBG1(DBG_IKE, "SCard: Failed to select MF");
        return -1;
    }

    if (SelectFile(hCard, pioSendPci, pioRecvPci, SCARD_FILE_EF_DIR, buf, &blen, SCARD_UMTS_USIM, NULL, 0))
    {
        DBG1(DBG_IKE, "SCard: Failed to select EF_DIR");
        return -1;
    }
    for (rec = 1; rec < 10; rec++) 
    {
        rlen = GetRecordLen(hCard, pioSendPci, pioRecvPci, rec, SIM_RECORD_MODE_ABSOLUTE);
        if (rlen < 0) 
        {
            DBG1(DBG_IKE, "SCard: Failed to get EF_DIR record length");
            return -1;
        }
        blen = sizeof(buf);
        if (rlen > (int) blen) {
            DBG1(DBG_IKE, "SCard: Too long EF_DIR record");
            return -1;
        }
        if (ReadRecord(hCard, pioSendPci, pioRecvPci, buf, rlen, rec,
                      SIM_RECORD_MODE_ABSOLUTE) < 0) 
        {
            DBG1(DBG_IKE, "SCard: Failed to read EF_DIR record %d", rec);
            return -1;
        }
        if (efdir->appl_template_tag != 0x61) 
        {
            DBG1(DBG_IKE, "SCard: Unexpected application template tag 0x%x",
                   efdir->appl_template_tag);
            continue;
        }
        if (efdir->appl_template_len > rlen - 2) 
        {
            DBG1(DBG_IKE, "SCard: Too long application template (len=%d rlen=%d)\n",
                   efdir->appl_template_len, rlen);
            continue;
        }

        if (efdir->appl_id_tag != 0x4f) 
        {
            DBG1(DBG_IKE, "SCard: Unexpected application identifier tag 0x%x",
               efdir->appl_id_tag);
            continue;
        }

        if (efdir->aid_len < 1 || efdir->aid_len > 16) 
        {
            DBG1(DBG_IKE, "SCard: Invalid AID length %d",
                   efdir->aid_len);
            continue;
        }

        if (efdir->appl_code[0] == 0x10 &&
            efdir->appl_code[1] == 0x02) 
        {
            DBG3(DBG_IKE, "SCard: 3G USIM app found from EF_DIR record %d", rec);
            break;
        }
    }

    if (rec >= 10) 
    {
        DBG1(DBG_IKE, "SCard: 3G USIM app not found from EF_DIR records");
        return -1;
    }

    if (efdir->aid_len > maxlen) 
    {
        DBG1(DBG_IKE, "SCard: Too long AID");
        return -1;
    }

    memcpy(aid, efdir->rid, efdir->aid_len);
    return efdir->aid_len;
}



int GetRecordLen(SCARDHANDLE hCard, 
                 const SCARD_IO_REQUEST *pioSendPci, 
                 SCARD_IO_REQUEST *pioRecvPci, 
                 unsigned char recnum, unsigned char mode)
{
    unsigned char buf[255];
    unsigned char cmd[5] = { SIM_CMD_READ_RECORD /* , len */ };
    DWORD blen;
    long ret;
 
    cmd[0] = USIM_CLA;
    cmd[2] = recnum;
    cmd[3] = mode;
    cmd[4] = 0x00; 

     blen = sizeof(buf);
     ret = SCardTransmit(hCard, pioSendPci, cmd, sizeof(cmd), pioRecvPci, buf, &blen);
     if (ret != SCARD_S_SUCCESS) 
     {
         DBG3(DBG_IKE, "SCARD: failed to determine file length for record %d", recnum);
         return -1;
     }
     if (blen > 2 && buf[blen-1] == 0x00 && buf[blen-2] == 0x90)
         return (blen - 2);
     if (blen < 2 || buf[0] != 0x6c) 
     {
         DBG3(DBG_IKE, "SCARD: unexpected response to file length determination");
         return -1;
     }
     return buf[1];
}


int ReadRecord(SCARDHANDLE hCard, 
                const SCARD_IO_REQUEST *pioSendPci, 
                SCARD_IO_REQUEST *pioRecvPci,
                unsigned char *data, size_t len,
                unsigned char recnum, unsigned char mode)
 {
    unsigned char cmd[5] = { SIM_CMD_READ_RECORD /* , len */ };
    DWORD blen = len + 3;
    unsigned char *buf;
    long ret;

    cmd[0] = USIM_CLA;
    cmd[2] = recnum;
    cmd[3] = mode;
    cmd[4] = len;

    buf = (unsigned char *)malloc(blen);
    if (buf == NULL)
    {
        return -1;
    }
    ret = SCardTransmit(hCard, pioSendPci, cmd, sizeof(cmd), pioRecvPci, buf, &blen);
    if (ret != SCARD_S_SUCCESS) 
    {
        DBG1(DBG_IKE, "SCARD: transmit failed");
        free(buf);
        return -1;
     }
     if (blen != len + 2) 
     {
        DBG3(DBG_IKE, "SCARD: record read returned unexpected length %d (expected %d)", blen, len + 2);
        free(buf);
        return -1;
     }
     if (buf[len] != 0x90 || buf[len + 1] != 0x00) 
     {
        DBG1(DBG_IKE, "SCARD: record read returned unexpected status %02x %02x (expected 90 00)",
                buf[len], buf[len + 1]);
         free(buf);
         return -1;
     }
     memcpy(data, buf, len);
     free(buf);
     return 0;
 }

