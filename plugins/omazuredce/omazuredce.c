/* omazuredce.c
 * Prototype output module for Azure Monitor Logs Ingestion API (DCE/DCR).
 *
 * This prototype does not perform HTTP requests yet. It batches messages into
 * JSON under 1 MiB and prints both configuration and payload to stdout.
 *
 * Copyright 2026 Adiscon GmbH.
 *
 * This file is part of rsyslog.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *       -or-
 *       see COPYING.ASL20 in the source distribution
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "config.h"
#include "rsyslog.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "conf.h"
#include "syslogd-types.h"
#include "srUtils.h"
#include "template.h"
#include "module-template.h"
#include "errmsg.h"

MODULE_TYPE_OUTPUT;
MODULE_TYPE_NOKEEP;
MODULE_CNFNAME("omazuredce")

#define AZURE_MAX_BATCH_BYTES (1024 * 1024)

DEF_OMOD_STATIC_DATA;

typedef struct _instanceData {
	uchar *templateName;
	uchar *clientID;
	uchar *clientSecret;
	uchar *tenantID;
	uchar *dceURL;
	uchar *dcrID;
	uchar *tableName;
	int maxBatchBytes;
} instanceData;

typedef struct wrkrInstanceData {
	instanceData *pData;
	char *batchBuf; /* active JSON array, always starts with '[' */
	size_t batchLen;
	size_t recordCount;
} wrkrInstanceData_t;

static struct cnfparamdescr actpdescr[] = {
	{"template", eCmdHdlrGetWord, 0},
	{"client_id", eCmdHdlrString, 0},
	{"client_secret", eCmdHdlrString, 0},
	{"tenant_id", eCmdHdlrString, 0},
	{"dce_url", eCmdHdlrString, 0},
	{"dcr_id", eCmdHdlrString, 0},
	{"table_name", eCmdHdlrString, 0},
	{"max_batch_bytes", eCmdHdlrInt, 0}
};
static struct cnfparamblk actpblk = {CNFPARAMBLK_VERSION, sizeof(actpdescr) / sizeof(struct cnfparamdescr), actpdescr};

struct modConfData_s {
	rsconf_t *pConf;
};
static modConfData_t *runModConf = NULL;

static inline const char *safeStr(const uchar *s) {
	return (s == NULL) ? "<unset>" : (const char *)s;
}

static rsRetVal writeAll(const char *buf, size_t len) {
	DEFiRet;
	size_t off = 0;

	while (off < len) {
		const ssize_t wr = write(1, buf + off, len - off);
		if (wr <= 0) {
			ABORT_FINALIZE(RS_RET_IO_ERROR);
		}
		off += (size_t)wr;
	}

finalize_it:
	RETiRet;
}

static size_t jsonEscapedLen(const char *s) {
	size_t n = 0;
	for (; *s != '\0'; ++s) {
		const unsigned char c = (unsigned char)*s;
		switch (c) {
		case '"':
		case '\\':
		case '\b':
		case '\f':
		case '\n':
		case '\r':
		case '\t':
			n += 2;
			break;
		default:
			n += (c < 0x20) ? 6 : 1;
			break;
		}
	}
	return n;
}

static rsRetVal appendChar(wrkrInstanceData_t *pWrkrData, const char c) {
	DEFiRet;
	if (pWrkrData->batchLen + 1 > (size_t)pWrkrData->pData->maxBatchBytes) {
		ABORT_FINALIZE(RS_RET_ERR);
	}
	pWrkrData->batchBuf[pWrkrData->batchLen++] = c;
finalize_it:
	RETiRet;
}

static rsRetVal appendRaw(wrkrInstanceData_t *pWrkrData, const char *s, const size_t len) {
	DEFiRet;
	if (pWrkrData->batchLen + len > (size_t)pWrkrData->pData->maxBatchBytes) {
		ABORT_FINALIZE(RS_RET_ERR);
	}
	memcpy(pWrkrData->batchBuf + pWrkrData->batchLen, s, len);
	pWrkrData->batchLen += len;
finalize_it:
	RETiRet;
}

static rsRetVal appendEscapedJSON(wrkrInstanceData_t *pWrkrData, const char *s) {
	static const char hex[] = "0123456789abcdef";
	DEFiRet;

	for (; *s != '\0'; ++s) {
		const unsigned char c = (unsigned char)*s;
		switch (c) {
		case '"':
			CHKiRet(appendRaw(pWrkrData, "\\\"", 2));
			break;
		case '\\':
			CHKiRet(appendRaw(pWrkrData, "\\\\", 2));
			break;
		case '\b':
			CHKiRet(appendRaw(pWrkrData, "\\b", 2));
			break;
		case '\f':
			CHKiRet(appendRaw(pWrkrData, "\\f", 2));
			break;
		case '\n':
			CHKiRet(appendRaw(pWrkrData, "\\n", 2));
			break;
		case '\r':
			CHKiRet(appendRaw(pWrkrData, "\\r", 2));
			break;
		case '\t':
			CHKiRet(appendRaw(pWrkrData, "\\t", 2));
			break;
		default:
			if (c < 0x20) {
				char esc[6];
				esc[0] = '\\';
				esc[1] = 'u';
				esc[2] = '0';
				esc[3] = '0';
				esc[4] = hex[(c >> 4) & 0x0f];
				esc[5] = hex[c & 0x0f];
				CHKiRet(appendRaw(pWrkrData, esc, sizeof(esc)));
			} else {
				CHKiRet(appendChar(pWrkrData, (char)c));
			}
			break;
		}
	}

finalize_it:
	RETiRet;
}

static void resetBatch(wrkrInstanceData_t *pWrkrData) {
	pWrkrData->batchLen = 0;
	pWrkrData->recordCount = 0;
	pWrkrData->batchBuf[pWrkrData->batchLen++] = '[';
}

static rsRetVal flushBatch(wrkrInstanceData_t *pWrkrData) {
	char meta[768];
	instanceData *const pData = pWrkrData->pData;
	size_t payloadLen;
	int n;
	size_t outLen;
	DEFiRet;

	if (pWrkrData->recordCount == 0) {
		FINALIZE;
	}

	CHKiRet(appendChar(pWrkrData, ']'));
	payloadLen = pWrkrData->batchLen;
	pWrkrData->batchBuf[payloadLen] = '\0';

	n = snprintf(meta, sizeof(meta),
		     "omazuredce prototype config: client_id='%s' client_secret='%s' tenant_id='%s' "
		     "dce_url='%s' dcr_id='%s' table_name='%s' max_batch_bytes=%d\n",
		     safeStr(pData->clientID), safeStr(pData->clientSecret), safeStr(pData->tenantID),
		     safeStr(pData->dceURL), safeStr(pData->dcrID), safeStr(pData->tableName), pData->maxBatchBytes);
	if (n > 0) {
		outLen = ((size_t)n < sizeof(meta)) ? (size_t)n : sizeof(meta) - 1;
		CHKiRet(writeAll(meta, outLen));
	}

	n = snprintf(meta, sizeof(meta), "omazuredce prototype batch: records=%zu bytes=%zu payload=", pWrkrData->recordCount,
		     payloadLen);
	if (n > 0) {
		outLen = ((size_t)n < sizeof(meta)) ? (size_t)n : sizeof(meta) - 1;
		CHKiRet(writeAll(meta, outLen));
	}
	CHKiRet(writeAll(pWrkrData->batchBuf, payloadLen));
	CHKiRet(writeAll("\n", 1));

	resetBatch(pWrkrData);

finalize_it:
	RETiRet;
}

static rsRetVal addMessageToBatch(wrkrInstanceData_t *pWrkrData, const char *msg) {
	static const char recStart[] = "{\"message\":\"";
	static const char recEnd[] = "\"}";
	const size_t escapedLen = jsonEscapedLen(msg);
	const size_t recLen =
		(pWrkrData->recordCount > 0 ? 1 : 0) + sizeof(recStart) - 1 + escapedLen + sizeof(recEnd) - 1;
	DEFiRet;

	if (pWrkrData->batchLen + recLen + 1 > (size_t)pWrkrData->pData->maxBatchBytes) {
		CHKiRet(flushBatch(pWrkrData));
	}

	if (pWrkrData->batchLen + recLen + 1 > (size_t)pWrkrData->pData->maxBatchBytes) {
		LogError(0, RS_RET_ERR,
			 "omazuredce: dropping over-sized log record, escaped_len=%zu max_batch_bytes=%d",
			 escapedLen, pWrkrData->pData->maxBatchBytes);
		ABORT_FINALIZE(RS_RET_OK);
	}

	if (pWrkrData->recordCount > 0) CHKiRet(appendChar(pWrkrData, ','));
	CHKiRet(appendRaw(pWrkrData, recStart, sizeof(recStart) - 1));
	CHKiRet(appendEscapedJSON(pWrkrData, msg));
	CHKiRet(appendRaw(pWrkrData, recEnd, sizeof(recEnd) - 1));
	pWrkrData->recordCount++;

finalize_it:
	RETiRet;
}

static inline void setInstParamDefaults(instanceData *pData) {
	pData->templateName = NULL;
	pData->clientID = NULL;
	pData->clientSecret = NULL;
	pData->tenantID = NULL;
	pData->dceURL = NULL;
	pData->dcrID = NULL;
	pData->tableName = NULL;
	pData->maxBatchBytes = AZURE_MAX_BATCH_BYTES;
}

BEGINbeginCnfLoad
	CODESTARTbeginCnfLoad;
ENDbeginCnfLoad

BEGINendCnfLoad
	CODESTARTendCnfLoad;
ENDendCnfLoad

BEGINcheckCnf
	CODESTARTcheckCnf;
ENDcheckCnf

BEGINactivateCnf
	CODESTARTactivateCnf;
	runModConf = pModConf;
ENDactivateCnf

BEGINfreeCnf
	CODESTARTfreeCnf;
ENDfreeCnf

BEGINcreateInstance
	CODESTARTcreateInstance;
ENDcreateInstance

BEGINcreateWrkrInstance
	CODESTARTcreateWrkrInstance;
	CHKmalloc(pWrkrData->batchBuf = malloc((size_t)pWrkrData->pData->maxBatchBytes + 1));
	resetBatch(pWrkrData);
finalize_it:
ENDcreateWrkrInstance

BEGINisCompatibleWithFeature
	CODESTARTisCompatibleWithFeature;
	if (eFeat == sFEATURERepeatedMsgReduction) iRet = RS_RET_OK;
ENDisCompatibleWithFeature

BEGINfreeInstance
	CODESTARTfreeInstance;
	free(pData->clientID);
	free(pData->clientSecret);
	free(pData->tenantID);
	free(pData->dceURL);
	free(pData->dcrID);
	free(pData->tableName);
	free(pData->templateName);
ENDfreeInstance

BEGINfreeWrkrInstance
	CODESTARTfreeWrkrInstance;
	CHKiRet(flushBatch(pWrkrData));
finalize_it:
	free(pWrkrData->batchBuf);
ENDfreeWrkrInstance

BEGINdbgPrintInstInfo
	CODESTARTdbgPrintInstInfo;
	dbgprintf("omazuredce\n");
	dbgprintf("\ttemplate='%s'\n", safeStr(pData->templateName));
	dbgprintf("\tclient_id='%s'\n", safeStr(pData->clientID));
	dbgprintf("\ttenant_id='%s'\n", safeStr(pData->tenantID));
	dbgprintf("\tdce_url='%s'\n", safeStr(pData->dceURL));
	dbgprintf("\tdcr_id='%s'\n", safeStr(pData->dcrID));
	dbgprintf("\ttable_name='%s'\n", safeStr(pData->tableName));
	dbgprintf("\tmax_batch_bytes='%d'\n", pData->maxBatchBytes);
ENDdbgPrintInstInfo

BEGINtryResume
	CODESTARTtryResume;
ENDtryResume

BEGINbeginTransaction
	CODESTARTbeginTransaction;
ENDbeginTransaction

BEGINdoAction
	const char *msg;
	CODESTARTdoAction;
	msg = (const char *)ppString[0];
	if (msg == NULL) msg = "";

	CHKiRet(addMessageToBatch(pWrkrData, msg));
	iRet = RS_RET_DEFER_COMMIT;
finalize_it:
ENDdoAction

BEGINendTransaction
	CODESTARTendTransaction;
	CHKiRet(flushBatch(pWrkrData));
finalize_it:
ENDendTransaction

BEGINnewActInst
	struct cnfparamvals *pvals;
	int i;
	uchar *tplToUse;
	CODESTARTnewActInst;

	pvals = nvlstGetParams(lst, &actpblk, NULL);
	if (pvals == NULL) {
		LogError(0, RS_RET_MISSING_CNFPARAMS, "omazuredce: error reading config parameters");
		ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
	}

	CHKiRet(createInstance(&pData));
	setInstParamDefaults(pData);
	CODE_STD_STRING_REQUESTnewActInst(1);

	for (i = 0; i < actpblk.nParams; ++i) {
		if (!pvals[i].bUsed) continue;

		if (!strcmp(actpblk.descr[i].name, "template")) {
			free(pData->templateName);
			pData->templateName = (uchar *)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if (!strcmp(actpblk.descr[i].name, "client_id")) {
			pData->clientID = (uchar *)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if (!strcmp(actpblk.descr[i].name, "client_secret")) {
			pData->clientSecret = (uchar *)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if (!strcmp(actpblk.descr[i].name, "tenant_id")) {
			pData->tenantID = (uchar *)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if (!strcmp(actpblk.descr[i].name, "dce_url")) {
			pData->dceURL = (uchar *)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if (!strcmp(actpblk.descr[i].name, "dcr_id")) {
			pData->dcrID = (uchar *)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if (!strcmp(actpblk.descr[i].name, "table_name")) {
			pData->tableName = (uchar *)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if (!strcmp(actpblk.descr[i].name, "max_batch_bytes")) {
			pData->maxBatchBytes = (int)pvals[i].val.d.n;
		}
	}

	if (pData->maxBatchBytes <= 0 || pData->maxBatchBytes > AZURE_MAX_BATCH_BYTES) {
		LogError(0, RS_RET_PARAM_ERROR,
			 "omazuredce: max_batch_bytes must be in range 1..%d, got %d", AZURE_MAX_BATCH_BYTES,
			 pData->maxBatchBytes);
		ABORT_FINALIZE(RS_RET_PARAM_ERROR);
	}

	tplToUse = (uchar *)strdup((pData->templateName == NULL) ? "RSYSLOG_FileFormat" : (char *)pData->templateName);
	CHKiRet(OMSRsetEntry(*ppOMSR, 0, tplToUse, OMSR_NO_RQD_TPL_OPTS));

	CODE_STD_FINALIZERnewActInst;
	cnfparamvalsDestruct(pvals, &actpblk);
ENDnewActInst

BEGINmodExit
	CODESTARTmodExit;
ENDmodExit

NO_LEGACY_CONF_parseSelectorAct;

BEGINqueryEtryPt
	CODESTARTqueryEtryPt;
	CODEqueryEtryPt_STD_OMOD_QUERIES;
	CODEqueryEtryPt_STD_OMOD8_QUERIES;
	CODEqueryEtryPt_STD_CONF2_OMOD_QUERIES;
	CODEqueryEtryPt_STD_CONF2_QUERIES;
ENDqueryEtryPt

BEGINmodInit()
	CODESTARTmodInit;
	*ipIFVersProvided = CURR_MOD_IF_VERSION;
	CODEmodInit_QueryRegCFSLineHdlr
ENDmodInit

/* vi:set ai:
 */
