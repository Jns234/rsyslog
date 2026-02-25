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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <ctype.h>
#include <curl/curl.h>
#include "conf.h"
#include "syslogd-types.h"
#include "srUtils.h"
#include "template.h"
#include "module-template.h"
#include "errmsg.h"

MODULE_TYPE_OUTPUT;
MODULE_TYPE_NOKEEP;
MODULE_CNFNAME("omazuredce")

/* The maximum size of an API call to the Azure Log Ingestion API is 1MB, which (I assume) means that the call itself with the headers and so on must not exceed this size */
#define AZURE_MAX_BATCH_BYTES (1024 * 1024)

/* The max size of field values is 64KB, when that limit is reached the rest is turnecated. Not sure if this applies to the whole batch or per individual item in Batch 
    https://learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/service-limits#logs-ingestion-api */
#define AZURE_MAX_FIELD_BYTES (64 * 1024)
#define AZURE_OAUTH_SCOPE "https://monitor.azure.com/.default"
#define AZUREDCE_TimeGenerated "\"%timegenerated:::date-rfc3339%\""

/* Since I will be requesting a access token for log forwarding, this will come in useful https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow#first-case-access-token-request-with-a-shared-secret*/

DEF_OMOD_STATIC_DATA;

typedef struct _instanceData {
	uchar *templateName;
	uchar *clientID;
	uchar *clientSecret;
	uchar *tenantID;
	uchar *dceURL;
	uchar *dcrID;
	uchar *tableName;
	uchar *accessToken;
	int maxBatchBytes;
	int flushTimeoutMs;
	sbool includeTimeGenerated;
} instanceData;

typedef struct wrkrInstanceData {
	instanceData *pData;
	char *batchBuf; /* active JSON array, always starts with '[' */
	size_t batchLen;
	size_t recordCount;
	uint64_t lastMessageTimeMs;
	pthread_mutex_t batchLock;
	pthread_t timerThread;
	sbool timerThreadRunning;
	sbool stopTimerThread;
} wrkrInstanceData_t;

static struct cnfparamdescr actpdescr[] = {
	{"template", eCmdHdlrGetWord, 0},
	{"client_id", eCmdHdlrString, 0},
	{"client_secret", eCmdHdlrString, 0},
	{"tenant_id", eCmdHdlrString, 0},
	{"dce_url", eCmdHdlrString, 0},
	{"dcr_id", eCmdHdlrString, 0},
	{"table_name", eCmdHdlrString, 0},
	{"max_batch_bytes", eCmdHdlrInt, 0},
	{"flush_timeout_ms", eCmdHdlrNonNegInt, 0},
	{"time_generated", eCmdHdlrBinary, 0}
};
static struct cnfparamblk actpblk = {CNFPARAMBLK_VERSION, sizeof(actpdescr) / sizeof(struct cnfparamdescr), actpdescr};

struct modConfData_s {
	rsconf_t *pConf;
};
static modConfData_t *runModConf = NULL;

static inline const char *safeStr(const uchar *s) {
	return (s == NULL) ? "<unset>" : (const char *)s;
}

typedef struct tokenRespBuf_s {
	char *data;
	size_t len;
} tokenRespBuf_t;

static size_t tokenWriteCb(void *contents, size_t size, size_t nmemb, void *userp) {
	const size_t realsz = size * nmemb;
	tokenRespBuf_t *buf = (tokenRespBuf_t *)userp;
	char *newData = realloc(buf->data, buf->len + realsz + 1);
	if (newData == NULL) {
		return 0;
	}
	buf->data = newData;
	memcpy(buf->data + buf->len, contents, realsz);
	buf->len += realsz;
	buf->data[buf->len] = '\0';
	return realsz;
}

static char *extractJsonStringField(const char *json, const char *field) {
	char needle[128];
	char *p;
	char *start;
	char *out;
	size_t outLen = 0;

	if (json == NULL || field == NULL) return NULL;

	if (snprintf(needle, sizeof(needle), "\"%s\"", field) <= 0) return NULL;
	p = strstr((char *)json, needle);
	if (p == NULL) return NULL;
	p += strlen(needle);

	while (*p != '\0' && *p != ':') ++p;
	if (*p != ':') return NULL;
	++p;

	while (*p != '\0' && isspace((unsigned char)*p)) ++p;
	if (*p != '"') return NULL;
	++p;
	start = p;

	out = malloc(strlen(start) + 1);
	if (out == NULL) return NULL;

	while (*p != '\0') {
		if (*p == '\\') {
			++p;
			if (*p == '\0') break;
			switch (*p) {
			case '"':
			case '\\':
			case '/':
				out[outLen++] = *p;
				break;
			case 'b':
				out[outLen++] = '\b';
				break;
			case 'f':
				out[outLen++] = '\f';
				break;
			case 'n':
				out[outLen++] = '\n';
				break;
			case 'r':
				out[outLen++] = '\r';
				break;
			case 't':
				out[outLen++] = '\t';
				break;
			default:
				out[outLen++] = *p;
				break;
			}
		} else if (*p == '"') {
			out[outLen] = '\0';
			return out;
		} else {
			out[outLen++] = *p;
		}
		++p;
	}

	free(out);
	return NULL;
}

static rsRetVal requestAccessToken(instanceData *pData) {
	char tokenURL[512];
	char *body = NULL;
	char *escClientID = NULL;
	char *escClientSecret = NULL;
	char *escScope = NULL;
	CURL *curl = NULL;
	CURLcode curlRes;
	long httpCode = 0;
	size_t bodyLen;
	struct curl_slist *headers = NULL;
	tokenRespBuf_t response = {NULL, 0};
	char *token = NULL;
	DEFiRet;

	if (pData->clientID == NULL || pData->clientSecret == NULL || pData->tenantID == NULL) {
		LogError(0, RS_RET_PARAM_ERROR,
			 "omazuredce: cannot request access token, missing one of client_id/client_secret/tenant_id");
		ABORT_FINALIZE(RS_RET_PARAM_ERROR);
	}

	if (snprintf(tokenURL, sizeof(tokenURL), "https://login.microsoftonline.com/%s/oauth2/v2.0/token",
		     (char *)pData->tenantID) <= 0) {
		ABORT_FINALIZE(RS_RET_ERR);
	}

	curl = curl_easy_init();
	if (curl == NULL) {
		LogError(0, RS_RET_ERR, "omazuredce: curl_easy_init failed while requesting access token");
		ABORT_FINALIZE(RS_RET_ERR);
	}

	escClientID = curl_easy_escape(curl, (char *)pData->clientID, 0);
	escClientSecret = curl_easy_escape(curl, (char *)pData->clientSecret, 0);
	escScope = curl_easy_escape(curl, AZURE_OAUTH_SCOPE, 0);
	if (escClientID == NULL || escClientSecret == NULL || escScope == NULL) {
		LogError(0, RS_RET_ERR, "omazuredce: failed escaping OAuth form values");
		ABORT_FINALIZE(RS_RET_ERR);
	}

	bodyLen = strlen("client_id=&scope=&client_secret=&grant_type=client_credentials") + strlen(escClientID) +
		  strlen(escScope) + strlen(escClientSecret) + 1;
	body = malloc(bodyLen);
	if (body == NULL) ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);

	snprintf(body, bodyLen, "client_id=%s&scope=%s&client_secret=%s&grant_type=client_credentials", escClientID,
		 escScope, escClientSecret);

	headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
	curl_easy_setopt(curl, CURLOPT_URL, tokenURL);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(body));
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, tokenWriteCb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);

	DBGPRINTF("omazuredce: requesting OAuth token for tenant_id='%s' client_id='%s'\n", safeStr(pData->tenantID),
		  safeStr(pData->clientID));
	curlRes = curl_easy_perform(curl);
	if (curlRes != CURLE_OK) {
		LogError(0, RS_RET_IO_ERROR, "omazuredce: token request failed: %s", curl_easy_strerror(curlRes));
		ABORT_FINALIZE(RS_RET_IO_ERROR);
	}
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
	if (httpCode < 200 || httpCode >= 300) {
		LogError(0, RS_RET_IO_ERROR, "omazuredce: token request HTTP status=%ld response='%s'", httpCode,
			 response.data == NULL ? "" : response.data);
		ABORT_FINALIZE(RS_RET_IO_ERROR);
	}

	token = extractJsonStringField(response.data, "access_token");
	if (token == NULL || token[0] == '\0') {
		LogError(0, RS_RET_IO_ERROR, "omazuredce: access_token not found in token response");
		ABORT_FINALIZE(RS_RET_IO_ERROR);
	}

	free(pData->accessToken);
	pData->accessToken = (uchar *)token;
	token = NULL;
	DBGPRINTF("omazuredce: access token acquired successfully (len=%zu)\n", strlen((char *)pData->accessToken));

finalize_it:
	if (token != NULL) free(token);
	free(response.data);
	free(body);
	if (escClientID != NULL) curl_free(escClientID);
	if (escClientSecret != NULL) curl_free(escClientSecret);
	if (escScope != NULL) curl_free(escScope);
	if (headers != NULL) curl_slist_free_all(headers);
	if (curl != NULL) curl_easy_cleanup(curl);
	RETiRet;
}

static uint64_t nowMs(void) {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return ((uint64_t)tv.tv_sec * 1000ULL) + ((uint64_t)tv.tv_usec / 1000ULL);
}

static rsRetVal writeAll(const char *buf, size_t len) {
	DEFiRet;
	size_t off = 0;

	while (off < len) {
		const ssize_t wr = write(1, buf + off, len - off);
		if (wr <= 0) {
			DBGPRINTF("omazuredce: writeAll failed while writing %zu bytes (offset=%zu)\n", len, off);
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
	DBGPRINTF("omazuredce[%p]: reset batch buffer\n", pWrkrData);
}

static rsRetVal flushBatchUnlocked(wrkrInstanceData_t *pWrkrData) {
	char meta[768];
	instanceData *const pData = pWrkrData->pData;
	size_t payloadLen;
	int n;
	size_t outLen;
	DEFiRet;
	DBGPRINTF("omazuredce[%p]: flushBatch enter, records=%zu currentLen=%zu\n", pWrkrData, pWrkrData->recordCount,
		  pWrkrData->batchLen);

	if (pWrkrData->recordCount == 0) {
		FINALIZE;
	}

	CHKiRet(appendChar(pWrkrData, ']'));
	payloadLen = pWrkrData->batchLen;
	pWrkrData->batchBuf[payloadLen] = '\0';

	/*n = snprintf(meta, sizeof(meta),
		     "omazuredce prototype config: client_id='%s' client_secret='%s' tenant_id='%s' "
		     "dce_url='%s' dcr_id='%s' table_name='%s' max_batch_bytes=%d flush_timeout_ms=%d access_token='",
		     safeStr(pData->clientID), safeStr(pData->clientSecret), safeStr(pData->tenantID),
		     safeStr(pData->dceURL), safeStr(pData->dcrID), safeStr(pData->tableName), pData->maxBatchBytes,
		     pData->flushTimeoutMs);
	if (n > 0) {
		outLen = ((size_t)n < sizeof(meta)) ? (size_t)n : sizeof(meta) - 1;
		CHKiRet(writeAll(meta, outLen));
	}
	CHKiRet(writeAll(safeStr(pData->accessToken), strlen(safeStr(pData->accessToken))));
	CHKiRet(writeAll("'\n", 2));
	*/

	n = snprintf(meta, sizeof(meta), "omazuredce prototype batch: records=%zu bytes=%zu payload=", pWrkrData->recordCount,
		     payloadLen);
	if (n > 0) {
		outLen = ((size_t)n < sizeof(meta)) ? (size_t)n : sizeof(meta) - 1;
		CHKiRet(writeAll(meta, outLen));
	}
	CHKiRet(writeAll(pWrkrData->batchBuf, payloadLen));
	CHKiRet(writeAll("\n", 1));
	DBGPRINTF("omazuredce[%p]: flushed batch records=%zu payloadBytes=%zu\n", pWrkrData, pWrkrData->recordCount,
		  payloadLen);

	resetBatch(pWrkrData);

finalize_it:
	RETiRet;
}

static rsRetVal flushBatch(wrkrInstanceData_t *pWrkrData) {
	DEFiRet;
	int lockHeld = 0;
	if (pthread_mutex_lock(&pWrkrData->batchLock) != 0) {
		ABORT_FINALIZE(RS_RET_SYS_ERR);
	}
	lockHeld = 1;
	CHKiRet(flushBatchUnlocked(pWrkrData));
	if (pthread_mutex_unlock(&pWrkrData->batchLock) != 0) {
		lockHeld = 0;
		ABORT_FINALIZE(RS_RET_SYS_ERR);
	}
	lockHeld = 0;
finalize_it:
	if (lockHeld) {
		(void)pthread_mutex_unlock(&pWrkrData->batchLock);
	}
	RETiRet;
}

static rsRetVal addMessageToBatchUnlocked(wrkrInstanceData_t *pWrkrData, const char *msg, const char *timeGenerated) {
	static const char recStart[] = "{\"message\":\"";
	static const char timeGeneratedField[] = "\",\"TimeGenerated\":\"";
	static const char recEnd[] = "\"}";
	const size_t escapedLen = jsonEscapedLen(msg);
	size_t recLen = (pWrkrData->recordCount > 0 ? 1 : 0) + sizeof(recStart) - 1 + escapedLen + sizeof(recEnd) - 1;
	size_t timeGeneratedLen = 0;
	DEFiRet;
	DBGPRINTF("omazuredce[%p]: add message escapedLen=%zu projectedRecordLen=%zu currentBatchLen=%zu\n", pWrkrData,
		  escapedLen, recLen, pWrkrData->batchLen);

	if (pWrkrData->pData->includeTimeGenerated && timeGenerated != NULL && timeGenerated[0] != '\0') {
		timeGeneratedLen = jsonEscapedLen(timeGenerated);
		recLen += sizeof(timeGeneratedField) - 1 + timeGeneratedLen;
	}

	if (pWrkrData->batchLen + recLen + 1 > (size_t)pWrkrData->pData->maxBatchBytes) {
		DBGPRINTF("omazuredce[%p]: batch limit reached, forcing flush before append\n", pWrkrData);
		CHKiRet(flushBatchUnlocked(pWrkrData));
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
	if (pWrkrData->pData->includeTimeGenerated && timeGenerated != NULL && timeGenerated[0] != '\0') {
		CHKiRet(appendRaw(pWrkrData, timeGeneratedField, sizeof(timeGeneratedField) - 1));
		CHKiRet(appendEscapedJSON(pWrkrData, timeGenerated));
	}
	CHKiRet(appendRaw(pWrkrData, recEnd, sizeof(recEnd) - 1));
	pWrkrData->recordCount++;
	DBGPRINTF("omazuredce[%p]: message appended, recordCount=%zu batchLen=%zu\n", pWrkrData, pWrkrData->recordCount,
		  pWrkrData->batchLen);

finalize_it:
	RETiRet;
}

static void *batchTimerThread(void *arg) {
	wrkrInstanceData_t *const pWrkrData = (wrkrInstanceData_t *)arg;
	instanceData *const pData = pWrkrData->pData;
	DBGPRINTF("omazuredce[%p]: timer thread started with flush_timeout_ms=%d\n", pWrkrData, pData->flushTimeoutMs);

	while (!pWrkrData->stopTimerThread) {
		if (pData->flushTimeoutMs <= 0) {
			srSleep(0, 100000);
			continue;
		}

		if (pthread_mutex_lock(&pWrkrData->batchLock) == 0) {
			if (pWrkrData->recordCount > 0) {
				const uint64_t now = nowMs();
				const uint64_t elapsed = (now >= pWrkrData->lastMessageTimeMs) ? (now - pWrkrData->lastMessageTimeMs) : 0;
				if (elapsed >= (uint64_t)pData->flushTimeoutMs) {
					DBGPRINTF("omazuredce[%p]: timer flush triggered elapsed=%llums records=%zu\n", pWrkrData,
						  (unsigned long long)elapsed, pWrkrData->recordCount);
					(void)flushBatchUnlocked(pWrkrData);
				}
			}
			pthread_mutex_unlock(&pWrkrData->batchLock);
		}
		srSleep(0, 10000); /* 10ms check interval */
	}

	DBGPRINTF("omazuredce[%p]: timer thread exiting\n", pWrkrData);
	return NULL;
}

static inline void setInstParamDefaults(instanceData *pData) {
	pData->templateName = NULL;
	pData->clientID = NULL;
	pData->clientSecret = NULL;
	pData->tenantID = NULL;
	pData->dceURL = NULL;
	pData->dcrID = NULL;
	pData->tableName = NULL;
	pData->accessToken = NULL;
	pData->maxBatchBytes = AZURE_MAX_BATCH_BYTES;
	pData->flushTimeoutMs = 1000;
	pData->includeTimeGenerated = 0;
}

BEGINbeginCnfLoad
	CODESTARTbeginCnfLoad;
	DBGPRINTF("omazuredce: beginCnfLoad\n");
ENDbeginCnfLoad

BEGINendCnfLoad
	CODESTARTendCnfLoad;
	DBGPRINTF("omazuredce: endCnfLoad\n");
ENDendCnfLoad

BEGINcheckCnf
	CODESTARTcheckCnf;
	DBGPRINTF("omazuredce: checkCnf\n");
ENDcheckCnf

BEGINactivateCnf
	CODESTARTactivateCnf;
	runModConf = pModConf;
	DBGPRINTF("omazuredce: activateCnf runModConf=%p\n", runModConf);
ENDactivateCnf

BEGINfreeCnf
	CODESTARTfreeCnf;
	DBGPRINTF("omazuredce: freeCnf\n");
ENDfreeCnf

BEGINcreateInstance
	CODESTARTcreateInstance;
	DBGPRINTF("omazuredce: createInstance[%p]\n", pData);
ENDcreateInstance

BEGINcreateWrkrInstance
	int mutexInit = 0;
	CODESTARTcreateWrkrInstance;
	DBGPRINTF("omazuredce: createWrkrInstance[%p] maxBatchBytes=%d flushTimeoutMs=%d\n", pWrkrData,
		  pWrkrData->pData->maxBatchBytes, pWrkrData->pData->flushTimeoutMs);
	pWrkrData->lastMessageTimeMs = nowMs();
	pWrkrData->timerThreadRunning = 0;
	pWrkrData->stopTimerThread = 0;
	CHKmalloc(pWrkrData->batchBuf = malloc((size_t)pWrkrData->pData->maxBatchBytes + 1));
	if (pthread_mutex_init(&pWrkrData->batchLock, NULL) != 0) {
		ABORT_FINALIZE(RS_RET_SYS_ERR);
	}
	mutexInit = 1;
	resetBatch(pWrkrData);
	CHKiRet(requestAccessToken(pWrkrData->pData));
	if (pthread_create(&pWrkrData->timerThread, NULL, batchTimerThread, pWrkrData) != 0) {
		ABORT_FINALIZE(RS_RET_SYS_ERR);
	}
	pWrkrData->timerThreadRunning = 1;
finalize_it:
	if (iRet != RS_RET_OK) {
		if (pWrkrData->timerThreadRunning) {
			pWrkrData->stopTimerThread = 1;
			pthread_join(pWrkrData->timerThread, NULL);
			pWrkrData->timerThreadRunning = 0;
		}
		if (mutexInit) pthread_mutex_destroy(&pWrkrData->batchLock);
		free(pWrkrData->batchBuf);
		pWrkrData->batchBuf = NULL;
	}
	DBGPRINTF("omazuredce: createWrkrInstance[%p] ret=%d\n", pWrkrData, iRet);
ENDcreateWrkrInstance

BEGINisCompatibleWithFeature
	CODESTARTisCompatibleWithFeature;
	if (eFeat == sFEATURERepeatedMsgReduction) iRet = RS_RET_OK;
ENDisCompatibleWithFeature

BEGINfreeInstance
	CODESTARTfreeInstance;
	DBGPRINTF("omazuredce: freeInstance[%p]\n", pData);
	free(pData->clientID);
	free(pData->clientSecret);
	free(pData->tenantID);
	free(pData->dceURL);
	free(pData->dcrID);
	free(pData->tableName);
	free(pData->accessToken);
	free(pData->templateName);
ENDfreeInstance

BEGINfreeWrkrInstance
	CODESTARTfreeWrkrInstance;
	DBGPRINTF("omazuredce: freeWrkrInstance[%p]\n", pWrkrData);
	pWrkrData->stopTimerThread = 1;
	if (pWrkrData->timerThreadRunning) {
		pthread_join(pWrkrData->timerThread, NULL);
		pWrkrData->timerThreadRunning = 0;
	}
	CHKiRet(flushBatch(pWrkrData));
finalize_it:
	pthread_mutex_destroy(&pWrkrData->batchLock);
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
	dbgprintf("\tflush_timeout_ms='%d'\n", pData->flushTimeoutMs);
	dbgprintf("\ttime_generated='%d'\n", pData->includeTimeGenerated);
	dbgprintf("\taccess_token=%s\n", pData->accessToken == NULL ? "<unset>" : "<set>");
ENDdbgPrintInstInfo

BEGINtryResume
	CODESTARTtryResume;
	DBGPRINTF("omazuredce[%p]: tryResume\n", pWrkrData);
ENDtryResume

BEGINbeginTransaction
	CODESTARTbeginTransaction;
	DBGPRINTF("omazuredce[%p]: beginTransaction\n", pWrkrData);
ENDbeginTransaction

BEGINdoAction
	const char *msg;
	const char *timeGenerated;
	size_t msgLen;
	int lockHeld = 0;
	size_t recCnt;
	CODESTARTdoAction;
	msg = (ppString != NULL) ? (const char *)ppString[0] : "";
	timeGenerated = (pWrkrData->pData->includeTimeGenerated && ppString != NULL) ? (const char *)ppString[1] : NULL;
	if (msg == NULL) msg = "";
	msgLen = strlen(msg);
	DBGPRINTF("omazuredce[%p]: doAction msgLen=%zu preview='%.*s%s'\n", pWrkrData, msgLen,
		  (int)(msgLen > 80 ? 80 : msgLen), msg, (msgLen > 80 ? "..." : ""));

	if (pthread_mutex_lock(&pWrkrData->batchLock) != 0) {
		ABORT_FINALIZE(RS_RET_SYS_ERR);
	}
	lockHeld = 1;
	CHKiRet(addMessageToBatchUnlocked(pWrkrData, msg, timeGenerated));
	recCnt = pWrkrData->recordCount;
	pWrkrData->lastMessageTimeMs = nowMs();
	if (pthread_mutex_unlock(&pWrkrData->batchLock) != 0) {
		lockHeld = 0;
		ABORT_FINALIZE(RS_RET_SYS_ERR);
	}
	lockHeld = 0;
	/* Signal queue engine that all previous records are already batched/flushed. */
	iRet = (recCnt == 1) ? RS_RET_PREVIOUS_COMMITTED : RS_RET_DEFER_COMMIT;
finalize_it:
	if (lockHeld) {
		(void)pthread_mutex_unlock(&pWrkrData->batchLock);
	}
	DBGPRINTF("omazuredce[%p]: doAction ret=%d\n", pWrkrData, iRet);
ENDdoAction

BEGINendTransaction
	CODESTARTendTransaction;
	DBGPRINTF("omazuredce[%p]: endTransaction\n", pWrkrData);
	/* Preserve time-based batching: only force flush when timeout is explicitly disabled. */
	if (pWrkrData->pData->flushTimeoutMs == 0) {
		CHKiRet(flushBatch(pWrkrData));
	}
finalize_it:
	DBGPRINTF("omazuredce[%p]: endTransaction ret=%d\n", pWrkrData, iRet);
ENDendTransaction

BEGINnewActInst
	struct cnfparamvals *pvals;
	int i;
	int nTpls;
	uchar *tplToUse;
	CODESTARTnewActInst;
	DBGPRINTF("omazuredce: newActInst begin\n");

	pvals = nvlstGetParams(lst, &actpblk, NULL);
	if (pvals == NULL) {
		LogError(0, RS_RET_MISSING_CNFPARAMS, "omazuredce: error reading config parameters");
		ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
	}

	CHKiRet(createInstance(&pData));
	setInstParamDefaults(pData);

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
		} else if (!strcmp(actpblk.descr[i].name, "flush_timeout_ms")) {
			pData->flushTimeoutMs = (int)pvals[i].val.d.n;
		} else if (!strcmp(actpblk.descr[i].name, "time_generated")) {
			pData->includeTimeGenerated = (sbool)pvals[i].val.d.n;
		}
	}
	DBGPRINTF("omazuredce: parsed params template='%s' client_id='%s' tenant_id='%s' dce_url='%s' dcr_id='%s' "
		  "table_name='%s' max_batch_bytes=%d flush_timeout_ms=%d time_generated=%d client_secret=%s\n",
		  safeStr(pData->templateName), safeStr(pData->clientID), safeStr(pData->tenantID), safeStr(pData->dceURL),
		  safeStr(pData->dcrID), safeStr(pData->tableName), pData->maxBatchBytes, pData->flushTimeoutMs,
		  pData->includeTimeGenerated,
		  (pData->clientSecret == NULL) ? "<unset>" : "<set>");

	if (pData->maxBatchBytes <= 0 || pData->maxBatchBytes > AZURE_MAX_BATCH_BYTES) {
		LogError(0, RS_RET_PARAM_ERROR,
			 "omazuredce: max_batch_bytes must be in range 1..%d, got %d", AZURE_MAX_BATCH_BYTES,
			 pData->maxBatchBytes);
		ABORT_FINALIZE(RS_RET_PARAM_ERROR);
	}

	nTpls = pData->includeTimeGenerated ? 2 : 1;
	CODE_STD_STRING_REQUESTnewActInst(nTpls);
	tplToUse = (uchar *)strdup((pData->templateName == NULL) ? "RSYSLOG_FileFormat" : (char *)pData->templateName);
	CHKiRet(OMSRsetEntry(*ppOMSR, 0, tplToUse, OMSR_NO_RQD_TPL_OPTS));
	if (pData->includeTimeGenerated) {
		CHKiRet(OMSRsetEntry(*ppOMSR, 1, (uchar *)strdup(" AZUREDCE_TimeGenerated"), OMSR_NO_RQD_TPL_OPTS));
	}

	CODE_STD_FINALIZERnewActInst;
	cnfparamvalsDestruct(pvals, &actpblk);
ENDnewActInst

BEGINmodExit
	CODESTARTmodExit;
	DBGPRINTF("omazuredce: modExit\n");
	curl_global_cleanup();
ENDmodExit

NO_LEGACY_CONF_parseSelectorAct;

BEGINqueryEtryPt
	CODESTARTqueryEtryPt;
	CODEqueryEtryPt_STD_OMOD_QUERIES;
	CODEqueryEtryPt_TXIF_OMOD_QUERIES;
	CODEqueryEtryPt_STD_OMOD8_QUERIES;
	CODEqueryEtryPt_STD_CONF2_OMOD_QUERIES;
	CODEqueryEtryPt_STD_CONF2_QUERIES;
ENDqueryEtryPt

BEGINmodInit()
	uchar *pTmp;
	CODESTARTmodInit;
	*ipIFVersProvided = CURR_MOD_IF_VERSION;
	CODEmodInit_QueryRegCFSLineHdlr
	if (curl_global_init(CURL_GLOBAL_ALL) != 0) {
		LogError(0, RS_RET_OBJ_CREATION_FAILED, "omazuredce: curl_global_init failed");
		ABORT_FINALIZE(RS_RET_OBJ_CREATION_FAILED);
	}
	pTmp = (uchar *)AZUREDCE_TimeGenerated;
	tplAddLine(ourConf, " AZUREDCE_TimeGenerated", &pTmp);
	DBGPRINTF("omazuredce: modInit complete\n");
ENDmodInit

/* vi:set ai:
 */
