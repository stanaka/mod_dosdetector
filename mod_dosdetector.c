/*
 * Copyright (C) 2007 Hatena Inc.
 * The author is Shinji Tanaka <stanaka@hatena.ne.jp>.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice, this permission notice, and the
 * following disclaimer shall be included in all copies or substantial
 * portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */

#include <arpa/inet.h>
//#include <netinet/in.h>
#include <time.h>
#include <regex.h>
#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_protocol.h"
#include "http_core.h"
#include "http_main.h"
#include "http_log.h"
#include "ap_mpm.h"
#include "ap_config.h"
#include "apr_strings.h"
#include "apr_shm.h"
#include "apr_thread_mutex.h"

//#define _DEBUG

#ifdef _DEBUG
#define DEBUGLOG(...) ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, NULL, __VA_ARGS__)
//#define DEBUGLOG debuglog
#else
#define DEBUGLOG(...) //
//#define DEBUGLOG(...) ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, NULL, __VA_ARGS__)
//#define DEBUGLOG debuglog
#endif

#define TRACELOG(...) ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, NULL, __VA_ARGS__)

#define MODULE_NAME "mod_dosdetector"
#define MODULE_VERSION "0.2"

#define USER_DATA_KEY "DoSDetecterUserDataKey"

#define DEFAULT_THRESHOLD 10000
#define DEFAULT_PERIOD 10
#define DEFAULT_BAN_PERIOD 300
#define DEFAULT_TABLE_SIZE 100

#if (AP_SERVER_MINORVERSION_NUMBER > 2)
static const char *DefaultContentType = "text/plain";
#endif

module AP_MODULE_DECLARE_DATA dosdetector_module;

struct s_client {
	struct in_addr addr;
	int count;
	time_t interval;
	time_t last;
	struct s_client* next;
	time_t suspected;
	time_t hard_suspected;
};
typedef struct s_client client_t;

typedef struct {
	client_t *head;
	client_t base[1];
} client_list_t;

typedef struct {
	signed int detection;
    signed int threshold;
    signed int ban_threshold;
    signed int period;
    signed int ban_period;
	signed int forwarded;
    apr_array_header_t *ignore_contenttype;
    apr_array_header_t *contenttype_regexp;
} dosdetector_dir_config;

static long table_size  = DEFAULT_TABLE_SIZE;
const char *shmname;

static client_list_t *client_list;
static char lock_name[L_tmpnam];
static char shm_name[L_tmpnam];
static apr_global_mutex_t *lock = NULL;
static apr_shm_t *shm = NULL;


static apr_status_t cleanup_shm(void *not_used)
{
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, "Notice: cleaning up shared memory");
    fflush(stderr);

    if (shm) {
        apr_shm_destroy(shm);
        shm = NULL;
    }

    if (lock) {
        apr_global_mutex_destroy(lock);
        lock = NULL;
    }

    return APR_SUCCESS;
}

static void log_and_cleanup(char *msg, apr_status_t status, server_rec *s)
{
    ap_log_error(APLOG_MARK, APLOG_ERR, status, s, "Error: %s", msg);
    cleanup_shm(NULL);
}

static void create_shm(server_rec *s,apr_pool_t *p)
{	
    int threaded_mpm;
    ap_mpm_query(AP_MPMQ_IS_THREADED, &threaded_mpm);
    //if (threaded_mpm) {
	tmpnam(lock_name);
	apr_global_mutex_create(&lock, lock_name, APR_THREAD_MUTEX_DEFAULT, p);
	//DEBUGLOG("threaded!");
    // }

	size_t size;
	size =  sizeof(client_list_t) + table_size * sizeof(client_t);

    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
				 "Create or Joining shmem. name: %s, size: %d", shmname, size);
    if(lock) apr_global_mutex_lock(lock);
    apr_status_t rc = apr_shm_attach(&shm, shmname, p);
    if (APR_SUCCESS != rc) {
		DEBUGLOG("dosdetector: Creating shared memory");
		apr_shm_remove(shmname, p);
		rc = apr_shm_create(&shm, size, shmname, p);
		if (APR_SUCCESS != rc) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0,0, "dosdetector: failed to create shared memory %s\n", shmname);
			//ap_log_error(APLOG_MARK, APLOG_ERR, 0,0, "dosdetector: %s:%d: failed to create shared memory %s\n", __FILE__, __LINE__, shmname);
		} else {
			client_list = apr_shm_baseaddr_get(shm);
			memset(client_list, 0, size);
		}
    } else {
		DEBUGLOG("dosdetector: Joining shared memory");
		client_list = apr_shm_baseaddr_get(shm);
    }

	apr_shm_remove(shmname, p); // Just to set destroy flag.

	client_list->head = client_list->base;
	client_t *c = client_list->base;
	int i;

	for (i = 1; i < table_size; i++) {
		c->next = (c + 1);
		c++;
	}
	c->next = NULL;
	if (lock) apr_global_mutex_unlock(lock);

}

static client_t *get_client(client_list_t *client_list, struct in_addr clientip, int period)
{
	//ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, 0, "get_client: looking %d", clientip.s_addr);
	client_t *index, **prev = &client_list->head;
	
	for(index = client_list->head; index->next != (client_t *) 0; index = index->next){
		if(index->addr.s_addr == 0 || index->addr.s_addr == clientip.s_addr)
			break;
		prev = &index->next;
	}

	if(index == (client_t *) 0)
		return (client_t *)0;

	*prev = index->next;
	index->next = client_list->head;
	client_list->head = index;

	time_t now = time((time_t*)0);
	int rest;
	if(now - index->last > period){
		index->interval = (now - index->last) / period;
		rest = (now - index->last) % period;
		index->last = now - rest;
	} else {
		index->interval = 0;
	}
	if(index->addr.s_addr != clientip.s_addr){
		index->count = 0;
		index->interval = 0;
		index->suspected = 0;
		index->hard_suspected = 0;
		index->addr = clientip;
	}

	return index;
}

static void *dosdetector_create_dir_config(apr_pool_t *p, char *path)
{
	//DEBUGLOG("create dir is called");
    dosdetector_dir_config *cfg = (dosdetector_dir_config *)
	    apr_pcalloc(p, sizeof (*cfg));
	
    /* default configuration: no limit, and both arrays are empty */
	cfg->detection  = 1;
    cfg->threshold  = DEFAULT_THRESHOLD;
    cfg->period     = DEFAULT_PERIOD;
    cfg->ban_period = DEFAULT_BAN_PERIOD;
	cfg->forwarded  = 0;
    cfg->ignore_contenttype = apr_array_make(p, 0, sizeof(char *));
    cfg->contenttype_regexp = apr_array_make(p, 0, sizeof(char *));

    return (void *) cfg;
}

static void count_increment(client_t *client, int threshold)
{
	//counter->count = counter->count - counter->interval * period;
	client->count = client->count - client->interval * threshold;
	if(client->count < 0)
		client->count = 0;
	client->count ++;
	
	return;
}

static int dosdetector_handler(request_rec *r)
{
	//DEBUGLOG("dosdetector_handler is called");

    dosdetector_dir_config *cfg = (dosdetector_dir_config *) ap_get_module_config(r->per_dir_config, &dosdetector_module);
	
	if(cfg->detection) return DECLINED;
    if (!ap_is_initial_req(r)) return DECLINED;

    //char **ignore_contenttype = (char **) cfg->ignore_contenttype->elts;
	
    const char *content_type;
    const char *address_tmp;
    const char *address = NULL;
    int i;

    content_type = ap_sub_req_lookup_uri(r->uri, r, NULL)->content_type;
    if (!content_type) {
#if (AP_SERVER_MINORVERSION_NUMBER > 2)
        content_type = DefaultContentType;
#else
        content_type = ap_default_type(r);
#endif
    }

	if (cfg->forwarded){
		if ((address_tmp = apr_table_get(r->headers_in, "X-Forwarded-For")) != NULL){
			const char *i = address_tmp;
			while(*i != 0 && *i != ',')
				i++;
			address = apr_pstrndup(r->pool, address_tmp, i - address_tmp);
		}
	}
	if (address == NULL) {
#if (AP_SERVER_MINORVERSION_NUMBER > 2)
		address = r->connection->client_ip;
#else
		address = r->connection->remote_ip;
#endif
    }

    ap_regmatch_t regmatch[AP_MAX_REG_MATCH];
    ap_regex_t **contenttype_regexp = (ap_regex_t **) cfg->contenttype_regexp->elts;
	for (i = 0; i < cfg->contenttype_regexp->nelts; i++) {
		if(!ap_regexec(contenttype_regexp[i], content_type, AP_MAX_REG_MATCH, regmatch, 0)){
			//ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, 0, "ignoring content-type: %s", content_type);
			return OK;
		}
    }
	DEBUGLOG("dosdetector: processing content-type: %s", content_type);

	struct in_addr addr;
	if(!cfg->forwarded) {
#if (AP_SERVER_MINORVERSION_NUMBER > 2)
		addr = r->connection->client_addr->sa.sin.sin_addr;
#else
		addr = r->connection->remote_addr->sa.sin.sin_addr;
#endif
    }
	if(cfg->forwarded || addr.s_addr == 0){
		if (inet_aton(address, &addr) == 0) {
			TRACELOG("dosdetector: '%s' is not  a valid IP addresss", address);
			return DECLINED;
		}
	}
	if (lock) apr_global_mutex_lock(lock);
	client_t *client = get_client(client_list, addr, cfg->period);
	if (lock) apr_global_mutex_unlock(lock);

	#ifdef _DEBUG
	int last_count = client->count;
	#endif
	count_increment(client, cfg->threshold);
    DEBUGLOG("dosdetector: %s, count: %d -> %d, interval: %d", address, last_count, client->count, (int)client->interval);
    //DEBUGLOG("dosdetector: %s, count: %d -> %d, interval: %d on tid %d, pid %d", address, last_count, client->count, (int)client->interval, gettid(), getpid());

	time_t now = time((time_t *)0);
	if(client->suspected > 0 && client->suspected + cfg->ban_period > now){
		apr_table_setn(r->subprocess_env, "SuspectDoS", "1");
		//apr_table_setn(r->notes, "SuspectDoS", "1");
		DEBUGLOG("dosdetector: '%s' has been still suspected as DoS attack! (suspected %d sec ago)", address, now - client->suspected);

		if(client->count > cfg->ban_threshold){
			if(client->hard_suspected == 0)
				TRACELOG("dosdetector: '%s' is suspected as Hard DoS attack! (counter: %d)", address, client->count);
			client->hard_suspected = now;
			apr_table_setn(r->subprocess_env, "SuspectHardDoS", "1");
			//apr_table_setn(r->notes, "SuspectHardDoS", "1");
		}
	} else {
        if(client->suspected > 0){
			client->suspected = 0;
			client->hard_suspected = 0;
			client->count = 0;
		}
		//int last_count = client->count;
		//client->count = client->count - client->interval * cfg->threshold;
		//if(client->count < 0)
		//	client->count = 0;
		//client->count ++;
		//DEBUGLOG("client address: %s, count: %d -> %d, interval: %d", address, last_count, client->count, client->interval);

		if(client->count > cfg->threshold){
			client->suspected = now;
			apr_table_setn(r->subprocess_env, "SuspectDoS", "1");
			//apr_table_setn(r->notes, "SuspectDoS", "1");
			TRACELOG("dosdetector: '%s' is suspected as DoS attack! (counter: %d)", address, client->count);
		}
	}

	return DECLINED;
}

static const char *set_detection_config(cmd_parms *parms, void *mconfig, const char *arg)
{
    dosdetector_dir_config *cfg = (dosdetector_dir_config *) mconfig;

    cfg->detection = ap_strcasecmp_match("on", arg);
	//ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, 0, "detection: %d", cfg->detection);
    return NULL;
}

static const char *set_threshold_config(cmd_parms *parms, void *mconfig, const char *arg)
{
    dosdetector_dir_config *cfg = (dosdetector_dir_config *) mconfig;
    signed long int threshold = strtol(arg, (char **) NULL, 10);
    if ((threshold > 65535) || (threshold < 0)) return "Integer invalid number";

    cfg->threshold = threshold;
    return NULL;
}

static const char *set_hard_threshold_config(cmd_parms *parms, void *mconfig, const char *arg)
{
    dosdetector_dir_config *cfg = (dosdetector_dir_config *) mconfig;
    signed long int ban_threshold = strtol(arg, (char **) NULL, 10);
    if ((ban_threshold > 65535) || (ban_threshold < 0)) return "Integer invalid number";

    cfg->ban_threshold = ban_threshold;
    return NULL;
}

static const char *set_period_config(cmd_parms *parms, void *mconfig, const char *arg)
{
    dosdetector_dir_config *cfg = (dosdetector_dir_config *) mconfig;
    signed long int period = strtol(arg, (char **) NULL, 10);
    if ((period > 65535) || (period < 0)) return "Integer invalid number";

    cfg->period = period;
    return NULL;
}

static const char *set_ban_period_config(cmd_parms *parms, void *mconfig, const char *arg)
{
    dosdetector_dir_config *cfg = (dosdetector_dir_config *) mconfig;
    signed long int ban_period = strtol(arg, (char **) NULL, 10);
    if ((ban_period > 65535) || (ban_period < 0)) return "Integer overflow or invalid number";

    cfg->ban_period = ban_period;
    return NULL;
}

static const char *set_shmem_name_config(cmd_parms *parms, void *mconfig, const char *arg)
{
    shmname = arg;
    return NULL;
}

static const char *set_table_size_config(cmd_parms *parms, void *mconfig, const char *arg)
{
    signed long int size = strtol(arg, (char **) NULL, 10);
    if ((size > 65535) || (size < 0)) return "Integer invalid number";

    table_size = size;
    return NULL;
}

static const char *set_forwarded_config(cmd_parms *parms, void *mconfig, const char *arg)
{
    dosdetector_dir_config *cfg = (dosdetector_dir_config *) mconfig;

    cfg->forwarded = !ap_strcasecmp_match("on", arg);
	//ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, 0, "forwarded: %d", cfg->forwarded);
    return NULL;
}

static const char *set_ignore_contenttype_config(cmd_parms *parms, void *mconfig,
					 const char *arg)
{
    dosdetector_dir_config *cfg = (dosdetector_dir_config *) mconfig;
    char **ignore_contenttype = (char **) cfg->ignore_contenttype->elts;

    *(char **) apr_array_push(cfg->ignore_contenttype) = apr_pstrdup(parms->pool, arg);

	int i;
	regex_t *regexp;
	for (i = 0; i < cfg->ignore_contenttype->nelts; i++) {
        regexp = (regex_t *)ap_pregcomp(parms->pool, (char *)ignore_contenttype[i], REG_EXTENDED|REG_ICASE);
		*(regex_t **)apr_array_push(cfg->contenttype_regexp) = regexp;
    }

    return NULL;
}

static command_rec dosdetector_cmds[] = {
    AP_INIT_TAKE1("DoSDetection", set_detection_config, NULL, OR_FILEINFO,
     "Enable to detect DoS Attack or not"),
    AP_INIT_TAKE1("DoSThreshold", set_threshold_config, NULL, OR_FILEINFO,
     "Threshold of detecting DoS Attack"),
    AP_INIT_TAKE1("DoSHardThreshold", set_hard_threshold_config, NULL, OR_FILEINFO,
     "Hard Threshold for DoS Attack"),
    AP_INIT_TAKE1("DoSPeriod", set_period_config, NULL, OR_FILEINFO,
     "Period of detecting DoS Attack"),
    AP_INIT_TAKE1("DoSBanPeriod", set_ban_period_config, NULL, OR_FILEINFO,
     "Period of banning client"),
    AP_INIT_TAKE1("DoSShmemName", set_shmem_name_config, NULL, OR_FILEINFO,
     "The name of shared memory to allocate for keeping track of clients"),
    AP_INIT_TAKE1("DoSTableSize", set_table_size_config, NULL, OR_FILEINFO,
     "The size of table for tracking clients"),
    AP_INIT_TAKE1("DoSForwarded", set_forwarded_config, NULL, OR_FILEINFO,
     "Use X-Forwarded-For header for Remote Address"),
    AP_INIT_ITERATE("DoSIgnoreContentType", set_ignore_contenttype_config, NULL, OR_FILEINFO,
     "The names of ignoring Content Type"),
    {NULL},
};

static int initialize_module(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
	//DEBUGLOG("initialize_module is called");
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                 MODULE_NAME " " MODULE_VERSION " started.");

	void *user_data;
    apr_pool_userdata_get(&user_data, USER_DATA_KEY, s->process->pool);
    if (user_data == NULL) {
        apr_pool_userdata_set((const void *)(1), USER_DATA_KEY, apr_pool_cleanup_null, s->process->pool);
        return OK;
    }

    create_shm(s, p);
    apr_pool_cleanup_register(p, NULL, cleanup_shm, apr_pool_cleanup_null);

    return OK;
}

static void initialize_child(apr_pool_t *p, server_rec *s)
{
	//DEBUGLOG("initialize_child is called");
    apr_status_t status;

    if (!shm) {
		DEBUGLOG("dosdetector: shm is null in initialize_child");
        return;
    }

    status = apr_global_mutex_child_init(&lock, lock_name, p);
    if (status != APR_SUCCESS) {
        log_and_cleanup("dosdetector: failed to create lock (lock)", status, s);
        return;
    }
}

static void register_hooks(apr_pool_t *p)
{
	tmpnam(shm_name);
    shmname    = shm_name;

    ap_hook_post_read_request(dosdetector_handler,NULL,NULL,APR_HOOK_MIDDLE);
    ap_hook_post_config(initialize_module, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(initialize_child, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA dosdetector_module = {
    STANDARD20_MODULE_STUFF,
    dosdetector_create_dir_config, /* create per-dir config structures */
    NULL,			/* merge  per-dir    config structures */
    NULL,			/* create per-server config structures */
    NULL,			/* merge  per-server config structures */
    dosdetector_cmds,		/* table of config file commands       */
    register_hooks
};
