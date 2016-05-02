
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) hongzhidao (hongzhidao@gmail.com)
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_atomic_t                n1xx;
    ngx_atomic_t                n2xx;
    ngx_atomic_t                n3xx;
    ngx_atomic_t                n4xx;
    ngx_atomic_t                n5xx;
    ngx_atomic_t                total;

    ngx_msec_t                  avg_time;
    ngx_msec_t                  min_time;
    ngx_msec_t                  max_time;

    ngx_msec_t                  elapse;
    ngx_uint_t                  times;
} ngx_http_metric_shctx_t;


typedef struct {
    ngx_http_metric_shctx_t     *sh;
    ngx_slab_pool_t             *shpool;
    ngx_msec_t                   min_time;
    ngx_msec_t                   max_time;
} ngx_http_metric_shmctx_t;


typedef struct {
    ngx_shm_zone_t              *shm_zone;
    ngx_flag_t                   enable;
} ngx_http_metric_loc_conf_t;


static ngx_int_t ngx_http_metric_init(ngx_conf_t *cf);
static void *ngx_http_metric_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_metric_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);

static char *ngx_http_metric_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_metric(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_metric_status(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_metric_reset(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static void ngx_http_metric_cleanup(void *data);


static ngx_command_t ngx_http_metric_commands[] = {

    { ngx_string("metric_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_1MORE,
      ngx_http_metric_zone,
      0,
      0,
      NULL },

    { ngx_string("metric"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_metric,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("metric_status"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_http_metric_status,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("metric_reset"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_http_metric_reset,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};


static ngx_http_module_t ngx_http_metric_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_metric_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_metric_create_loc_conf,       /* create location configuration */
    ngx_http_metric_merge_loc_conf         /* merge location configuration */
};


ngx_module_t ngx_http_metric_module = {
    NGX_MODULE_V1,
    &ngx_http_metric_module_ctx,       /* module context */
    ngx_http_metric_commands,          /* module directives */
    NGX_HTTP_MODULE,                   /* module type */
    NULL,                              /* init master */
    NULL,                              /* init module */
    NULL,                              /* init process */
    NULL,                              /* init thread */
    NULL,                              /* exit thread */
    NULL,                              /* exit process */
    NULL,                              /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

static ngx_str_t  ngx_http_metric_zone_name = ngx_string("metric_zone");


static ngx_int_t
ngx_http_metric_header_filter(ngx_http_request_t *r)
{
    ngx_http_metric_loc_conf_t  *mlcf;
    ngx_http_cleanup_t          *cln;

    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_metric_module);

    if (!mlcf->enable) {
        return ngx_http_next_header_filter(r);
    }

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_http_metric_cleanup;
    cln->data = r;

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_metric_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    return ngx_http_next_body_filter(r, in);
}


static ngx_int_t
ngx_http_metric_status_handler(ngx_http_request_t *r)
{
    size_t                        size;
    ngx_int_t                     rc;
    ngx_buf_t                    *b;
    ngx_chain_t                   out;
    ngx_shm_zone_t               *shm_zone;
    ngx_slab_pool_t              *shpool;
    ngx_http_metric_shctx_t      *sh;
    ngx_http_metric_shmctx_t     *shmctx;
    ngx_http_metric_loc_conf_t   *mlcf;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    r->headers_out.content_type_len = sizeof("text/plain") - 1;
    ngx_str_set(&r->headers_out.content_type, "text/plain");
    r->headers_out.content_type_lowcase = NULL;

    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }

    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_metric_module);

    shm_zone = mlcf->shm_zone;
    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    shmctx = shm_zone->data;
    sh = shmctx->sh;

    ngx_shmtx_lock(&shpool->mutex);

    size = 1 + sizeof("\"1xx\":") - 1 + NGX_ATOMIC_T_LEN
           + sizeof(",\"2xx\":") + 1 + NGX_ATOMIC_T_LEN
           + sizeof(",\"3xx\":") + 1 + NGX_ATOMIC_T_LEN
           + sizeof(",\"4xx\":") + 1 + NGX_ATOMIC_T_LEN
           + sizeof(",\"5xx\":") + 1 + NGX_ATOMIC_T_LEN
           + sizeof(",\"total\":") + 1 + NGX_ATOMIC_T_LEN
           + sizeof(",\"avg_time\":") + 1 + NGX_TIME_T_LEN + 4 
           + sizeof(",\"min_time\":") + 1 + NGX_TIME_T_LEN + 4 
           + sizeof(",\"max_time\":") + 1 + NGX_TIME_T_LEN + 4 + 1;

    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    b->last = ngx_sprintf(b->last, "{\"1xx\":%uA", sh->n1xx);
    b->last = ngx_sprintf(b->last, ",\"2xx\":%uA", sh->n2xx);
    b->last = ngx_sprintf(b->last, ",\"3xx\":%uA", sh->n3xx);
    b->last = ngx_sprintf(b->last, ",\"4xx\":%uA", sh->n4xx);
    b->last = ngx_sprintf(b->last, ",\"5xx\":%uA", sh->n5xx);
    b->last = ngx_sprintf(b->last, ",\"total\":%uA", shmctx->sh->total);
    b->last = ngx_sprintf(b->last, ",\"avg_time\":%T.%03M", (time_t) sh->avg_time / 1000, sh->avg_time % 1000);
    b->last = ngx_sprintf(b->last, ",\"min_time\":%T.%03M", (time_t) sh->min_time / 1000, sh->min_time % 1000);
    b->last = ngx_sprintf(b->last, ",\"max_time\":%T.%03M}", (time_t) sh->max_time / 1000, sh->max_time % 1000);

    ngx_shmtx_unlock(&shpool->mutex);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}


static ngx_int_t
ngx_http_metric_reset_handler(ngx_http_request_t *r)
{
    size_t                        size;
    ngx_int_t                     rc;
    ngx_buf_t                    *b;
    ngx_chain_t                   out;
    ngx_shm_zone_t               *shm_zone;
    ngx_slab_pool_t              *shpool;
    ngx_http_metric_shctx_t      *sh;
    ngx_http_metric_shmctx_t     *shmctx;
    ngx_http_metric_loc_conf_t   *mlcf;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    r->headers_out.content_type_len = sizeof("text/plain") - 1;
    ngx_str_set(&r->headers_out.content_type, "text/plain");
    r->headers_out.content_type_lowcase = NULL;

    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }

    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_metric_module);

    shm_zone = mlcf->shm_zone;
    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    shmctx = shm_zone->data;
    sh = shmctx->sh;

    ngx_shmtx_lock(&shpool->mutex);

    size = sizeof("reset ok");

    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    b->last = ngx_sprintf(b->last, "reset ok");

	sh->total = 0;
    sh->n1xx = 0;
    sh->n2xx = 0;
    sh->n3xx = 0;
    sh->n3xx = 0;
    sh->n4xx = 0;
    sh->n5xx = 0;
    sh->avg_time = 0;
    sh->min_time = 0;
    sh->max_time = 0;
    sh->elapse = 0;
    sh->times = 0;

    ngx_shmtx_unlock(&shpool->mutex);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}


static void *
ngx_http_metric_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_metric_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_metric_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_metric_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_metric_loc_conf_t *prev = parent;
    ngx_http_metric_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    if (conf->shm_zone == NULL) {
        conf->shm_zone = prev->shm_zone;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_metric_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_metric_shmctx_t  *oshmctx = data;

    size_t                     len;
    ngx_http_metric_shmctx_t  *shmctx;

    shmctx = shm_zone->data;

    if (oshmctx) {
        shmctx->sh = oshmctx->sh;
        shmctx->shpool = oshmctx->shpool;

        return NGX_OK;
    }

    shmctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        shmctx->sh = shmctx->shpool->data;

        return NGX_OK;
    }

    shmctx->sh = ngx_slab_alloc(shmctx->shpool, sizeof(ngx_http_metric_shctx_t));
    if (shmctx->sh == NULL) {
        return NGX_ERROR;
    }

    shmctx->sh->total = 0;
    shmctx->sh->n1xx = 0;
    shmctx->sh->n2xx = 0;
    shmctx->sh->n3xx = 0;
    shmctx->sh->n3xx = 0;
    shmctx->sh->n4xx = 0;
    shmctx->sh->n5xx = 0;
    shmctx->sh->avg_time = 0;
    shmctx->sh->min_time = 0;
    shmctx->sh->max_time = 0;
    shmctx->sh->elapse = 0;
    shmctx->sh->times = 0;

    shmctx->shpool->data = shmctx->sh;

    len = sizeof(" in metric zone \"\"") + shm_zone->shm.name.len;

    shmctx->shpool->log_ctx = ngx_slab_alloc(shmctx->shpool, len);
    if (shmctx->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(shmctx->shpool->log_ctx, " in metric zone \"%V\"%Z",
                &shm_zone->shm.name);

    shmctx->shpool->log_nomem = 0;

    return NGX_OK;
}


static char *
ngx_http_metric_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ssize_t                            size;
    ngx_uint_t                         i;
    ngx_str_t                          s;
    ngx_msec_t                         min_time;
    ngx_msec_t                         max_time;
    ngx_str_t                         *value;
    ngx_shm_zone_t                    *shm_zone;
    ngx_http_metric_shmctx_t          *shmctx;

    value = cf->args->elts;

    shmctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_metric_shmctx_t));
    if (shmctx == NULL) {
        return NGX_CONF_ERROR;
    }

    size = 0;
    min_time = 1; /* 1 ms */
    max_time = 60 * 1000;  /* 1 minute */

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "size=", 5) == 0) {

            s.data = value[i].data + 5;
            s.len = value[i].data + value[i].len - s.data;

            size = ngx_parse_size(&s);

            if (size == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            if (size < (ssize_t) (8 * ngx_pagesize)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "zone \"%V\" is too small", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "min_time=", 9) == 0) {

            s.data = value[i].data + 9;
            s.len = value[i].data + value[i].len - s.data;

            min_time = ngx_parse_time(&s, 0);
            if (min_time == (ngx_msec_t) NGX_ERROR) {
                return "invalid value";
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "max_time=", 9) == 0) {

            s.data = value[i].data + 9;
            s.len = value[i].data + value[i].len - s.data;

            max_time = ngx_parse_time(&s, 0);
            if (max_time == (ngx_msec_t) NGX_ERROR) {
                return "invalid value";
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    shmctx->min_time = min_time;
    shmctx->max_time = max_time;

    shm_zone = ngx_shared_memory_add(cf, &ngx_http_metric_zone_name, size,
                                     &ngx_http_metric_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%V \"%V\" is already bound", &cmd->name, &ngx_http_metric_zone_name);
        return NGX_CONF_ERROR;
    }

    shm_zone->init = ngx_http_metric_init_zone;
    shm_zone->data = shmctx;

    return NGX_CONF_OK;
}


static char *
ngx_http_metric(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_metric_loc_conf_t  *mlcf = conf;

    ngx_str_t                   *value;
    ngx_shm_zone_t              *shm_zone;

    value = cf->args->elts;

    if (mlcf->enable != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    if (ngx_strcasecmp(value[1].data, (u_char *) "on") == 0) {
        mlcf->enable = 1;

    } else if (ngx_strcasecmp(value[1].data, (u_char *) "off") == 0) {
        mlcf->enable = 0;
        return NGX_CONF_OK;

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                     "invalid value \"%s\" in \"%s\" directive, "
                     "it must be \"on\" or \"off\"",
                     value[1].data, cmd->name.data);
        return NGX_CONF_ERROR;
    }

    shm_zone = ngx_shared_memory_add(cf, &ngx_http_metric_zone_name, 0,
                                     &ngx_http_metric_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    mlcf->shm_zone = shm_zone;

    return NGX_CONF_OK;
}


static char *
ngx_http_metric_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_metric_loc_conf_t  *mlcf = conf;

    ngx_shm_zone_t              *shm_zone;
    ngx_http_core_loc_conf_t    *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_metric_status_handler;

    shm_zone = ngx_shared_memory_add(cf, &ngx_http_metric_zone_name, 0,
                                     &ngx_http_metric_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    mlcf->shm_zone = shm_zone;

    return NGX_CONF_OK;
}


static char *
ngx_http_metric_reset(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_metric_loc_conf_t  *mlcf = conf;

    ngx_shm_zone_t              *shm_zone;
    ngx_http_core_loc_conf_t    *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_metric_reset_handler;

    shm_zone = ngx_shared_memory_add(cf, &ngx_http_metric_zone_name, 0,
                                     &ngx_http_metric_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    mlcf->shm_zone = shm_zone;

    return NGX_CONF_OK;
}


static void
ngx_http_metric_cleanup(void *data)
{
    ngx_http_request_t  *r = data;

    ngx_uint_t                   status;
    ngx_time_t                  *tp;
    ngx_msec_t                   ms;
    ngx_http_metric_shctx_t     *sh;
    ngx_http_metric_shmctx_t    *shmctx;
    ngx_http_metric_loc_conf_t  *mlcf;

    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_metric_module);

    shmctx = mlcf->shm_zone->data;
    sh = shmctx->sh;

    tp = ngx_timeofday();

    ms = (ngx_msec_t) ((tp->sec - r->start_sec) * 1000 + (tp->msec - r->start_msec));

    ngx_shmtx_lock(&shmctx->shpool->mutex);

    status = r->headers_out.status;

    if (status >= 200 && status < 300)
    {
        /* 2XX */
        sh->n2xx++;

    } else if (status >= 300 && status < 400)
    {
        /* 3XX */
        sh->n3xx++;

    } else if (status >= 400 && status < 500)
    {
        /* 4XX */
        sh->n4xx++;

    } else if (status >= 500 && status < 600)
    {
        /* 5XX */
        sh->n5xx++;

    } else {
        /* 1XX */
        sh->n1xx++;
    }

	sh->total++;

    if (ms > shmctx->min_time && ms < shmctx->max_time) {
	    sh->times++;
        sh->elapse += ms;

		if (sh->min_time == 0) {
            sh->min_time = ms;
	
		} else if (ms < sh->min_time) {
            sh->min_time = ms;
        }

		if (sh->max_time == 0) {
            sh->max_time = ms;

        } else if (ms > sh->max_time) {
            sh->max_time = ms;
        }

        sh->avg_time = sh->elapse / sh->times;
    }

    ngx_shmtx_unlock(&shmctx->shpool->mutex);
}


static ngx_int_t
ngx_http_metric_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_metric_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_metric_body_filter;

    return NGX_OK;
}
