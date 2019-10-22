
/*
 * Based on nginx src/http/modules/ngx_http_try_files_module.c
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_array_t           *lengths;
    ngx_array_t           *values;
    ngx_str_t              name;
    unsigned               required:1;
} ngx_http_last_modified_try_file_t;


typedef struct {
    ngx_flag_t                          override;
    ngx_flag_t                          clear_etag;
    ngx_array_t                        *try_files;
} ngx_http_last_modified_loc_conf_t;


static ngx_int_t ngx_http_last_modified_header_filter(ngx_http_request_t *r);
static char *ngx_http_last_modified_try_files(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static void *ngx_http_last_modified_filter_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_last_modified_filter_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_last_modified_filter_init(ngx_conf_t *cf);


static ngx_command_t ngx_http_last_modified_commands[] = {
    { ngx_string("last_modified_override"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_last_modified_loc_conf_t, override),
      NULL },

    { ngx_string("last_modified_clear_etag"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_last_modified_loc_conf_t, clear_etag),
      NULL },

    { ngx_string("last_modified_try_files"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_last_modified_try_files,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_last_modified_loc_conf_t, try_files),
      NULL },

      ngx_null_command
};


static ngx_http_module_t ngx_http_last_modified_filter_module_ctx = {
    NULL,                                /* preconfiguration */
    ngx_http_last_modified_filter_init,  /* postconfiguration */

    NULL,                                /* create main configuration */
    NULL,                                /* init main configuration */

    NULL,                                /* create server configuration */
    NULL,                                /* merge server configuration */

    /* create location configuration */
    ngx_http_last_modified_filter_create_loc_conf,
    /* merge location configuration */
    ngx_http_last_modified_filter_merge_loc_conf
};


ngx_module_t ngx_http_last_modified_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_last_modified_filter_module_ctx, /* module context */
    ngx_http_last_modified_commands,     /* module directives */
    NGX_HTTP_MODULE,                     /* module type */
    NULL,                                /* init master */
    NULL,                                /* init module */
    NULL,                                /* init process */
    NULL,                                /* init thread */
    NULL,                                /* exit thread */
    NULL,                                /* exit process */
    NULL,                                /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;


static ngx_int_t
ngx_http_last_modified_header_filter(ngx_http_request_t *r)
{
    size_t                              len, root, alias, reserve, allocated;
    time_t                              initial;
    u_char                             *name;
    ngx_str_t                           path;
    ngx_uint_t                          i;
    ngx_open_file_info_t                of;
    ngx_http_script_code_pt             code;
    ngx_http_core_loc_conf_t           *clcf;
    ngx_http_script_engine_t            e;
    ngx_http_script_len_code_pt         lcode;
    ngx_http_last_modified_loc_conf_t  *lmcf;
    ngx_http_last_modified_try_file_t  *tf;

    if (r != r->main || !(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD))) {
        return ngx_http_next_header_filter(r);
    }

    lmcf = ngx_http_get_module_loc_conf(r,
                                        ngx_http_last_modified_filter_module);

    if (!lmcf->override) {
        return ngx_http_next_header_filter(r);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "last_modified handler (files: %d, date: %T)",
                   lmcf->try_files->nelts, r->headers_out.last_modified_time);

    initial = r->headers_out.last_modified_time;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    alias = clcf->alias;

    allocated = 0;
    root = 0;
    name = NULL;
    tf = lmcf->try_files->elts;

    for (i = 0; i < lmcf->try_files->nelts; i++)
    {
        if (tf->lengths) {
            ngx_memzero(&e, sizeof(ngx_http_script_engine_t));

            e.ip = tf->lengths->elts;
            e.request = r;

            /* 1 is for terminating '\0' as in static names */
            len = 1;

            while (*(uintptr_t *) e.ip) {
                lcode = *(ngx_http_script_len_code_pt *) e.ip;
                len += lcode(&e);
            }

        } else {
            len = tf->name.len;
        }

        if (!alias) {
            reserve = len > r->uri.len ? len - r->uri.len : 0;

        } else if (alias == NGX_MAX_SIZE_T_VALUE) {
            reserve = len;

        } else {
            reserve = len > r->uri.len - alias ? len - (r->uri.len - alias) : 0;
        }

        if (reserve > allocated || !allocated) {

            /* 16 bytes are preallocation */
            allocated = reserve + 16;

            if (ngx_http_map_uri_to_path(r, &path, &root, allocated) == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            name = path.data + root;
        }

        if (tf->values == NULL) {

            /* tf->name.len includes the terminating '\0' */

            ngx_memcpy(name, tf->name.data, tf->name.len);

            path.len = (name + tf->name.len - 1) - path.data;

        } else {
            e.ip = tf->values->elts;
            e.pos = name;
            e.flushed = 1;

            while (*(uintptr_t *) e.ip) {
                code = *(ngx_http_script_code_pt *) e.ip;
                code((ngx_http_script_engine_t *) &e);
            }

            path.len = e.pos - path.data;

            *e.pos = '\0';

            if (alias && alias != NGX_MAX_SIZE_T_VALUE
                && ngx_strncmp(name, r->uri.data, alias) == 0)
            {
                ngx_memmove(name, name + alias, len - alias);
                path.len -= alias;
            }
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "last_modified: trying to use \"%s\" \"%s\"",
                       name, path.data);

        ngx_memzero(&of, sizeof(ngx_open_file_info_t));

        of.read_ahead = clcf->read_ahead;
        of.directio = clcf->directio;
        of.valid = clcf->open_file_cache_valid;
        of.min_uses = clcf->open_file_cache_min_uses;
        of.test_only = 1;
        of.errors = clcf->open_file_cache_errors;
        of.events = clcf->open_file_cache_events;

        if (ngx_http_set_disable_symlinks(r, clcf, &path, &of) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
            == NGX_OK)
        {
            if (r->headers_out.last_modified_time < of.mtime) {
                r->headers_out.last_modified_time = of.mtime;

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "last_modified: overridden with %T", of.mtime);

            } else {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "last_modified: file is older");
            }

        } else {
            if (of.err == 0) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            if ((of.err != NGX_ENOENT && of.err != NGX_ENOTDIR
                 && of.err != NGX_ENAMETOOLONG) || tf->required)
            {
                ngx_log_error(NGX_LOG_CRIT, r->connection->log, of.err,
                              "last_modified: %s \"%V\" failed",
                              of.failed, &path);

                if (tf->required) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

            } else {
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, of.err,
                               "last_modified: %s \"%V\" failed",
                               of.failed, &path);
            }
        }

        tf++;
    }

    if (r->headers_out.last_modified_time != initial && r->headers_out.etag) {
        if (lmcf->clear_etag) {
            ngx_http_clear_etag(r);
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "last_modified: cleared etag");

        } else {
            ngx_http_set_etag(r);
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "last_modified: updated etag");
        }
    }

    return ngx_http_next_header_filter(r);
}


static char *
ngx_http_last_modified_try_files(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_last_modified_loc_conf_t *lmcf = conf;

    ngx_str_t                          *value;
    ngx_uint_t                          i, n;
    ngx_http_script_compile_t           sc;
    ngx_http_last_modified_try_file_t  *tf;

    if (lmcf->try_files) {
        return "is duplicate";
    }

    lmcf->try_files = ngx_array_create(cf->pool, cf->args->nelts - 1,
                                     sizeof(ngx_http_last_modified_try_file_t));

    if (lmcf->try_files == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    for (i = 0; i < cf->args->nelts - 1; i++) {
        tf = ngx_array_push(lmcf->try_files);
        if (tf == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(tf, sizeof(ngx_http_last_modified_try_file_t));

        tf->name = value[i + 1];

        if (tf->name.len > 0 && tf->name.data[0] == '!') {
            tf->required = 1;

            tf->name.data++;
            tf->name.len--;
        }

        n = ngx_http_script_variables_count(&tf->name);

        if (n) {
            ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

            sc.cf = cf;
            sc.source = &tf->name;
            sc.lengths = &tf->lengths;
            sc.values = &tf->values;
            sc.variables = n;
            sc.complete_lengths = 1;
            sc.complete_values = 1;

            if (ngx_http_script_compile(&sc) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

        } else {
            /* add trailing '\0' to length */
            tf->name.len++;
        }

        tf++;
    }

    return NGX_CONF_OK;
}


static void *
ngx_http_last_modified_filter_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_last_modified_loc_conf_t  *lmcf;

    lmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_last_modified_loc_conf_t));

    if (lmcf != NULL) {
        lmcf->override = NGX_CONF_UNSET;
        lmcf->clear_etag = NGX_CONF_UNSET;
    }

    return lmcf;
}


static char *
ngx_http_last_modified_filter_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_http_last_modified_loc_conf_t *prev = parent;
    ngx_http_last_modified_loc_conf_t *conf = child;

    ngx_uint_t                          i;
    ngx_http_last_modified_try_file_t  *tf, *ptf;

    ngx_conf_merge_value(conf->override, prev->override, 0);
    ngx_conf_merge_value(conf->clear_etag, prev->clear_etag, 1);

    if (conf->try_files == NULL) {
        conf->try_files = prev->try_files;
    }

    else if (prev->try_files) {
        ptf = prev->try_files->elts;

        for (i = 0; i < prev->try_files->nelts; i++) {
            tf = ngx_array_push(conf->try_files);

            if (tf == NULL) {
                return NGX_CONF_ERROR;
            }

            *tf = ptf[i];
        }
    }

    if (conf->override && !conf->try_files) {
        return "last_modified_override is on but files are not set";
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_last_modified_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_last_modified_header_filter;

    return NGX_OK;
}
