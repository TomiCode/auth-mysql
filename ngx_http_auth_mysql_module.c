/*
 *
 * Copyright (C) Tomasz K. 2015.
 *
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
  /* TODO: ngx_flag_t ssl_enable; */ 
  /* MySQL Connection information. */
  ngx_str_t  mysql_address;
  ngx_uint_t mysql_port;

  /* MySQL Connection auth. */
  ngx_str_t mysql_username;
  ngx_str_t mysql_password;

  /* MySQL Database information. */
  ngx_str_t mysql_database;
  ngx_str_t mysql_table;
  
} ngx_http_auth_mysql_conf_t;

static void * ngx_http_auth_mysql_create_conf(ngx_conf_t *ct);
static char * ngx_http_auth_mysql_merge_conf(ngx_conf_t *ct, void *parent, void *child);
static ngx_int_t ngx_http_auth_mysql_init(ngx_conf_t *ct);
static ngx_int_t ngx_http_auth_mysql_handler(ngx_http_request_t *r);

static ngx_command_t ngx_http_auth_mysql_module_commands[] = {

  { ngx_string("auth_mysql_address"), 
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_auth_mysql_conf_t, mysql_address),
    NULL },
  
  { ngx_string("auth_mysql_port"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_num_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_auth_mysql_conf_t, mysql_port),
    NULL },

  { ngx_string("auth_mysql_username"), 
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_auth_mysql_conf_t, mysql_username),
    NULL },
 
  { ngx_string("auth_mysql_password"), 
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_auth_mysql_conf_t, mysql_password),
    NULL },

  { ngx_string("auth_mysql_database"), 
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_auth_mysql_conf_t, mysql_database),
    NULL },

  { ngx_string("auth_mysql_table"), 
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_auth_mysql_conf_t, mysql_table),
    NULL },
  
  ngx_null_command
};

static ngx_http_module_t ngx_http_auth_mysql_module_ctx = {
  NULL,     /* preconfiguration */
  ngx_http_auth_mysql_init,     /* postconfiguration */

  NULL,     /* create main config */
  NULL,     /* init main config */

  NULL,     /* create server config */
  NULL,     /* merge server config */

  ngx_http_auth_mysql_create_conf,     /* create location config */
  ngx_http_auth_mysql_merge_conf      /* merge location config */
};

ngx_module_t ngx_http_auth_mysql_module = {
  NGX_MODULE_V1,
  &ngx_http_auth_mysql_module_ctx,
  ngx_http_auth_mysql_module_commands,
  NGX_HTTP_MODULE,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NGX_MODULE_V1_PADDING
};

static void * ngx_http_auth_mysql_create_conf(ngx_conf_t *ct)
{
  ngx_http_auth_mysql_conf_t *conf;

  conf = ngx_pcalloc(ct->pool, sizeof(ngx_http_auth_mysql_conf_t));
  if (conf == NULL) {
    return NULL; /* Should I return.. a error? [FIXME] */
  }

  conf->mysql_port = NGX_CONF_UNSET_UINT;

  return conf;
}

static char * ngx_http_auth_mysql_merge_conf(ngx_conf_t *ct, void *parent, void *child)
{
  ngx_http_auth_mysql_conf_t *perv = parent;
  ngx_http_auth_mysql_conf_t *conf = child;

  /* Merging configs.. */
  ngx_conf_merge_str_value(conf->mysql_address, perv->mysql_address, "");
  ngx_conf_merge_uint_value(conf->mysql_port, perv->mysql_port, 0);

  ngx_conf_merge_str_value(conf->mysql_username, perv->mysql_username, "");
  ngx_conf_merge_str_value(conf->mysql_password, perv->mysql_password, "");
  
  ngx_conf_merge_str_value(conf->mysql_database, perv->mysql_database, "");
  ngx_conf_merge_str_value(conf->mysql_table, perv->mysql_table, "");
  
  return NGX_CONF_OK;
}

static ngx_int_t ngx_http_auth_mysql_init(ngx_conf_t *ct)
{
  ngx_http_handler_pt *hr;
  ngx_http_core_main_conf_t *conf;

  conf = ngx_http_conf_get_module_main_conf(ct, ngx_http_core_module);
  hr = ngx_array_push(&conf->phases[NGX_HTTP_ACCESS_PHASE].handlers);

  if (hr == NULL) {
    return NGX_ERROR;
  }

  *hr = ngx_http_auth_mysql_handler;

  return NGX_OK;
}

static ngx_int_t ngx_http_auth_mysql_realm(ngx_http_request_t *r)
{
  u_char *str;
  size_t len;

  r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
  if (r->headers_out.www_authenticate == NULL) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }
  
  len = sizeof("Basic realm=\"MySQL Auth\"") - 1;
  
  str = ngx_pnalloc(r->pool, len);
  if (str == NULL) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }
  ngx_cpymem(str, "Basic realm=\"MySQL Auth\"", len);

  r->headers_out.www_authenticate->hash = 1;
  ngx_str_set(&r->headers_out.www_authenticate->key, "WWW-Authenticate");
  r->headers_out.www_authenticate->value.data = str;
  r->headers_out.www_authenticate->value.len = len;
 
  return NGX_HTTP_UNAUTHORIZED;
}

static ngx_int_t ngx_http_auth_mysql_handler(ngx_http_request_t *r)
{
  
  ngx_int_t c;
  ngx_http_auth_mysql_conf_t * conf;

  conf = ngx_http_get_module_loc_conf(r, ngx_http_auth_mysql_module);
  
  if (conf == NULL) {
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "conf == NULL");
    return NGX_DECLINED;
  }
  
  if (conf->mysql_address.len) {
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "MySQL Address: %s", conf->mysql_address.data);
  }

  ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "MySQL Port: %d", conf->mysql_port);
  
  if (conf->mysql_username.len) {
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "MySQL User: %s", conf->mysql_username.data);
  }

  if (conf->mysql_password.len) {
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "MySQL Password: %s", conf->mysql_password.data);
  }

  c = ngx_http_auth_basic_user(r);
  if (c == NGX_DECLINED) {
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
        "Error in basic auth.");
    
    return ngx_http_auth_mysql_realm(r);
  }

  if (c == NGX_ERROR) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  // TODO.
  ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
      "User: %s with pass: %s", r->headers_in.user.data,
        r->headers_in.passwd.data);

  if(strstr(r->headers_in.user.data, "tomi:1234") != NULL) {
    return NGX_OK;
  }

  return ngx_http_auth_mysql_realm(r);
}

