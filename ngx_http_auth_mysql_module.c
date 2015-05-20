/*
 *
 * Copyright (C) Tomasz K. 2015.
 *
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static ngx_int_t ngx_http_auth_mysql_init(ngx_conf_t *ct);
static ngx_int_t ngx_http_auth_mysql_handler(ngx_http_request_t *r);

static ngx_command_t ngx_http_auth_mysql_module_commands[] = {
  ngx_null_command
};

static ngx_http_module_t ngx_http_auth_mysql_module_ctx = {
  NULL,     /* preconfiguration */
  ngx_http_auth_mysql_init,     /* postconfiguration */

  NULL,     /* create main config */
  NULL,     /* init main config */

  NULL,     /* create server config */
  NULL,     /* merge server config */

  NULL,     /* create location config */
  NULL      /* merge location config */
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

