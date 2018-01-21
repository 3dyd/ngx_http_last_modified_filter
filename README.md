# ngx_http_last_modified_filter
NGINX module to override `Last-Modified` and `ETag` response headers using different file as the source.

## Directives

<table>
  <tr>
    <td align="left">Syntax:</td>
    <td><code><strong>last_modified_override</strong> on | off;</code></td>
  </tr>
  <tr>
    <td align="left">Default:</td>
    <td><code>last_modified_override off;</code></td>
  </tr>
  <tr>
    <td align="left">Context:</td>
    <td><code>http, server, location</code></td>
  </tr>
</table>

Enables or disables the override of `Last-Modified` and `ETag` headers in response header fields.

<table>
  <tr>
    <td align="left">Syntax:</td>
    <td><code><strong>last_modified_source</strong> <i>file</i>;</code></td>
  </tr>
  <tr>
    <td align="left">Default:</td>
    <td><code>—</code></td>
  </tr>
  <tr>
    <td align="left">Context:</td>
    <td><code>http, server, location</code></td>
  </tr>
</table>

Defines the file whose last access time will be used in `Last-Modified` header. If value there aleady exists, it will be overridden only if it is older.

<table>
  <tr>
    <td align="left">Syntax:</td>
    <td><code><strong>last_modified_clear_etag</strong> on | off;</code></td>
  </tr>
  <tr>
    <td align="left">Default:</td>
    <td><code>last_modified_clear_etag on;</code></td>
  </tr>
  <tr>
    <td align="left">Context:</td>
    <td><code>http, server, location</code></td>
  </tr>
</table>

If disabled, `ETag` response header will be removed.
