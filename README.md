# ngx_http_last_modified_filter
NGINX module to override `Last-Modified` and `ETag` response headers using last access time of different files.

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
    <td><code>server, location</code></td>
  </tr>
</table>

Enables or disables the override of `Last-Modified` and `ETag` headers in response header fields.

<table>
  <tr>
    <td align="left">Syntax:</td>
    <td><code><strong>last_modified_try_files</strong> <i>file ...</i>;</code></td>
  </tr>
  <tr>
    <td align="left">Default:</td>
    <td><code>—</code></td>
  </tr>
  <tr>
    <td align="left">Context:</td>
    <td><code>server, location</code></td>
  </tr>
</table>

Defines files whose last access time should be considered. `Last-Modified` header value is retained if it contains more recent date than the files.

The path to a file is constructed from the file parameter according to the `root` and `alias` directives. Variables can be used.

Contexts are merged. I.e. if you have files in `server` and `location` contexts they all are considered.

By default nonexistent files do not lead to an error processing request. If you want internal server error to be fired if some file does not exist, prepend its path with `!` character.

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
    <td><code>server, location</code></td>
  </tr>
</table>

If disabled, `ETag` response header will be removed.
