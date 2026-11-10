/* url_crack: InternetCrackUrlA/W vector table, one TEST per URL.
 * Every row was observed on genuine Windows 10 22H2 (wininet 11.0.19041.2193, VM boot wnprobe-20261109-171613) and
 * matches the decomp of CrackUrl@0x60e70 / GetUrlAddress@0x61d20 / _InternetCrackUrlA@0x2dd88.
 * Each row is checked four ways: A and W, with and without an extra-info buffer (without one the path keeps the
 * ?query/#fragment, except file: URLs where PathCreateFromUrl drops it - the last column).
 * Columns: url, ok, error, nScheme, nPort, scheme, host, user, password, path, extra, path-without-extra-buffer.
 * Notable Win10 facts pinned here:
 *  - nPort: explicit port wins (":0" gives 0, ":0080" gives 80, ":" gives the default); > 65535, sign, space or
 *    letters -> 12005 (ERROR_INTERNET_INVALID_URL). Defaults: ftp 21, http 80, https 443, everything else 0.
 *  - no ':' at all -> 12006 (UNRECOGNIZED_SCHEME); "http:" / "http:/x" / "http:x" -> 12006 (http requires "//");
 *    "http:///p" (empty host) -> 12005.
 *  - mailto:, javascript:, vbscript: are cracked as user@host / host with an empty path; socks://, mailto://,
 *    javascript:// -> 12006. news: and unknown schemes without "//" are opaque (everything after ':' is the path).
 *  - file: the path is PathCreateFromUrl'ed (C:\dir\file.txt, \\server\share\...); the host is always empty.
 *  - the scheme string keeps its case; a leading space makes the scheme " http" (unknown, -1).
 *  - userinfo splits at the FIRST '@' ("a@b@host" -> user a, host "b@host"); "user:pa:ss@" -> 12005.
 *  - backslashes are not authority terminators for http ("http://host\path" -> host "host\path").
 * VM_TIMEOUT: 120 */
#include "uc.h"

UC_CRACK_VEC(http_www_example_com, "http://www.example.com/", 1, 0, 3, 80,
    "http", "www.example.com", "", "", "/", "", NULL)
UC_CRACK_VEC(http_www_example_com_2, "http://www.example.com", 1, 0, 3, 80,
    "http", "www.example.com", "", "", "", "", NULL)
UC_CRACK_VEC(http_www_example_com_path_file_ht, "http://www.example.com/path/file.html?q=1&r=2#frag", 1, 0, 3, 80,
    "http", "www.example.com", "", "", "/path/file.html", "?q=1&r=2#frag", NULL)
UC_CRACK_VEC(http_www_example_com_path_frag_no, "http://www.example.com/path#frag?notq", 1, 0, 3, 80,
    "http", "www.example.com", "", "", "/path", "#frag?notq", NULL)
UC_CRACK_VEC(http_www_example_com_q, "http://www.example.com?q", 1, 0, 3, 80,
    "http", "www.example.com", "", "", "", "?q", NULL)
UC_CRACK_VEC(http_www_example_com_f, "http://www.example.com#f", 1, 0, 3, 80,
    "http", "www.example.com", "", "", "", "#f", NULL)
UC_CRACK_VEC(http_user_pass_host_example_8080_, "http://user:pass@host.example:8080/p?x#y", 1, 0, 3, 8080,
    "http", "host.example", "user", "pass", "/p", "?x#y", NULL)
UC_CRACK_VEC(http_user_host, "http://user@host/", 1, 0, 3, 80,
    "http", "host", "user", "", "/", "", NULL)
UC_CRACK_VEC(http_user_host_2, "http://user:@host/", 1, 0, 3, 80,
    "http", "host", "user", "", "/", "", NULL)
UC_CRACK_VEC(http_pass_host, "http://:pass@host/", 1, 0, 3, 80,
    "http", "host", "", "pass", "/", "", NULL)
UC_CRACK_VEC(http_host, "http://@host/", 1, 0, 3, 80,
    "http", "host", "", "", "/", "", NULL)
UC_CRACK_VEC(http_a_b_host, "http://a@b@host/", 1, 0, 3, 80,
    "http", "b@host", "a", "", "/", "", NULL)
UC_CRACK_VEC(http_user_pa_ss_host, "http://user:pa:ss@host/", 0, 12005, 0, -1)
UC_CRACK_VEC(https_host, "https://host/", 1, 0, 4, 443,
    "https", "host", "", "", "/", "", NULL)
UC_CRACK_VEC(https_host_443, "https://host:443/", 1, 0, 4, 443,
    "https", "host", "", "", "/", "", NULL)
UC_CRACK_VEC(https_host_80, "https://host:80/", 1, 0, 4, 80,
    "https", "host", "", "", "/", "", NULL)
UC_CRACK_VEC(http_host_80, "http://host:80/", 1, 0, 3, 80,
    "http", "host", "", "", "/", "", NULL)
UC_CRACK_VEC(http_host_0, "http://host:0/", 1, 0, 3, 0,
    "http", "host", "", "", "/", "", NULL)
UC_CRACK_VEC(http_host_2, "http://host:/", 1, 0, 3, 80,
    "http", "host", "", "", "/", "", NULL)
UC_CRACK_VEC(http_host_65535, "http://host:65535/", 1, 0, 3, 65535,
    "http", "host", "", "", "/", "", NULL)
UC_CRACK_VEC(http_host_65536, "http://host:65536/", 0, 12005, 0, -1)
UC_CRACK_VEC(http_host_99999, "http://host:99999/", 0, 12005, 0, -1)
UC_CRACK_VEC(http_host_12ab, "http://host:12ab/", 0, 12005, 0, -1)
UC_CRACK_VEC(http_host_1, "http://host:-1/", 0, 12005, 0, -1)
UC_CRACK_VEC(http_host_80_2, "http://host:+80/", 0, 12005, 0, -1)
UC_CRACK_VEC(http_host_80_3, "http://host: 80/", 0, 12005, 0, -1)
UC_CRACK_VEC(http_host_0080, "http://host:0080/", 1, 0, 3, 80,
    "http", "host", "", "", "/", "", NULL)
UC_CRACK_VEC(ftp_ftp_example_com_pub_file_txt, "ftp://ftp.example.com/pub/file.txt", 1, 0, 1, 21,
    "ftp", "ftp.example.com", "", "", "/pub/file.txt", "", NULL)
UC_CRACK_VEC(ftp_user_pw_ftp_example_com_2121, "ftp://user:pw@ftp.example.com:2121/dir/", 1, 0, 1, 2121,
    "ftp", "ftp.example.com", "user", "pw", "/dir/", "", NULL)
UC_CRACK_VEC(ftp_ftp_example_com_a_type_i, "ftp://ftp.example.com/a;type=i", 1, 0, 1, 21,
    "ftp", "ftp.example.com", "", "", "/a;type=i", "", NULL)
UC_CRACK_VEC(gopher_gopher_example_com_1_x, "gopher://gopher.example.com/1/x", 1, 0, 2, 0,
    "gopher", "gopher.example.com", "", "", "/1/x", "", NULL)
UC_CRACK_VEC(gopher_gopher_example_com, "gopher://gopher.example.com", 1, 0, 2, 0,
    "gopher", "gopher.example.com", "", "", "", "", NULL)
UC_CRACK_VEC(file_c_dir_file_txt, "file:///C:/dir/file.txt", 1, 0, 5, 0,
    "file", "", "", "", "C:\\dir\\file.txt", "", NULL)
UC_CRACK_VEC(file_c_dir_file_txt_2, "file://C:/dir/file.txt", 1, 0, 5, 0,
    "file", "", "", "", "C:\\dir\\file.txt", "", NULL)
UC_CRACK_VEC(file_c_dir_file_txt_3, "file:///C|/dir/file.txt", 1, 0, 5, 0,
    "file", "", "", "", "C:\\dir\\file.txt", "", NULL)
UC_CRACK_VEC(file_server_share_file_txt, "file://server/share/file.txt", 1, 0, 5, 0,
    "file", "", "", "", "\\\\server\\share\\file.txt", "", NULL)
UC_CRACK_VEC(file_file_c_dir_file_txt, "file:C:/dir/file.txt", 0, 12006, 0, -1)
UC_CRACK_VEC(file_c_dir_20sp_file_txt, "file:///C:/dir%20sp/file.txt", 1, 0, 5, 0,
    "file", "", "", "", "C:\\dir sp\\file.txt", "", NULL)
UC_CRACK_VEC(file_c_a_b_txt_q_f, "file:///C:/a/b.txt?q#f", 1, 0, 5, 0,
    "file", "", "", "", "C:\\a\\b.txt", "?q#f", "C:\\a\\b.txt")
UC_CRACK_VEC(file_localhost_c_x_txt, "file://localhost/C:/x.txt", 1, 0, 5, 0,
    "file", "", "", "", "C:\\x.txt", "", NULL)
UC_CRACK_VEC(file_file_c_x_txt, "file:/C:/x.txt", 0, 12006, 0, -1)
UC_CRACK_VEC(mailto_mailto_someone_example_com, "mailto:someone@example.com", 1, 0, 7, 0,
    "mailto", "example.com", "someone", "", "", "", NULL)
UC_CRACK_VEC(mailto_mailto_someone_example_com_s, "mailto:someone@example.com?subject=hi", 1, 0, 7, 0,
    "mailto", "example.com", "someone", "", "", "?subject=hi", NULL)
UC_CRACK_VEC(mailto_someone_example_com, "mailto://someone@example.com", 0, 12006, 0, -1)
UC_CRACK_VEC(news_news_comp_lang_c, "news:comp.lang.c", 1, 0, 6, 0,
    "news", "", "", "", "comp.lang.c", "", NULL)
UC_CRACK_VEC(news_news_example_com_comp_lang_c, "news://news.example.com/comp.lang.c", 1, 0, 6, 0,
    "news", "news.example.com", "", "", "/comp.lang.c", "", NULL)
UC_CRACK_VEC(javascript_javascript_alert_1, "javascript:alert(1)", 1, 0, 9, 0,
    "javascript", "alert(1)", "", "", "", "", NULL)
UC_CRACK_VEC(javascript_x_y, "javascript://x/y", 0, 12006, 0, -1)
UC_CRACK_VEC(vbscript_vbscript_msgbox, "vbscript:msgbox", 1, 0, 10, 0,
    "vbscript", "msgbox", "", "", "", "", NULL)
UC_CRACK_VEC(res_shell32_dll_1_bmp, "res://shell32.dll/1.bmp", 1, 0, 11, 0,
    "res", "shell32.dll", "", "", "/1.bmp", "", NULL)
UC_CRACK_VEC(res_c_windows_x_dll_2_3, "res://C:\\windows\\x.dll/2/3", 1, 0, 11, 0,
    "res", "C:\\windows\\x.dll", "", "", "/2/3", "", NULL)
UC_CRACK_VEC(socks_proxy_1080, "socks://proxy:1080/", 0, 12006, 0, -1)
UC_CRACK_VEC(about_about_blank, "about:blank", 1, 0, -1, 0,
    "about", "", "", "", "blank", "", NULL)
UC_CRACK_VEC(foo_host_12_path_x, "foo://host:12/path?x", 1, 0, -1, 12,
    "foo", "host", "", "", "/path", "?x", NULL)
UC_CRACK_VEC(foo_foo_bar, "foo:bar", 1, 0, -1, 0,
    "foo", "", "", "", "bar", "", NULL)
UC_CRACK_VEC(foo_foo, "foo:", 1, 0, -1, 0,
    "foo", "", "", "", "", "", NULL)
UC_CRACK_VEC(x, "x:", 1, 0, -1, 0,
    "x", "", "", "", "", "", NULL)
UC_CRACK_VEC(x_2, "x:/", 1, 0, -1, 0,
    "x", "", "", "", "/", "", NULL)
UC_CRACK_VEC(a_a_b, "a:b", 1, 0, -1, 0,
    "a", "", "", "", "b", "", NULL)
UC_CRACK_VEC(http_host_example_path, "HTTP://HOST.EXAMPLE/PATH", 1, 0, 3, 80,
    "HTTP", "HOST.EXAMPLE", "", "", "/PATH", "", NULL)
UC_CRACK_VEC(https_host_2, "HtTpS://Host/", 1, 0, 4, 443,
    "HtTpS", "Host", "", "", "/", "", NULL)
UC_CRACK_VEC(ftp_h, "FTP://h/", 1, 0, 1, 21,
    "FTP", "h", "", "", "/", "", NULL)
UC_CRACK_VEC(file_c_x, "FILE:///C:/x", 1, 0, 5, 0,
    "FILE", "", "", "", "C:\\x", "", NULL)
UC_CRACK_VEC(http_1, "http://[::1]/", 1, 0, 3, 80,
    "http", "[::1]", "", "", "/", "", NULL)
UC_CRACK_VEC(http_1_8080_p, "http://[::1]:8080/p", 1, 0, 3, 8080,
    "http", "[::1]", "", "", "/p", "", NULL)
UC_CRACK_VEC(http_1_2, "http://[::1/", 0, 12005, 0, -1)
UC_CRACK_VEC(http_1_3, "http://::1/", 0, 12005, 0, -1)
UC_CRACK_VEC(http_1_2_3_4_5, "http://1.2.3.4:5/", 1, 0, 3, 5,
    "http", "1.2.3.4", "", "", "/", "", NULL)
UC_CRACK_VEC(http_host_example_x, "http://host.example./x", 1, 0, 3, 80,
    "http", "host.example.", "", "", "/x", "", NULL)
UC_CRACK_VEC(http_http_host_x, "http:/host/x", 0, 12006, 0, -1)
UC_CRACK_VEC(http_http_host_x_2, "http:host/x", 0, 12006, 0, -1)
UC_CRACK_VEC(http_http, "http:", 0, 12006, 0, -1)
UC_CRACK_VEC(http_empty, "http://", 0, 12006, 0, -1)
UC_CRACK_VEC(http_path, "http:///path", 0, 12005, 0, -1)
UC_CRACK_VEC(http_empty_2, "http:///", 0, 12005, 0, -1)
UC_CRACK_VEC(http_host_3, "http://host", 1, 0, 3, 80,
    "http", "host", "", "", "", "", NULL)
UC_CRACK_VEC(http_host_a_b_c, "http://host/a b c", 1, 0, 3, 80,
    "http", "host", "", "", "/a b c", "", NULL)
UC_CRACK_VEC(http_host_a_20b, "http://host/a%20b", 1, 0, 3, 80,
    "http", "host", "", "", "/a%20b", "", NULL)
UC_CRACK_VEC(http_host_7euser, "http://host/%7euser/", 1, 0, 3, 80,
    "http", "host", "", "", "/%7euser/", "", NULL)
UC_CRACK_VEC(http_host_p_a_20b, "http://host/p?a%20b", 1, 0, 3, 80,
    "http", "host", "", "", "/p", "?a%20b", NULL)
UC_CRACK_VEC(http_ho_st, "http://ho st/", 1, 0, 3, 80,
    "http", "ho st", "", "", "/", "", NULL)
UC_CRACK_VEC(http_host_4, "http://host\x09/", 1, 0, 3, 80,
    "http", "host\x09", "", "", "/", "", NULL)
UC_CRACK_VEC(http_http_host, " http://host/", 1, 0, -1, 0,
    " http", "host", "", "", "/", "", NULL)
UC_CRACK_VEC(http_host_5, "http://host/ ", 1, 0, 3, 80,
    "http", "host", "", "", "/ ", "", NULL)
UC_CRACK_VEC(http_host_path_x, "http://host\\path\\x", 1, 0, 3, 80,
    "http", "host\\path\\x", "", "", "", "", NULL)
UC_CRACK_VEC(http_host_path_x_2, "http://host/path\\x", 1, 0, 3, 80,
    "http", "host", "", "", "/path\\x", "", NULL)
UC_CRACK_VEC(http_host_q_path, "http://host?q/path", 1, 0, 3, 80,
    "http", "host", "", "", "", "?q/path", NULL)
UC_CRACK_VEC(http_host_f_path, "http://host#f/path", 1, 0, 3, 80,
    "http", "host", "", "", "", "#f/path", NULL)
UC_CRACK_VEC(http_host_param_x, "http://host;param/x", 1, 0, 3, 80,
    "http", "host;param", "", "", "/x", "", NULL)
UC_CRACK_VEC(http_host_param, "http://host/;param", 1, 0, 3, 80,
    "http", "host", "", "", "/;param", "", NULL)
UC_CRACK_VEC(http_user_pass, "http://user:pass@/", 0, 12005, 0, -1)
UC_CRACK_VEC(http_h_st, "http://h\xc3\xa9st/", 1, 0, 3, 80,
    "http", "h\xc3\xa9st", "", "", "/", "", NULL)
UC_CRACK_VEC(http_host_6, "http://host/\xc3\xa9", 1, 0, 3, 80,
    "http", "host", "", "", "/\xc3\xa9", "", NULL)
UC_CRACK_VEC(http_h, "hTTp://h/", 1, 0, 3, 80,
    "hTTp", "h", "", "", "/", "", NULL)
UC_CRACK_VEC(https_h_8443, "https://h:8443", 1, 0, 4, 8443,
    "https", "h", "", "", "", "", NULL)
UC_CRACK_VEC(http_host_double_slash, "http://host//double//slash", 1, 0, 3, 80,
    "http", "host", "", "", "//double//slash", "", NULL)
UC_CRACK_VEC(http_host_7, "http:////host/", 0, 12005, 0, -1)
UC_CRACK_VEC(http_host_x, "http://host/../x", 1, 0, 3, 80,
    "http", "host", "", "", "/../x", "", NULL)
UC_CRACK_VEC(http_host_x_2, "http://host/./x", 1, 0, 3, 80,
    "http", "host", "", "", "/./x", "", NULL)
UC_CRACK_VEC(nocolon_nocolon, "nocolon", 0, 12006, 0, -1)
UC_CRACK_VEC(empty, "", 0, 12006, 0, -1)
UC_CRACK_VEC(empty_2, ":", 1, 0, UC_NS_ANY, 0,
    "", "", "", "", "", "", NULL)
UC_CRACK_VEC(host, "://host/", 0, 12006, 0, -1)
UC_CRACK_VEC(1http_x, "1http://x/", 1, 0, -1, 0,
    "1http", "x", "", "", "/", "", NULL)
UC_CRACK_VEC(htdashtp_x, "ht-tp://x/", 1, 0, -1, 0,
    "ht-tp", "x", "", "", "/", "", NULL)
UC_CRACK_VEC(htplustp_x, "ht+tp://x/", 1, 0, -1, 0,
    "ht+tp", "x", "", "", "/", "", NULL)
UC_CRACK_VEC(htdottp_x, "ht.tp://x/", 1, 0, -1, 0,
    "ht.tp", "x", "", "", "/", "", NULL)
UC_CRACK_VEC(http_host_8080, "http://host:8080", 1, 0, 3, 8080,
    "http", "host", "", "", "", "", NULL)
UC_CRACK_VEC(http_user_pass_host, "http://user:pass@host", 1, 0, 3, 80,
    "http", "host", "user", "pass", "", "", NULL)
UC_CRACK_VEC(http_user_host_81, "http://user@host:81", 1, 0, 3, 81,
    "http", "host", "user", "", "", "", NULL)
UC_CRACK_VEC(ftp_h_21, "ftp://h:21/", 1, 0, 1, 21,
    "ftp", "h", "", "", "/", "", NULL)
UC_CRACK_VEC(ftp_h_0, "ftp://h:0/", 1, 0, 1, 0,
    "ftp", "h", "", "", "/", "", NULL)
UC_CRACK_VEC(https_h_65535_p, "https://h:65535/p", 1, 0, 4, 65535,
    "https", "h", "", "", "/p", "", NULL)
