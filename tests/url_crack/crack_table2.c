/* url_crack (widening pass 2): InternetCrackUrlA/W, more vectors (schemes, ports, userinfo, IPv6, host forms, query/fragment, control characters,
 * file:, mailto:, news:, javascript:, res:, opaque and unknown schemes)
 * Generated from the Win10 22H2 VM probe dump (boot ucprobe3-20261110-054841) by a throw-away generator; every row was observed on
 * genuine Windows 10 (wininet 11.0.19041.2193) and cross-read against the decomp named in EVIDENCE.md.
 * Each row: url, ok, error, nScheme, nPort, scheme, host, user, password, path, extra, path-without-extra-buffer, which
 * (0 = A and W agree and both are checked with and without an extra buffer; 1 = A only; 2 = W only).
 * W rows for non-ASCII input are separate because W lengths are characters and the inner A call sees UTF-8.
 * VM_TIMEOUT: 120 */
#include "uc.h"

UC_CRACK_VEC2(ws_h_x, "ws://h/x", 1, 0, -1, 0,
    "ws", "h", "", "", "/x", "", NULL, 0)
UC_CRACK_VEC2(wss_h_9443_x, "wss://h:9443/x", 1, 0, -1, 9443,
    "wss", "h", "", "", "/x", "", NULL, 0)
UC_CRACK_VEC2(ldap_h_dc_x_dc_y_cn_sub, "ldap://h/dc=x,dc=y?cn?sub", 1, 0, -1, 0,
    "ldap", "h", "", "", "/dc=x,dc=y", "?cn?sub", NULL, 0)
UC_CRACK_VEC2(telnet_u_p_h_23, "telnet://u:p@h:23/", 1, 0, -1, 23,
    "telnet", "h", "u", "p", "/", "", NULL, 0)
UC_CRACK_VEC2(nntp_h_group_12, "nntp://h/group/12", 1, 0, -1, 0,
    "nntp", "h", "", "", "/group/12", "", NULL, 0)
UC_CRACK_VEC2(rtsp_h_554_x, "rtsp://h:554/x", 1, 0, -1, 554,
    "rtsp", "h", "", "", "/x", "", NULL, 0)
UC_CRACK_VEC2(irc_h_chan, "irc://h/chan", 1, 0, -1, 0,
    "irc", "h", "", "", "/chan", "", NULL, 0)
UC_CRACK_VEC2(wais_h_db, "wais://h/db", 1, 0, -1, 0,
    "wais", "h", "", "", "/db", "", NULL, 0)
UC_CRACK_VEC2(prospero_h_x, "prospero://h/x", 1, 0, -1, 0,
    "prospero", "h", "", "", "/x", "", NULL, 0)
UC_CRACK_VEC2(snews_h_g, "snews://h/g", 1, 0, -1, 0,
    "snews", "h", "", "", "/g", "", NULL, 0)
UC_CRACK_VEC2(data_text_plain_abc, "data:text/plain,abc", 1, 0, -1, 0,
    "data", "", "", "", "text/plain,abc", "", NULL, 0)
UC_CRACK_VEC2(data_text_plain_base64_qq, "data:text/plain;base64,QQ==", 1, 0, -1, 0,
    "data", "", "", "", "text/plain;base64,QQ==", "", NULL, 0)
UC_CRACK_VEC2(urn_isbn_0451450523, "urn:isbn:0451450523", 1, 0, -1, 0,
    "urn", "", "", "", "isbn:0451450523", "", NULL, 0)
UC_CRACK_VEC2(tel_1_555_0100, "tel:+1-555-0100", 1, 0, -1, 0,
    "tel", "", "", "", "+1-555-0100", "", NULL, 0)
UC_CRACK_VEC2(sip_alice_h_example, "sip:alice@h.example", 1, 0, -1, 0,
    "sip", "", "", "", "alice@h.example", "", NULL, 0)
UC_CRACK_VEC2(ms_settings_display, "ms-settings:display", 1, 0, -1, 0,
    "ms-settings", "", "", "", "display", "", NULL, 0)
UC_CRACK_VEC2(shell_startup, "shell:startup", 1, 0, -1, 0,
    "shell", "", "", "", "startup", "", NULL, 0)
UC_CRACK_VEC2(view_source_http_h_x, "view-source:http://h/x", 1, 0, -1, 0,
    "view-source", "", "", "", "http://h/x", "", NULL, 0)
UC_CRACK_VEC2(about, "about:", 1, 0, -1, 0,
    "about", "", "", "", "", "", NULL, 0)
UC_CRACK_VEC2(about_h_x, "about://h/x", 1, 0, -1, 0,
    "about", "h", "", "", "/x", "", NULL, 0)
UC_CRACK_VEC2(mk_msitstore_x_chm_a_htm, "mk:@MSITStore:x.chm::/a.htm", 1, 0, -1, 0,
    "mk", "", "", "", "@MSITStore:x.chm::/a.htm", "", NULL, 0)
UC_CRACK_VEC2(its_x_chm_a_htm, "its:x.chm::/a.htm", 1, 0, -1, 0,
    "its", "", "", "", "x.chm::/a.htm", "", NULL, 0)
UC_CRACK_VEC2(cid_part1_h, "cid:part1@h", 1, 0, -1, 0,
    "cid", "", "", "", "part1@h", "", NULL, 0)
UC_CRACK_VEC2(mid_m1_h, "mid:m1@h", 1, 0, -1, 0,
    "mid", "", "", "", "m1@h", "", NULL, 0)
UC_CRACK_VEC2(outlook_inbox, "outlook:inbox", 1, 0, -1, 0,
    "outlook", "", "", "", "inbox", "", NULL, 0)
UC_CRACK_VEC2(callto_x, "callto:x", 1, 0, -1, 0,
    "callto", "", "", "", "x", "", NULL, 0)
UC_CRACK_VEC2(search_ms_query_x, "search-ms:query=x", 1, 0, -1, 0,
    "search-ms", "", "", "", "query=x", "", NULL, 0)
UC_CRACK_VEC2(gopher_h_70_1, "GOPHER://h:70/1", 1, 0, 2, 70,
    "GOPHER", "h", "", "", "/1", "", NULL, 0)
UC_CRACK_VEC2(news_h_g, "NEWS://h/g", 1, 0, 6, 0,
    "NEWS", "h", "", "", "/g", "", NULL, 0)
UC_CRACK_VEC2(javascript_x, "JAVASCRIPT:x", 1, 0, 9, 0,
    "JAVASCRIPT", "x", "", "", "", "", NULL, 0)
UC_CRACK_VEC2(vbscript_y, "VBScript:y", 1, 0, 10, 0,
    "VBScript", "y", "", "", "", "", NULL, 0)
UC_CRACK_VEC2(res_x_dll_1, "Res://x.dll/1", 1, 0, 11, 0,
    "Res", "x.dll", "", "", "/1", "", NULL, 0)
UC_CRACK_VEC2(mailto_a_b, "MAILTO:a@b", 1, 0, 7, 0,
    "MAILTO", "b", "a", "", "", "", NULL, 0)
UC_CRACK_VEC2(https_h_8443_p, "HTTPS://H:8443/P", 1, 0, 4, 8443,
    "HTTPS", "H", "", "", "/P", "", NULL, 0)
UC_CRACK_VEC2(gopher_h_70_0x, "gopher://h:70/0x", 1, 0, 2, 70,
    "gopher", "h", "", "", "/0x", "", NULL, 0)
UC_CRACK_VEC2(gopher_h_1, "gopher://h/1", 1, 0, 2, 0,
    "gopher", "h", "", "", "/1", "", NULL, 0)
UC_CRACK_VEC2(gopher_h_7070, "gopher://h:7070", 1, 0, 2, 7070,
    "gopher", "h", "", "", "", "", NULL, 0)
UC_CRACK_VEC2(gopher_u_h, "gopher://u@h/", 1, 0, 2, 0,
    "gopher", "h", "u", "", "/", "", NULL, 0)
UC_CRACK_VEC2(gopher_h_x, "gopher://h/?x", 1, 0, 2, 0,
    "gopher", "h", "", "", "/", "?x", NULL, 0)
UC_CRACK_VEC2(http_h_443, "http://h:443/", 1, 0, 3, 443,
    "http", "h", "", "", "/", "", NULL, 0)
UC_CRACK_VEC2(https_h_8080, "https://h:8080/", 1, 0, 4, 8080,
    "https", "h", "", "", "/", "", NULL, 0)
UC_CRACK_VEC2(ftp_h_80, "ftp://h:80/", 1, 0, 1, 80,
    "ftp", "h", "", "", "/", "", NULL, 0)
UC_CRACK_VEC2(http_h_00000, "http://h:00000/", 1, 0, 3, 0,
    "http", "h", "", "", "/", "", NULL, 0)
UC_CRACK_VEC2(http_h_65535, "http://h:65535", 1, 0, 3, 65535,
    "http", "h", "", "", "", "", NULL, 0)
UC_CRACK_VEC2(http_h_80_x, "http://h:80?x", 1, 0, 3, 80,
    "http", "h", "", "", "", "?x", NULL, 0)
UC_CRACK_VEC2(http_h_80_f, "http://h:80#f", 1, 0, 3, 80,
    "http", "h", "", "", "", "#f", NULL, 0)
UC_CRACK_VEC2(ftp_h_21_x, "ftp://h:21?x", 1, 0, 1, 21,
    "ftp", "h", "", "", "", "?x", NULL, 0)
UC_CRACK_VEC2(http_h_1_2, "http://h:1:2/", 0, 12005, 0, -1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0)
UC_CRACK_VEC2(http_h_80, "http://h::80/", 0, 12005, 0, -1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0)
UC_CRACK_VEC2(http_h_8_0, "http://h:8 0/", 0, 12005, 0, -1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0)
UC_CRACK_VEC2(http_h_80_2, "http://h:\x09" "80/", 0, 12005, 0, -1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0)
UC_CRACK_VEC2(http_h_80_3, "http://h:80\x09/", 0, 12005, 0, -1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0)
UC_CRACK_VEC2(http_h_12345678901234567890, "http://h:12345678901234567890/", 0, 12005, 0, -1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0)
UC_CRACK_VEC2(http_h_0000000000080, "http://h:0000000000080/", 1, 0, 3, 80,
    "http", "h", "", "", "/", "", NULL, 0)
UC_CRACK_VEC2(http_u_h, "http://u@h:/", 1, 0, 3, 80,
    "http", "h", "u", "", "/", "", NULL, 0)
UC_CRACK_VEC2(foo_h_0, "foo://h:0/", 1, 0, -1, 0,
    "foo", "h", "", "", "/", "", NULL, 0)
UC_CRACK_VEC2(foo_h_65536, "foo://h:65536/", 0, 12005, 0, -1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0)
UC_CRACK_VEC2(foo_h_x, "foo://h:x/", 0, 12005, 0, -1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0)
UC_CRACK_VEC2(news_h_119_g, "news://h:119/g", 1, 0, 6, 119,
    "news", "h", "", "", "/g", "", NULL, 0)
UC_CRACK_VEC2(res_x_dll_12_a, "res://x.dll:12/a", 1, 0, 11, 0,
    "res", "x.dll:12", "", "", "/a", "", NULL, 0)
UC_CRACK_VEC2(http_u_40x_h, "http://u%40x@h/", 1, 0, 3, 80,
    "http", "h", "u@x", "", "/", "", NULL, 0)
UC_CRACK_VEC2(http_user_p_ss_h, "http://user:p@ss@h/", 1, 0, 3, 80,
    "http", "ss@h", "user", "p", "/", "", NULL, 0)
UC_CRACK_VEC2(http_u_p_q_h, "http://u:p:q@h/", 0, 12005, 0, -1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0)
UC_CRACK_VEC2(http_h, "http://:@h/", 1, 0, 3, 80,
    "http", "h", "", "", "/", "", NULL, 0)
UC_CRACK_VEC2(http_u_p_h, "http://u:p@h:/", 1, 0, 3, 80,
    "http", "h", "u", "p", "/", "", NULL, 0)
UC_CRACK_VEC2(ftp_anonymous_me_h, "ftp://anonymous:me@h/", 1, 0, 1, 21,
    "ftp", "h", "anonymous", "me", "/", "", NULL, 0)
UC_CRACK_VEC2(http_us_er_h, "http://us er@h/", 1, 0, 3, 80,
    "http", "h", "us er", "", "/", "", NULL, 0)
UC_CRACK_VEC2(http_u_p_h_2, "http://u;p@h/", 1, 0, 3, 80,
    "http", "h", "u;p", "", "/", "", NULL, 0)
UC_CRACK_VEC2(http_u_x_h, "http://u?x@h/", 1, 0, 3, 80,
    "http", "u", "", "", "", "?x@h/", NULL, 0)
UC_CRACK_VEC2(http_u_x_h_2, "http://u#x@h/", 1, 0, 3, 80,
    "http", "u", "", "", "", "#x@h/", NULL, 0)
UC_CRACK_VEC2(http_u_x_h_3, "http://u/x@h/", 1, 0, 3, 80,
    "http", "u", "", "", "/x@h/", "", NULL, 0)
UC_CRACK_VEC2(http_u_p_h_81_q, "http://u:p@h:81/?q", 1, 0, 3, 81,
    "http", "h", "u", "p", "/", "?q", NULL, 0)
UC_CRACK_VEC2(http_u_3ap_h, "http://u%3Ap@h/", 1, 0, 3, 80,
    "http", "h", "u:p", "", "/", "", NULL, 0)
UC_CRACK_VEC2(http_u_p_40q_h, "http://u:p%40q@h/", 1, 0, 3, 80,
    "http", "h", "u", "p@q", "/", "", NULL, 0)
UC_CRACK_VEC2(http_75_70_h, "http://%75:%70@h/", 1, 0, 3, 80,
    "http", "h", "u", "p", "/", "", NULL, 0)
UC_CRACK_VEC2(http_u_h_81, "http://u:@h:81", 1, 0, 3, 81,
    "http", "h", "u", "", "", "", NULL, 0)
UC_CRACK_VEC2(http_81, "http://@:81/", 0, 12005, 0, -1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0)
UC_CRACK_VEC2(http_u, "http://u@/", 0, 12005, 0, -1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0)
UC_CRACK_VEC2(http, "http://@/", 0, 12005, 0, -1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0)
UC_CRACK_VEC2(https_user_h, "https://user@h/", 1, 0, 4, 443,
    "https", "h", "user", "", "/", "", NULL, 0)
UC_CRACK_VEC2(foo_u_p_h_1_p_q_f, "foo://u:p@h:1/p?q#f", 1, 0, -1, 1,
    "foo", "h", "u", "p", "/p", "?q#f", NULL, 0)
UC_CRACK_VEC2(http_1, "http://[::1]:/", 1, 0, 3, 80,
    "http", "[::1]", "", "", "/", "", NULL, 0)
UC_CRACK_VEC2(http_ffff_127_0_0_1, "http://[::ffff:127.0.0.1]/", 1, 0, 3, 80,
    "http", "[::ffff:127.0.0.1]", "", "", "/", "", NULL, 0)
UC_CRACK_VEC2(http_2001_db8_1_8080_a_b, "http://[2001:db8::1]:8080/a?b", 1, 0, 3, 8080,
    "http", "[2001:db8::1]", "", "", "/a", "?b", NULL, 0)
UC_CRACK_VEC2(http_1_x, "http://[::1]x/", 0, 12005, 0, -1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0)
UC_CRACK_VEC2(http_2, "http://[]/", 1, 0, 3, 80,
    "http", "[]", "", "", "/", "", NULL, 0)
UC_CRACK_VEC2(http_1_99999, "http://[::1]:99999/", 0, 12005, 0, -1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0)
UC_CRACK_VEC2(https_1, "https://[::1]", 1, 0, 4, 443,
    "https", "[::1]", "", "", "", "", NULL, 0)
UC_CRACK_VEC2(ftp_1, "ftp://[::1]/", 1, 0, 1, 21,
    "ftp", "[::1]", "", "", "/", "", NULL, 0)
UC_CRACK_VEC2(http_u_1, "http://u@[::1]/", 1, 0, 3, 80,
    "http", "[::1]", "u", "", "/", "", NULL, 0)
UC_CRACK_VEC2(http_u_p_1_81, "http://u:p@[::1]:81/", 1, 0, 3, 81,
    "http", "[::1]", "u", "p", "/", "", NULL, 0)
UC_CRACK_VEC2(http_1_2_3_4_5_6_7_8, "http://[1:2:3:4:5:6:7:8]/", 1, 0, 3, 80,
    "http", "[1:2:3:4:5:6:7:8]", "", "", "/", "", NULL, 0)
UC_CRACK_VEC2(http_1_2, "http://[::1]]/", 0, 12005, 0, -1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0)
UC_CRACK_VEC2(http_3, "http://[:::]/", 1, 0, 3, 80,
    "http", "[:::]", "", "", "/", "", NULL, 0)
UC_CRACK_VEC2(http_1_x_2, "http://[::1]/?x", 1, 0, 3, 80,
    "http", "[::1]", "", "", "/", "?x", NULL, 0)
UC_CRACK_VEC2(http_1_f, "http://[::1]#f", 0, 12005, 0, -1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0)
UC_CRACK_VEC2(http_v1_x, "http://[v1.x]/", 1, 0, 3, 80,
    "http", "[v1.x]", "", "", "/", "", NULL, 0)
UC_CRACK_VEC2(http_127_1, "http://127.1/", 1, 0, 3, 80,
    "http", "127.1", "", "", "/", "", NULL, 0)
UC_CRACK_VEC2(http_0x7f_1, "http://0x7f.1/", 1, 0, 3, 80,
    "http", "0x7f.1", "", "", "/", "", NULL, 0)
UC_CRACK_VEC2(http_68ost, "http://%68ost/", 1, 0, 3, 80,
    "http", "host", "", "", "/", "", NULL, 0)
UC_CRACK_VEC2(http_h_2fx, "http://h%2fx/", 1, 0, 3, 80,
    "http", "h/x", "", "", "/", "", NULL, 0)
UC_CRACK_VEC2(http_h_o_st, "http://H_O-ST/", 1, 0, 3, 80,
    "http", "H_O-ST", "", "", "/", "", NULL, 0)
UC_CRACK_VEC2(http_h_2, "http://-h-/", 1, 0, 3, 80,
    "http", "-h-", "", "", "/", "", NULL, 0)
UC_CRACK_VEC2(http_h_3, "http://h./", 1, 0, 3, 80,
    "http", "h.", "", "", "/", "", NULL, 0)
UC_CRACK_VEC2(http_h_4, "http://.h/", 1, 0, 3, 80,
    "http", ".h", "", "", "/", "", NULL, 0)
UC_CRACK_VEC2(http_h_x, "http://h..x/", 1, 0, 3, 80,
    "http", "h..x", "", "", "/", "", NULL, 0)
UC_CRACK_VEC2(http_a_b_c_d_e_f, "http://a.b.c.d.e.f/", 1, 0, 3, 80,
    "http", "a.b.c.d.e.f", "", "", "/", "", NULL, 0)
UC_CRACK_VEC2(http_h_80_81, "http://h:80:81/", 0, 12005, 0, -1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0)
UC_CRACK_VEC2(http_1_80_81, "http://[::1]:80:81/", 0, 12005, 0, -1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0)
UC_CRACK_VEC2(http_h_20x, "http://h%20x/", 1, 0, 3, 80,
    "http", "h x", "", "", "/", "", NULL, 0)
UC_CRACK_VEC2(http_h_5, "http://h%/", 0, 12005, 0, -1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0)
UC_CRACK_VEC2(http_h_4_2, "http://h%4/", 0, 12005, 0, -1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0)
UC_CRACK_VEC2(http_h_zz, "http://h%zz/", 0, 12005, 0, -1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0)
UC_CRACK_VEC2(http_h_6, "http://h/?", 1, 0, 3, 80,
    "http", "h", "", "", "/", "?", NULL, 0)
UC_CRACK_VEC2(http_h_7, "http://h/#", 1, 0, 3, 80,
    "http", "h", "", "", "/", "#", NULL, 0)
UC_CRACK_VEC2(http_h_8, "http://h?", 1, 0, 3, 80,
    "http", "h", "", "", "", "?", NULL, 0)
UC_CRACK_VEC2(http_h_9, "http://h#", 1, 0, 3, 80,
    "http", "h", "", "", "", "#", NULL, 0)
UC_CRACK_VEC2(http_h_a_b_c, "http://h/a?b?c", 1, 0, 3, 80,
    "http", "h", "", "", "/a", "?b?c", NULL, 0)
UC_CRACK_VEC2(http_h_a_b_c_2, "http://h/a#b#c", 1, 0, 3, 80,
    "http", "h", "", "", "/a", "#b#c", NULL, 0)
UC_CRACK_VEC2(http_h_a_b_c_d, "http://h/a?b#c?d", 1, 0, 3, 80,
    "http", "h", "", "", "/a", "?b#c?d", NULL, 0)
UC_CRACK_VEC2(http_h_8080_q, "http://h:8080?q", 1, 0, 3, 8080,
    "http", "h", "", "", "", "?q", NULL, 0)
UC_CRACK_VEC2(http_h_8080_f, "http://h:8080#f", 1, 0, 3, 8080,
    "http", "h", "", "", "", "#f", NULL, 0)
UC_CRACK_VEC2(http_h_10, "http://h/?#", 1, 0, 3, 80,
    "http", "h", "", "", "/", "?#", NULL, 0)
UC_CRACK_VEC2(http_h_11, "http://h/;?", 1, 0, 3, 80,
    "http", "h", "", "", "/;", "?", NULL, 0)
UC_CRACK_VEC2(http_h_a_b_c_d_e_f, "http://h/a;b?c;d#e;f", 1, 0, 3, 80,
    "http", "h", "", "", "/a;b", "?c;d#e;f", NULL, 0)
UC_CRACK_VEC2(http_h_3f_x, "http://h/%3F?x", 1, 0, 3, 80,
    "http", "h", "", "", "/%3F", "?x", NULL, 0)
UC_CRACK_VEC2(http_h_23_x, "http://h/%23#x", 1, 0, 3, 80,
    "http", "h", "", "", "/%23", "#x", NULL, 0)
UC_CRACK_VEC2(http_h_a_b_c_3, "http://h/a/b/c/", 1, 0, 3, 80,
    "http", "h", "", "", "/a/b/c/", "", NULL, 0)
UC_CRACK_VEC2(http_h_a_b_c_4, "http://h/a/./b/../c", 1, 0, 3, 80,
    "http", "h", "", "", "/a/./b/../c", "", NULL, 0)
UC_CRACK_VEC2(http_h_u, "http://h/~u/", 1, 0, 3, 80,
    "http", "h", "", "", "/~u/", "", NULL, 0)
UC_CRACK_VEC2(http_h_a_2fb, "http://h/a%2Fb", 1, 0, 3, 80,
    "http", "h", "", "", "/a%2Fb", "", NULL, 0)
UC_CRACK_VEC2(http_h_a_b, "http://h/a+b", 1, 0, 3, 80,
    "http", "h", "", "", "/a+b", "", NULL, 0)
UC_CRACK_VEC2(http_h_a_b_c_5, "http://h/a&b=c", 1, 0, 3, 80,
    "http", "h", "", "", "/a&b=c", "", NULL, 0)
UC_CRACK_VEC2(http_h_a_b_2, "http://h/a@b", 1, 0, 3, 80,
    "http", "h", "", "", "/a@b", "", NULL, 0)
UC_CRACK_VEC2(http_h_a_b_3, "http://h/a:b", 1, 0, 3, 80,
    "http", "h", "", "", "/a:b", "", NULL, 0)
UC_CRACK_VEC2(http_h_a_b_c_d_2, "http://h/?a=b&c=d", 1, 0, 3, 80,
    "http", "h", "", "", "/", "?a=b&c=d", NULL, 0)
UC_CRACK_VEC2(http_h_a_b_4, "http://h/?a@b", 1, 0, 3, 80,
    "http", "h", "", "", "/", "?a@b", NULL, 0)
UC_CRACK_VEC2(http_h_a_b_5, "http://h/#a@b", 1, 0, 3, 80,
    "http", "h", "", "", "/", "#a@b", NULL, 0)
UC_CRACK_VEC2(http_h_a_b_c_6, "http://h/?a:b@c", 1, 0, 3, 80,
    "http", "h", "", "", "/", "?a:b@c", NULL, 0)
UC_CRACK_VEC2(http_h_a_b_c_d_3, "http://h/a?b/c@d", 1, 0, 3, 80,
    "http", "h", "", "", "/a", "?b/c@d", NULL, 0)
UC_CRACK_VEC2(http_h_12, "http://h/\xe4\xb8\xad?\xc3\xa9#\xc3\xa9", 1, 0, 3, 80,
    "http", "h", "", "", "/\xe4\xb8\xad", "?\xc3\xa9#\xc3\xa9", NULL, 0)
UC_CRACK_VEC2(http_h_a_b_6, "http://h/a\x0d\x0a" "b", 1, 0, 3, 80,
    "http", "h", "", "", "/a\x0d\x0a" "b", "", NULL, 0)
UC_CRACK_VEC2(http_h_13, "\x09http://h/", 1, 0, -1, 0,
    "\x09http", "h", "", "", "/", "", NULL, 0)
UC_CRACK_VEC2(http_h_14, "http://h/\x01", 1, 0, 3, 80,
    "http", "h", "", "", "/\x01", "", NULL, 0)
UC_CRACK_VEC2(http_h_15, "http:// h/", 1, 0, 3, 80,
    "http", " h", "", "", "/", "", NULL, 0)
UC_CRACK_VEC2(http_h_16, "http ://h/", 1, 0, -1, 0,
    "http ", "h", "", "", "/", "", NULL, 0)
UC_CRACK_VEC2(http_h_17, "http://h/\x09", 1, 0, 3, 80,
    "http", "h", "", "", "/\x09", "", NULL, 0)
UC_CRACK_VEC2(http_h_a_b_c_d_e_f_2, "http://h/a b?c d#e f", 1, 0, 3, 80,
    "http", "h", "", "", "/a b", "?c d#e f", NULL, 0)
UC_CRACK_VEC2(http_h_18, "  http://h/", 1, 0, -1, 0,
    "  http", "h", "", "", "/", "", NULL, 0)
UC_CRACK_VEC2(http_h_19, "http://h /", 1, 0, 3, 80,
    "http", "h ", "", "", "/", "", NULL, 0)
UC_CRACK_VEC2(http_h_a_b_7, "http://h/a\x7f" "b", 1, 0, 3, 80,
    "http", "h", "", "", "/a\x7f" "b", "", NULL, 0)
UC_CRACK_VEC2(http_h_20, "HTTP://h/\x0b", 1, 0, 3, 80,
    "HTTP", "h", "", "", "/\x0b", "", NULL, 0)
UC_CRACK_VEC2(file_c_x, "file:///c:/x", 1, 0, 5, 0,
    "file", "", "", "", "c:\\x", "", NULL, 0)
UC_CRACK_VEC2(file_c, "file:///C:", 1, 0, 5, 0,
    "file", "", "", "", "C:", "", NULL, 0)
UC_CRACK_VEC2(file_c_2, "file:///C:/", 1, 0, 5, 0,
    "file", "", "", "", "C:\\", "", NULL, 0)
UC_CRACK_VEC2(file_c_a_b, "file:///C:/a/b/", 1, 0, 5, 0,
    "file", "", "", "", "C:\\a\\b\\", "", NULL, 0)
UC_CRACK_VEC2(file_server_share_x, "file:////server/share/x", 1, 0, 5, 0,
    "file", "", "", "", "\\\\server\\share\\x", "", NULL, 0)
UC_CRACK_VEC2(file_server_share, "file://///server/share", 1, 0, 5, 0,
    "file", "", "", "", "\\\\server\\share", "", NULL, 0)
UC_CRACK_VEC2(file_server_share_2, "file:///\\\\server\\share", 1, 0, 5, 0,
    "file", "", "", "", "\\\\server\\share", "", NULL, 0)
UC_CRACK_VEC2(file_c_x_2, "file://C|/x", 1, 0, 5, 0,
    "file", "", "", "", "C:\\x", "", NULL, 0)
UC_CRACK_VEC2(file_c_a_2fb, "file:///C:/a%2fb", 1, 0, 5, 0,
    "file", "", "", "", "C:\\a/b", "", NULL, 0)
UC_CRACK_VEC2(file_c_a_b_2, "file:///C:/a?b", 1, 0, 5, 0,
    "file", "", "", "", "C:\\a", "?b", "C:\\a", 0)
UC_CRACK_VEC2(file_c_a_b_3, "file:///C:/a#b", 1, 0, 5, 0,
    "file", "", "", "", "C:\\a#b", "#b", "C:\\a#b", 0)
UC_CRACK_VEC2(file_etc_passwd, "file:///etc/passwd", 1, 0, 5, 0,
    "file", "", "", "", "\\etc\\passwd", "", NULL, 0)
UC_CRACK_VEC2(file_x, "file:///x", 1, 0, 5, 0,
    "file", "", "", "", "\\x", "", NULL, 0)
UC_CRACK_VEC2(file_h, "file://h/", 1, 0, 5, 0,
    "file", "", "", "", "\\\\h", "", NULL, 0)
UC_CRACK_VEC2(file_localhost_etc, "file://localhost/etc", 1, 0, 5, 0,
    "file", "", "", "", "\\etc", "", NULL, 0)
UC_CRACK_VEC2(file, "file:", 0, 12006, 0, -1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0)
UC_CRACK_VEC2(file_2, "file://", 0, 12006, 0, -1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0)
UC_CRACK_VEC2(file_3, "file:///", 0, 87, 0, -1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 1)
UC_CRACK_VEC2(file_3_w, "file:///", 0, 87, 0, -1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 2)
UC_CRACK_VEC2(file_server_x, "FILE://server/x", 1, 0, 5, 0,
    "FILE", "", "", "", "\\\\server\\x", "", NULL, 0)
UC_CRACK_VEC2(file_c_a_b_4, "file:///C:/a/../b", 1, 0, 5, 0,
    "file", "", "", "", "C:\\a\\..\\b", "", NULL, 0)
UC_CRACK_VEC2(file_c_e9, "file:///C:/%E9", 1, 0, 5, 0,
    "file", "", "", "", "C:\\\xe9", "", NULL, 1)
UC_CRACK_VEC2(file_c_a_b_5, "file:///C:/a+b", 1, 0, 5, 0,
    "file", "", "", "", "C:\\a+b", "", NULL, 0)
UC_CRACK_VEC2(file_c_a_b_txt, "file://C:\\a\\b.txt", 1, 0, 5, 0,
    "file", "", "", "", "C:\\a\\b.txt", "", NULL, 0)
UC_CRACK_VEC2(file_c_a_b_txt_2, "file:///C:\\a\\b.txt", 1, 0, 5, 0,
    "file", "", "", "", "C:\\a\\b.txt", "", NULL, 0)
UC_CRACK_VEC2(file_c_a_20b_20c_d, "file:///C:/a%20b%20c/d", 1, 0, 5, 0,
    "file", "", "", "", "C:\\a b c\\d", "", NULL, 0)
UC_CRACK_VEC2(file_localhost_c_x, "file://localhost/C|/x", 1, 0, 5, 0,
    "file", "", "", "", "C:\\x", "", NULL, 0)
UC_CRACK_VEC2(file_u_p_server_share, "file://u:p@server/share", 1, 0, 5, 0,
    "file", "", "", "", "u:p@server\\share", "", NULL, 0)
UC_CRACK_VEC2(file_server_81_share, "file://server:81/share", 1, 0, 5, 0,
    "file", "", "", "", "\\\\server:81\\share", "", NULL, 0)
UC_CRACK_VEC2(file_c_a_b_6, "file:///C:/a;b", 1, 0, 5, 0,
    "file", "", "", "", "C:\\a;b", "", NULL, 0)
UC_CRACK_VEC2(file_c_a_b_txt_3, "file:///C:/a/b.txt?", 1, 0, 5, 0,
    "file", "", "", "", "C:\\a\\b.txt", "?", "C:\\a\\b.txt", 0)
UC_CRACK_VEC2(mailto, "mailto:", 1, 0, 7, 0,
    "mailto", "", "", "", "", "", NULL, 0)
UC_CRACK_VEC2(mailto_a, "mailto:a", 1, 0, 7, 0,
    "mailto", "a", "", "", "", "", NULL, 0)
UC_CRACK_VEC2(mailto_h, "mailto:@h", 1, 0, 7, 0,
    "mailto", "h", "", "", "", "", NULL, 0)
UC_CRACK_VEC2(mailto_a_2, "mailto:a@", 1, 0, 7, 0,
    "mailto", "", "a", "", "", "", NULL, 0)
UC_CRACK_VEC2(mailto_a_b_c, "mailto:a@b@c", 1, 0, 7, 0,
    "mailto", "b@c", "a", "", "", "", NULL, 0)
UC_CRACK_VEC2(mailto_a_b_c_2, "mailto:a:b@c", 1, 0, 7, 0,
    "mailto", "c", "a", "b", "", "", NULL, 0)
UC_CRACK_VEC2(mailto_a_b_25, "mailto:a@b:25", 1, 0, 7, 25,
    "mailto", "b", "a", "", "", "", NULL, 0)
UC_CRACK_VEC2(mailto_a_b_x, "mailto:a@b/x", 1, 0, 7, 0,
    "mailto", "b", "a", "", "/x", "", NULL, 0)
UC_CRACK_VEC2(mailto_a_b_f, "mailto:a@b#f", 1, 0, 7, 0,
    "mailto", "b", "a", "", "", "#f", NULL, 0)
UC_CRACK_VEC2(mailto_a_b_c_3, "mailto:a,b@c", 1, 0, 7, 0,
    "mailto", "c", "a,b", "", "", "", NULL, 0)
UC_CRACK_VEC2(mailto_a_b_cc_c_d_subject_x_y, "mailto:a@b?cc=c@d&subject=x y", 1, 0, 7, 0,
    "mailto", "b", "a", "", "", "?cc=c@d&subject=x y", NULL, 0)
UC_CRACK_VEC2(mailto_a_40b_c, "mailto:a%40b@c", 1, 0, 7, 0,
    "mailto", "c", "a@b", "", "", "", NULL, 0)
UC_CRACK_VEC2(news, "news:", 1, 0, 6, 0,
    "news", "", "", "", "", "", NULL, 0)
UC_CRACK_VEC2(news_a_b, "news:a@b", 1, 0, 6, 0,
    "news", "", "", "", "a@b", "", NULL, 0)
UC_CRACK_VEC2(news_h, "news://h", 1, 0, 6, 0,
    "news", "h", "", "", "", "", NULL, 0)
UC_CRACK_VEC2(news_a_b_c, "news:a/b?c", 1, 0, 6, 0,
    "news", "", "", "", "a/b", "?c", NULL, 0)
UC_CRACK_VEC2(javascript, "javascript:", 1, 0, 9, 0,
    "javascript", "", "", "", "", "", NULL, 0)
UC_CRACK_VEC2(javascript_void_0, "javascript:void(0);", 1, 0, 9, 0,
    "javascript", "void(0);", "", "", "", "", NULL, 0)
UC_CRACK_VEC2(javascript_a_b, "javascript:a/b", 1, 0, 9, 0,
    "javascript", "a", "", "", "/b", "", NULL, 0)
UC_CRACK_VEC2(javascript_a_b_2, "javascript:a?b", 1, 0, 9, 0,
    "javascript", "a", "", "", "", "?b", NULL, 0)
UC_CRACK_VEC2(javascript_a_b_3, "javascript:a@b", 1, 0, 9, 0,
    "javascript", "b", "a", "", "", "", NULL, 0)
UC_CRACK_VEC2(javascript_a_b_4, "javascript:a:b", 0, 12005, 0, -1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0)
UC_CRACK_VEC2(javascript_a_b_5, "javascript:a#b", 1, 0, 9, 0,
    "javascript", "a", "", "", "", "#b", NULL, 0)
UC_CRACK_VEC2(vbscript, "vbscript:", 1, 0, 10, 0,
    "vbscript", "", "", "", "", "", NULL, 0)
UC_CRACK_VEC2(vbscript_a_b, "vbscript:a b", 1, 0, 10, 0,
    "vbscript", "a b", "", "", "", "", NULL, 0)
UC_CRACK_VEC2(res_x_dll, "res://x.dll", 1, 0, 11, 0,
    "res", "x.dll", "", "", "", "", NULL, 0)
UC_CRACK_VEC2(res_x_dll_2_101, "res://x.dll/#2/#101", 1, 0, 11, 0,
    "res", "x.dll", "", "", "/", "#2/#101", NULL, 0)
UC_CRACK_VEC2(res_x, "res:x", 0, 12006, 0, -1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0)
UC_CRACK_VEC2(res_c_x_dll_a, "res://C:/x.dll/a", 1, 0, 11, 0,
    "res", "C:", "", "", "/x.dll/a", "", NULL, 0)
UC_CRACK_VEC2(res_x_dll_a_b_c, "res://x.dll/a?b#c", 1, 0, 11, 0,
    "res", "x.dll", "", "", "/a", "?b#c", NULL, 0)
UC_CRACK_VEC2(foo_x, "foo:/x", 1, 0, -1, 0,
    "foo", "", "", "", "/x", "", NULL, 0)
UC_CRACK_VEC2(foo_x_2, "foo:///x", 1, 0, -1, 0,
    "foo", "", "", "", "/x", "", NULL, 0)
UC_CRACK_VEC2(foo, "foo://", 1, 0, -1, 0,
    "foo", "", "", "", "//", "", NULL, 0)
UC_CRACK_VEC2(foo_x_3, "foo:?x", 1, 0, -1, 0,
    "foo", "", "", "", "", "?x", NULL, 0)
UC_CRACK_VEC2(foo_x_4, "foo:#x", 1, 0, -1, 0,
    "foo", "", "", "", "", "#x", NULL, 0)
UC_CRACK_VEC2(x_y_z_w_h, "x-y.z+w://h/", 1, 0, -1, 0,
    "x-y.z+w", "h", "", "", "/", "", NULL, 0)
UC_CRACK_VEC2(a_b_h, "a_b://h/", 1, 0, -1, 0,
    "a_b", "h", "", "", "/", "", NULL, 0)
UC_CRACK_VEC2(9ab_h, "9ab://h/", 1, 0, -1, 0,
    "9ab", "h", "", "", "/", "", NULL, 0)
UC_CRACK_VEC2(abcdefghijklmnopqrstuvwxyzabcdefghijklmn, "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789ab://h/", 1, 0, -1, 0,
    "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789ab", "h", "", "", "/", "", NULL, 0)
UC_CRACK_VEC2(foo_h_x_2, "foo:\\\\h\\x", 1, 0, -1, 0,
    "foo", "", "", "", "\\\\h\\x", "", NULL, 0)
UC_CRACK_VEC2(foo_h_x_y, "foo://h\\x/y", 1, 0, -1, 0,
    "foo", "h\\x", "", "", "/y", "", NULL, 0)
UC_CRACK_VEC2(ftp_h_a_b, "ftp://h/a b", 1, 0, 1, 21,
    "ftp", "h", "", "", "/a b", "", NULL, 0)
UC_CRACK_VEC2(ftp_h_2fetc, "ftp://h/%2Fetc", 1, 0, 1, 21,
    "ftp", "h", "", "", "/%2Fetc", "", NULL, 0)
UC_CRACK_VEC2(ftp_h_a_type_a, "ftp://h/a;type=a", 1, 0, 1, 21,
    "ftp", "h", "", "", "/a;type=a", "", NULL, 0)
UC_CRACK_VEC2(ftp_h_a_type_d_x, "ftp://h/a;type=d?x", 1, 0, 1, 21,
    "ftp", "h", "", "", "/a;type=d", "?x", NULL, 0)
UC_CRACK_VEC2(ftp_u_h_21, "ftp://u@h:21", 1, 0, 1, 21,
    "ftp", "h", "u", "", "", "", NULL, 0)
