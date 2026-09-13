// httplogin.cpp (level 1/2 都登录,20秒超时兜底,无控制台窗口, 只写日志)
// 纯 HTTP 登录校园网 (锐捷 ePortal / RG-SAM+)
// 日志: 与 exe 同目录的 httplogin_log.txt
//下面用法是cmd的好像，我没试过，比较懒
// 用法: httplogin.exe [账号] [密码]
// 编译: cl /std:c++20 /EHsc /O2 /utf-8 httplogin.cpp /I <cppwinrt> /Fe:... /link /SUBSYSTEM:WINDOWS
#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif
#include <windows.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <winrt/base.h>
#include <winrt/Windows.Networking.Connectivity.h>

#pragma comment(lib, "WindowsApp.lib")
#pragma comment(lib, "winhttp.lib")

// 无控制台窗口: GUI 子系统 + 保留 wmain 作为入口
#pragma comment(linker, "/SUBSYSTEM:WINDOWS")
#pragma comment(linker, "/ENTRY:wmainCRTStartup")

static const wchar_t* TRIGGER_URLS[] = {
    L"http://9.9.9.9/",
    L"http://223.5.5.5/",
    L"http://114.114.114.114/",
};
// 登录接口兜底地址: 优先用劫持返回的门户地址, 见 ExtractOrigin
static const char* LOGIN_FALLBACK = "http://10.110.141.3/eportal/InterFace.do?method=login";

static std::wstring g_user;   // 从 exe 同目录 auth.txt 或命令行读取
static std::wstring g_pass;

// 日志 (只写文件, 不弹控制台)
static FILE* g_log = NULL;

// 取 exe 自身所在目录 (不含末尾反斜杠) —— 让程序可以整体挪走
static std::wstring GetExeDir()
{
    wchar_t buf[MAX_PATH] = { 0 };
    DWORD n = GetModuleFileNameW(NULL, buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return L".";
    std::wstring p(buf, n);
    size_t s = p.find_last_of(L"\\/");
    return (s == std::wstring::npos) ? L"." : p.substr(0, s);
}

static void LogInit()
{
    std::wstring p = GetExeDir() + L"\\httplogin_log.txt";
    _wfopen_s(&g_log, p.c_str(), L"wb");   // 二进制: 避免 ccs=UTF-8 转中文崩溃
}

static void Log(const char* fmt, ...)
{
    char buf[4096];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (!g_log) return;

    SYSTEMTIME st; GetLocalTime(&st);
    const char* p = buf;
    while (*p) {
        const char* nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p + 1) : strlen(p);
        if (!(len == 1 && *p == '\n'))   // 空行不加时间戳
            fprintf(g_log, "[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
        fwrite(p, 1, len, g_log);
        if (!nl) break;
        p = nl + 1;
    }
    fflush(g_log);
}

// 全局崩溃处理器: 崩溃时把原因写进日志, 避免"程序静默消失、日志莫名中断"
// 注意: 崩溃时堆可能已损坏, 这里只用最简单的 snprintf + fwrite, 不调用 Log()
static LONG WINAPI CrashHandler(EXCEPTION_POINTERS* ep)
{
    if (g_log) {
        DWORD code = (ep && ep->ExceptionRecord) ? ep->ExceptionRecord->ExceptionCode : 0;
        void* addr = (ep && ep->ExceptionRecord) ? ep->ExceptionRecord->ExceptionAddress : nullptr;
        char buf[512];
        int n = snprintf(buf, sizeof(buf),
            "\n[崩溃] 未处理异常! 异常代码=0x%08lX 出错地址=%p 线程=%lu\n"
            "       请把本日志发给开发者\n",
            (unsigned long)code, addr, (unsigned long)GetCurrentThreadId());
        if (n > 0) {
            if (n > (int)sizeof(buf) - 1) n = (int)sizeof(buf) - 1;
            fwrite(buf, 1, (size_t)n, g_log);
            fflush(g_log);
        }
        fclose(g_log);
        g_log = NULL;
    }
    return EXCEPTION_EXECUTE_HANDLER;   // 记完就结束, 不弹系统错误窗
}
// 20 秒超时兜底
static DWORD WINAPI TimeoutProc(LPVOID)
{
    Sleep(20000);
    Log("\n[超时] 程序运行超过 20 秒, 强制退出\n");
    if (g_log) { fclose(g_log); g_log = NULL; }
    ExitProcess(0);
    return 0;
}

// 编码
static std::string ToUtf8(const std::wstring& w)
{
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), NULL, 0, NULL, NULL);
    std::string s((size_t)n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), &s[0], n, NULL, NULL);
    return s;
}

static std::wstring ToW(const std::string& s)
{
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), NULL, 0);
    std::wstring w((size_t)n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], n);
    return w;
}

static std::string UrlEncode(const std::string& s)
{
    static const char* hex = "0123456789ABCDEF";
    std::string o;
    for (size_t i = 0; i < s.size(); i++) {
        unsigned char c = (unsigned char)s[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
            || c=='-' || c=='_' || c=='.' || c=='!' || c=='~' || c=='*' || c=='\'' || c=='(' || c==')')
            o += (char)c;
        else { o += '%'; o += hex[c >> 4]; o += hex[c & 0x0F]; }
    }
    return o;
}

// HTTP
struct HttpResponse {
    int         status = 0;
    std::string location;
    std::string setCookie;
    std::string body;
    DWORD       err = 0;
};

static bool ParseUrl(const std::wstring& url, std::wstring& host, INTERNET_PORT& port, std::wstring& path)
{
    std::wstring u = url;
    if (u.rfind(L"https://", 0) == 0) { u = u.substr(8); port = 443; }
    else if (u.rfind(L"http://", 0) == 0) { u = u.substr(7); port = 80; }
    else return false;
    size_t slash = u.find(L'/');
    std::wstring hp = (slash == std::wstring::npos) ? u : u.substr(0, slash);
    path = (slash == std::wstring::npos) ? L"/" : u.substr(slash);
    size_t colon = hp.find(L':');
    if (colon != std::wstring::npos) {
        host = hp.substr(0, colon);
        port = (INTERNET_PORT)_wtoi(hp.substr(colon + 1).c_str());
    } else host = hp;
    return !host.empty();
}

static bool HttpRequest(const std::wstring& url, const wchar_t* method,
                        const std::string& body, bool followRedirect,
                        const std::wstring& extraHeaders, HttpResponse& resp)
{
    resp = HttpResponse();
    std::wstring host, path; INTERNET_PORT port = 80;
    if (!ParseUrl(url, host, port, path)) { Log("  [错误] URL 解析失败\n"); return false; }

    HINTERNET hS = WinHttpOpen(L"httplogin/3", WINHTTP_ACCESS_TYPE_NO_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hS) { Log("  [错误] WinHttpOpen 失败\n"); return false; }
    // 缩短超时, 确保整体在 watchdog 时限内
    WinHttpSetTimeouts(hS, 1200, 1500, 1500, 2500);

    if (!followRedirect) {
        DWORD policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
        WinHttpSetOption(hS, WINHTTP_OPTION_REDIRECT_POLICY, &policy, sizeof(policy));
    }

    HINTERNET hC = WinHttpConnect(hS, host.c_str(), port, 0);
    if (!hC) {
        resp.err = GetLastError();
        Log("  [错误] 连接 %s:%d 失败 (err=%lu)\n", ToUtf8(host).c_str(), (int)port, resp.err);
        WinHttpCloseHandle(hS); return false;
    }

    HINTERNET hR = WinHttpOpenRequest(hC, method, path.c_str(), NULL, WINHTTP_NO_REFERER,
                                      WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hR) { WinHttpCloseHandle(hC); WinHttpCloseHandle(hS); return false; }

    std::wstring headers;
    if (!body.empty()) headers += L"Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n";
    if (!extraHeaders.empty()) headers += extraHeaders;

    BOOL ok = WinHttpSendRequest(hR,
        headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers.c_str(),
        headers.empty() ? 0 : (DWORD)-1L,
        body.empty() ? WINHTTP_NO_REQUEST_DATA : (LPVOID)body.data(),
        (DWORD)body.size(), (DWORD)body.size(), 0);
    if (ok) ok = WinHttpReceiveResponse(hR, NULL);
    if (!ok) {
        resp.err = GetLastError();
        Log("  [错误] 请求/接收失败 (err=%lu)\n", resp.err);
    }

    if (ok) {
        DWORD st = 0, len = sizeof(st);
        WinHttpQueryHeaders(hR, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &st, &len, WINHTTP_NO_HEADER_INDEX);
        resp.status = (int)st;

        auto gh = [&](DWORD q, std::string& out) {
            wchar_t buf[4096]; DWORD n = sizeof(buf);
            if (WinHttpQueryHeaders(hR, q, WINHTTP_HEADER_NAME_BY_INDEX, buf, &n, WINHTTP_NO_HEADER_INDEX))
                out = ToUtf8(buf);
        };
        gh(WINHTTP_QUERY_LOCATION, resp.location);
        gh(WINHTTP_QUERY_SET_COOKIE, resp.setCookie);

        DWORD avail = 0;
        while (WinHttpQueryDataAvailable(hR, &avail) && avail > 0) {
            std::vector<char> b(avail); DWORD rd = 0;
            if (!WinHttpReadData(hR, b.data(), avail, &rd)) break;
            resp.body.append(b.data(), rd);
            if (resp.body.size() > 256 * 1024) break;
        }
    }

    WinHttpCloseHandle(hR);
    WinHttpCloseHandle(hC);
    WinHttpCloseHandle(hS);
    return ok != FALSE;
}

static std::string ExtractSessionId(const std::string& sc)
{
    size_t p = sc.find("JSESSIONID=");
    if (p == std::string::npos) return "";
    p += 11;
    size_t e = sc.find(';', p);
    if (e == std::string::npos) e = sc.size();
    return sc.substr(p, e - p);
}

static std::string JsonStr(const std::string& j, const char* key)
{
    std::string pat = std::string("\"") + key + "\"";
    size_t p = j.find(pat);
    if (p == std::string::npos) return "";
    p = j.find(':', p + pat.size());
    if (p == std::string::npos) return "";
    p = j.find('"', p);
    if (p == std::string::npos) return "";
    size_t e = j.find('"', p + 1);
    if (e == std::string::npos) return "";
    return j.substr(p + 1, e - p - 1);
}

// 门户劫持返回 200 + JS 跳转 (非 302)
static std::string ExtractJsRedirect(const std::string& body)
{
    const char* pats[] = {
        "location.href='",    "location.href=\"",
        "location.replace('", "location.replace(\"",
        "self.location='",    "self.location=\"",
    };
    for (int i = 0; i < 6; i++) {
        size_t plen = strlen(pats[i]);
        size_t p = body.find(pats[i]);
        if (p != std::string::npos) {
            char q = pats[i][plen - 1];
            size_t s = p + plen;
            size_t e = body.find(q, s);
            if (e != std::string::npos && e > s) return body.substr(s, e - s);
        }
    }
    return "";
}

// 从 URL 取出 scheme://host[:port] 部分, 供门户地址自适应使用
static std::string ExtractOrigin(const std::string& url)
{
    size_t p = url.find("://");
    if (p == std::string::npos) return "";
    size_t hs = p + 3;                       // host 起始位置
    size_t slash = url.find('/', hs);
    size_t end = (slash == std::string::npos) ? url.size() : slash;
    if (end <= hs) return "";                // 没有 host -> 空 (走兜底)
    return url.substr(0, end);
}
// 用 WinRT 读网络连接级别: 0=None 1=LocalAccess 2=ConstrainedInternetAccess 3=InternetAccess
static int GetConnectivityLevel()
{
    int level = -1;
    try {
        // 只在首次调用时初始化 apartment, 且永不 uninit:
        // 本函数会被重试逻辑多次调用, 反复 init/uninit 会导致 COM 状态损坏 -> 0xC0000005 崩溃
        static bool s_inited = false;
        if (!s_inited) {
            winrt::init_apartment();
            s_inited = true;
        }
        {
            // profile 必须在 apartment 存活期间析构 (作用域限定)
            auto profile = winrt::Windows::Networking::Connectivity::NetworkInformation::GetInternetConnectionProfile();
            level = profile ? (int)profile.GetNetworkConnectivityLevel() : 0;
        }
    } catch (...) {
        level = -1;
    }
    return level;
}

// 从 exe 同目录 auth.txt 读取账密: 第 1 个非空行=账号, 第 2 个=密码 (UTF-8, 可带BOM)
static bool ReadAuthFile(std::wstring& user, std::wstring& pass)
{
    std::wstring path = GetExeDir() + L"\\auth.txt";

    FILE* f = NULL;
    if (_wfopen_s(&f, path.c_str(), L"rb") != 0 || !f) return false;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return false; }

    std::vector<char> buf((size_t)sz + 1, 0);
    size_t rd = fread(buf.data(), 1, (size_t)sz, f);
    fclose(f);
    buf[rd] = 0;

    std::string content(buf.data(), rd);
    if (content.size() >= 3 && (unsigned char)content[0] == 0xEF
        && (unsigned char)content[1] == 0xBB && (unsigned char)content[2] == 0xBF)
        content = content.substr(3);   // 去 BOM

    std::vector<std::string> lines;
    std::string cur;
    for (size_t i = 0; i <= content.size(); i++) {
        char ch = (i < content.size()) ? content[i] : '\n';
        if (ch == '\r') continue;
        if (ch == '\n') {
            size_t a = cur.find_first_not_of(" \t");
            size_t b = cur.find_last_not_of(" \t");
            if (a != std::string::npos) lines.push_back(cur.substr(a, b - a + 1));
            cur.clear();
        } else cur += ch;
    }
    if (lines.size() < 2) return false;
    user = ToW(lines[0]);
    pass = ToW(lines[1]);
    return !user.empty();
}

// 弹一个控制台窗口显示提示, 等按任意键后关闭 (GUI 子系统程序用)
static void ShowConsoleWait(const wchar_t* msg)
{
    if (!AllocConsole()) return;              // 已有关联控制台则不动
    SetConsoleOutputCP(936);                  // 中文
    SetConsoleTitleW(L"校园网自动登录 - 提示");

    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h && h != INVALID_HANDLE_VALUE) {
        DWORD w = 0;
        const wchar_t* head = L"\n  ";
        const wchar_t* tail = L"\n\n  按任意键关闭...";
        WriteConsoleW(h, head, (DWORD)wcslen(head), &w, NULL);
        WriteConsoleW(h, msg,  (DWORD)wcslen(msg),  &w, NULL);
        WriteConsoleW(h, tail, (DWORD)wcslen(tail), &w, NULL);
    }

    // 等任意按键
    HANDLE hi = GetStdHandle(STD_INPUT_HANDLE);
    if (hi && hi != INVALID_HANDLE_VALUE) {
        FlushConsoleInputBuffer(hi);
        INPUT_RECORD rec; DWORD rd = 0;
        while (ReadConsoleInputW(hi, &rec, 1, &rd)) {
            if (rec.EventType == KEY_EVENT && rec.Event.KeyEvent.bKeyDown) break;
        }
    }
    FreeConsole();
}

// 主流程
int wmain(int argc, wchar_t** argv)
{
    LogInit();
    SetUnhandledExceptionFilter(CrashHandler);          // 崩溃时写日志
    CreateThread(NULL, 0, TimeoutProc, NULL, 0, NULL);   // 20 秒兜底

    bool hasCred = false;
    if (argc >= 3) { g_user = argv[1]; g_pass = argv[2]; hasCred = true; }   // 命令行优先
    else hasCred = ReadAuthFile(g_user, g_pass);                              // 否则读同目录 auth.txt

    if (!hasCred) {
        Log("[错误] 未取到账号密码!\n");
        Log("  请在本程序所在目录创建 auth.txt, 第一行写账号, 第二行写密码\n");
        Log("  或用命令行: httplogin.exe <账号> <密码>\n");
        if (g_log) fclose(g_log);
        return 1;
    }
    Log("账号: %s  (密码 %d 位)\n\n", ToUtf8(g_user).c_str(), (int)g_pass.size());

    // 0. 网络连接级别判断: 只处理 1(仅本地) 和 2(强制门户)
    // 网络未就绪时短重试 (应对"刚登录/刚开机时系统网络尚未完成")
    // 次数与间隔受 20 秒 watchdog 约束: 最多探测 5 次, 间隔 3 秒 (最坏等待 12 秒)
    int level = -1;
    const int MAX_PROBE = 5;
    const int PROBE_WAIT_MS = 3000;
    for (int probe = 0; probe < MAX_PROBE; probe++) {
        level = GetConnectivityLevel();
        const char* lvName =
            (level == 0) ? "None (无连接)" :
            (level == 1) ? "LocalAccess (仅本地网络)" :
            (level == 2) ? "ConstrainedInternetAccess (强制门户)" :
            (level == 3) ? "InternetAccess (已联网)" : "(读取失败)";
        Log("[0] 探测%d/%d: GetNetworkConnectivityLevel() = %d  %s\n",
            probe + 1, MAX_PROBE, level, lvName);
        if (level != 0 && level != -1) break;        // 网络已就绪
        if (probe < MAX_PROBE - 1) {
            Log("    网络尚未就绪, %d 秒后重试...\n", PROBE_WAIT_MS / 1000);
            Sleep(PROBE_WAIT_MS);
        }
    }

    if (level != 1 && level != 2) {
        Log("    当前 level=%d 非 1/2, 无需登录 -> 退出\n", level);
        if (g_log) fclose(g_log);
        return 0;
    }
    Log("    level=%d 需要登录 -> 继续\n\n", level);

    // 1. 触发门户劫持
    Log("[1] 尝试触发门户劫持 (禁止自动跳转)\n");
    HttpResponse r1;
    for (int i = 0; i < 3; i++) {
        Log("    试 %s ...\n", ToUtf8(TRIGGER_URLS[i]).c_str());
        HttpRequest(TRIGGER_URLS[i], L"GET", "", false, L"", r1);
        Log("      状态码=%d, Location=%s, err=%lu\n", r1.status,
            r1.location.empty() ? "(无)" : r1.location.c_str(), r1.err);
        if (!r1.location.empty()) break;

        std::string jsUrl = ExtractJsRedirect(r1.body);
        if (!jsUrl.empty()) {
            Log("      响应体是 JS 跳转, 提取到: %s\n", jsUrl.c_str());
            r1.location = jsUrl;
            break;
        }
        if (!r1.body.empty())
            Log("      响应体前120: %.120s\n", r1.body.c_str());
    }

    if (r1.location.empty()) {
        Log("\n[结果] 没拿到门户 URL -> 放弃\n");
        if (g_log) fclose(g_log);
        return 0;
    }

    // 2. 门户 URL / queryString
    std::string portalUrl = r1.location;
    if (portalUrl.rfind("http", 0) != 0)
        portalUrl = "http://10.110.141.3/eportal/" + portalUrl;
    size_t qpos = portalUrl.find('?');
    std::string queryString = (qpos == std::string::npos) ? "" : portalUrl.substr(qpos + 1);
    Log("\n[2] 门户 URL: %s\n", portalUrl.c_str());

    // 3. 门户地址自适应

    // 门户地址自适应: 优先用劫持返回的 origin, 失败则用兜底常量
    std::string origin = ExtractOrigin(portalUrl);
    std::string loginUrl;
    if (!origin.empty()) {
        loginUrl = origin + "/eportal/InterFace.do?method=login";
        Log("    门户地址(自适应): %s\n", origin.c_str());
    } else {
        loginUrl = LOGIN_FALLBACK;
        Log("    门户地址(兜底): %s\n", LOGIN_FALLBACK);
    }
    std::string jsid = "";        // 不携带 JSESSIONID
    bool needEncrypt = false;     // 假定不需要加密

    // 4. POST 登录 (用自适应得到的地址)
    std::string body = "userId=" + UrlEncode(UrlEncode(ToUtf8(g_user)))
                     + "&password=" + UrlEncode(UrlEncode(ToUtf8(g_pass)))
                     + "&service="
                     + "&queryString=" + UrlEncode(UrlEncode(queryString))
                     + "&operatorPwd=&operatorUserId=&validcode="
                     + "&passwordEncrypt=" + std::string(needEncrypt ? "true" : "false");

    Log("\n[3] POST 登录\n");
    std::wstring hdr;
    if (!jsid.empty()) hdr = L"Cookie: JSESSIONID=" + ToW(jsid) + L"\r\n";
    hdr += L"Referer: " + ToW(portalUrl) + L"\r\n";

    HttpResponse r3;
    HttpRequest(ToW(loginUrl), L"POST", body, false, hdr, r3);
    Log("    响应状态=%d\n", r3.status);
    Log("    响应内容: %s\n", r3.body.empty() ? "(空)" : r3.body.c_str());

    std::string result = JsonStr(r3.body, "result");
    std::string message = JsonStr(r3.body, "message");
    Log("\n[4] result=%s\n", result.empty() ? "(无)" : result.c_str());
    if (!message.empty()) Log("    message=%s\n", message.c_str());

    if (result == "success") {
        Log("\n>>> 登录成功! <<<\n");
    } else {
        Log("\n>>> 登录失败 (result=%s) <<<\n", result.empty() ? "(无)" : result.c_str());
        if (g_log) { fclose(g_log); g_log = NULL; }
        ShowConsoleWait(L"账号密码错误，请检查重试");
    }

    if (g_log) fclose(g_log);
    return 0;
}
