
#pragma mark - ============ Lua C API（内存符号表，未导出但可定位）============
typedef struct lua_State lua_State;
typedef int (*lua_CFunction)(lua_State *);
typedef void *lua_KContext;
typedef int (*lua_KFunction)(lua_State *, int, lua_KContext);

static struct {
    int            (*L_loadbufferx)(lua_State *, const char *, size_t, const char *, const char *);
    int            (*pcallk)(lua_State *, int, int, int, lua_KContext, lua_KFunction);
    void           (*settop)(lua_State *, int);
    int            (*gettop)(lua_State *);
    void           (*getglobal)(lua_State *, const char *);
    void           (*setglobal)(lua_State *, const char *);
    void           (*pushnumber)(lua_State *, double);
    void           (*pushinteger)(lua_State *, long long);
    void           (*pushstring)(lua_State *, const char *);
    void           (*pushboolean)(lua_State *, int);
    void           (*setfield)(lua_State *, int, const char *);
    const char*    (*tolstring)(lua_State *, int, size_t *);
    int            (*type)(lua_State *, int);
    void           (*createtable)(lua_State *, int, int);
    void           (*pushvalue)(lua_State *, int);
} L;

static int mx_lua_load(void) {
    static int ok = -1;
    if (ok >= 0) return ok;
    ok = 0;
    struct { const char *n; void **p; } t[] = {
        {"_luaL_loadbufferx", (void **)&L.L_loadbufferx},
        {"_lua_pcallk",       (void **)&L.pcallk},
        {"_lua_settop",       (void **)&L.settop},
        {"_lua_gettop",       (void **)&L.gettop},
        {"_lua_getglobal",    (void **)&L.getglobal},
        {"_lua_setglobal",    (void **)&L.setglobal},
        {"_lua_pushnumber",   (void **)&L.pushnumber},
        {"_lua_pushinteger",  (void **)&L.pushinteger},
        {"_lua_pushstring",   (void **)&L.pushstring},
        {"_lua_pushboolean",  (void **)&L.pushboolean},
        {"_lua_setfield",     (void **)&L.setfield},
        {"_lua_tolstring",    (void **)&L.tolstring},
        {"_lua_type",         (void **)&L.type},
        {"_lua_createtable",  (void **)&L.createtable},
        {"_lua_pushvalue",    (void **)&L.pushvalue},
    };
    int miss = 0;
    for (size_t i = 0; i < sizeof(t)/sizeof(t[0]); i++) {
        *t[i].p = mx_sym_find(t[i].n);
        if (!*t[i].p) { mlog(@"lua: MISSING %s", t[i].n); miss++; }
    }
    if (miss) return 0;
    ok = 1;
    mlog(@"lua: 15/15 C API resolved");
    return 1;
}

#pragma mark - ============ 全局加速（纯 il2cpp 反射：Time.timeScale）============
// 不用内联 patch，不碰 C++ 私有方法。直接 invoke 官方托管 API:
//   UnityEngine.Time.set_timeScale(float)  —— 引擎与托管侧统一变速，Lua 动画/渲染全覆盖
static Il2CppMethodInfo *g_timeSetScale = NULL;
static Il2CppMethodInfo *g_timeGetScale = NULL;
static float g_speedMul = 1.0f;

static void mx_time_warmup(void) {
    Il2CppClass *k = mx_class("UnityEngine", "Time");
    if (!k) { mlog(@"Time class NOT FOUND"); return; }
    g_timeSetScale = mx_meth(k, "set_timeScale", 1);
    g_timeGetScale = mx_meth(k, "get_timeScale", 0);
    mlog(@"Time: set_timeScale=%p get_timeScale=%p", g_timeSetScale, g_timeGetScale);
}

static void mx_time_apply(float mul) {
    if (!g_timeSetScale || !I.runtime_invoke) return;
    float v = mul;
    void *args[1] = { &v };
    void *exc = NULL;
    if (!I.thread_current || !I.thread_current()) {
        if (I.thread_attach) I.thread_attach(I.domain_get());
    }
    I.runtime_invoke(g_timeSetScale, NULL, args, &exc);
    if (exc) mlog(@"timeScale invoke exception!");
}

#pragma mark - ============ 内嵌 Lua 注入源 ============
// 设计原则：不硬编码游戏内部标识符（无法静态确认）——用「自发现」：
//   1) 遍历 package.loaded 全部模块（深度 3），收集表里的函数
//   2) 按关键字匹配战斗相关函数名（damage/hurt/hp/attr/attack/...）
//   3) 包一层：秒杀 → 对「我方造成伤害」的返回值放大；无敌 → 对「我方受到伤害」压 0
//   4) 把所有发现写入 __CJCS_FOUND，native 落盘 → 供下一版精确化
// 同时 native 每 tick 通过 __CJCS 全局表下发开关（无需文件 IO）
static const char *kLuaHook =
"if __CJCS_INSTALLED then return end\n"
"__CJCS_INSTALLED = true\n"
"local FOUND = {}\n"
"__CJCS_FOUND = FOUND\n"
"__CJCS = __CJCS or {}\n"
"local C = __CJCS\n"
"C.invincible = C.invincible or false\n"
"C.oneshot    = C.oneshot    or false\n"
"local KW_DMG   = { 'damage','Damage','hurt','Hurt','hurtvalue','hurtValue','subhp','reducehp','attack','Attack' }\n"
"local KW_STATE = { 'hp','Hp','HP','health','Health','attr','Attr','dead','Dead','die','Die','alive' }\n"
"local function has(s, list)\n"
"  for i=1,#list do if string.find(s, list[i], 1, true) then return list[i] end end\n"
"  return nil\n"
"end\n"
"local wrapped = 0\n"
"local function wrapFn(tbl, key, path, kind)\n"
"  local ok, f = pcall(function() return tbl[key] end)\n"
"  if not ok or type(f) ~= 'function' then return end\n"
"  if debug and debug.getinfo and not debug.getinfo(f, 'S').what:find('C') then end\n"
"  if getmetatable and getmetatable(f) == 'CJCS_WRAPPED' then return end\n"
"  local orig = f\n"
"  tbl[key] = function(...)\n"
"    local r = orig(...)\n"
"    if kind == 'DMG' then\n"
"      if C.oneshot and type(r) == 'number' and r > 0 then return r * 100000\n"
"      end\n"
"    elseif kind == 'HURT' then\n"
"      if C.invincible and type(r) == 'number' and r > 0 then return 0 end\n"
"    end\n"
"    return r\n"
"  end\n"
"  pcall(function() setmetatable(tbl[key], { __name = 'CJCS_WRAPPED' }) end)\n"
"  wrapped = wrapped + 1\n"
"  FOUND[#FOUND+1] = path .. '.' .. key .. ' [' .. kind .. ']'\n"
"end\n"
"local seen = {}\n"
"local function scan(tbl, path, depth)\n"
"  if depth > 3 or type(tbl) ~= 'table' or seen[tbl] then return end\n"
"  seen[tbl] = true\n"
"  local n = 0\n"
"  for k, v in pairs(tbl) do\n"
"    n = n + 1; if n > 400 then break end\n"
"    if type(k) == 'string' then\n"
"      if type(v) == 'function' then\n"
"        local kw = has(k, KW_DMG)\n"
"        if kw then\n"
"          if string.find(k, 'hurt', 1, true) or string.find(k, 'Hurt', 1, true)\n"
"             or string.find(k, 'damage', 1, true) or string.find(k, 'Damage', 1, true) then\n"
"            wrapFn(tbl, k, path, 'HURT')\n"
"          elseif string.find(k, 'attack', 1, true) or string.find(k, 'Attack', 1, true) then\n"
"            wrapFn(tbl, k, path, 'DMG')\n"
"          end\n"
"        end\n"
"      elseif type(v) == 'table' then\n"
"        scan(v, path .. '.' .. k, depth + 1)\n"
"      end\n"
"    end\n"
"  end\n"
"end\n"
"local keys = {}\n"
"for k in pairs(package.loaded) do keys[#keys+1] = k end\n"
"table.sort(keys)\n"
"for i=1,#keys do\n"
"  local k = keys[i]\n"
"  if not string.find(k, '^_') then\n"
"    local ok, m = pcall(require, k)\n"
"    if ok and type(m) == 'table' then scan(m, k, 1) end\n"
"  end\n"
"end\n"
"FOUND[#FOUND+1] = 'modules=' .. #keys .. ' wrapped=' .. wrapped\n";
