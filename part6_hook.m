
#pragma mark - ============ LuaSvr.Update 挂钩（methodPointer 热替换，非内联）============
static Il2CppMethodInfo *g_updateMI   = NULL;
static void            (*g_updateOrig)(void *self, void *mi) = NULL;
static int               g_updateTicks = 0;
static int               g_luaInjected = 0;
static lua_State        *g_L          = NULL;

// 从对象读一个指针型字段（字段名 + 偏移由运行时反射得到）
static size_t g_off_luaState = (size_t)-1;   // SLua.LuaSvr.luaState
static size_t g_off_l       = (size_t)-1;    // SLua.LuaState.l_

static void mx_inject_lua(lua_State *Ls) {
    if (!Ls || !mx_lua_load()) return;
    if (L.L_loadbufferx(Ls, kLuaHook, strlen(kLuaHook), "@cjcs_hook", "t") != 0) {
        const char *e = L.tolstring ? L.tolstring(Ls, -1, NULL) : "?";
        mlog(@"lua: loadbufferx FAILED: %s", e ? e : "?");
        L.settop(Ls, -L.gettop(Ls));
        return;
    }
    if (L.pcallk(Ls, 0, -1, 0, 0, NULL) != 0) {
        const char *e = L.tolstring ? L.tolstring(Ls, -1, NULL) : "?";
        mlog(@"lua: pcallk FAILED: %s", e ? e : "?");
        L.settop(Ls, -L.gettop(Ls));
        return;
    }
    L.settop(Ls, -L.gettop(Ls));
    g_luaInjected = 1;
    mlog(@"lua: hook injected into game state %p", (void *)Ls);
}

static void mx_update_replacement(void *self, void *mi) {
    if (g_updateOrig) g_updateOrig(self, mi);

    if (!g_updateTicks++) mlog(@"LuaSvr.Update hooked (self=%p mi=%p)", self, mi);

    // 拿到 lua_State（懒解析字段偏移）
    if (!g_L && self && I.class_get_field_from_name) {
        if (g_off_luaState == (size_t)-1) {
            Il2CppClass *k = mx_class("SLua", "LuaSvr");
            g_off_luaState = mx_field_off(k, "luaState", NULL);
            mlog(@"LuaSvr.luaState offset=%zd", (ssize_t)g_off_luaState);
        }
        if (g_off_luaState != (size_t)-1 && g_off_luaState < 4096) {
            void *ls = *(void **)((char *)self + g_off_luaState);
            if (ls) {
                if (g_off_l == (size_t)-1) {
                    Il2CppClass *kl = mx_class("SLua", "LuaState");
                    g_off_l = mx_field_off(kl, "l_", NULL);
                    mlog(@"LuaState.l_ offset=%zd", (ssize_t)g_off_l);
                }
                if (g_off_l != (size_t)-1 && g_off_l < 4096) {
                    void *Lraw = *(void **)((char *)ls + g_off_l);
                    if (Lraw) g_L = (lua_State *)Lraw;
                }
            }
        }
    }

    // Lua 已就绪（Update 被调用 = LuaSvr 初始化完成）→ 注入一次
    if (!g_luaInjected && g_L && g_updateTicks > 2) {
        mx_inject_lua(g_L);
    }

    // 每 ~30 帧下发开关到 Lua（__CJCS 表，无需文件 IO）
    if (g_luaInjected && g_L && (g_updateTicks % 30) == 0 && L.getglobal && L.pushboolean && L.setfield) {
        extern volatile int g_inv, g_oneshot;
        L.getglobal(g_L, "__CJCS");
        if (L.type(g_L, -1) == 5 /* LUA_TTABLE */) {
            L.pushboolean(g_L, g_inv);
            L.setfield(g_L, -2, "invincible");
            L.pushboolean(g_L, g_oneshot);
            L.setfield(g_L, -2, "oneshot");
        }
        L.settop(g_L, -L.gettop(g_L));
    }
}

static void mx_install_lua_hook(void) {
    if (!mx_il2cpp_load() || !mx_lua_load()) return;
    Il2CppClass *k = mx_class("SLua", "LuaSvr");
    if (!k) { mlog(@"SLua.LuaSvr class NOT FOUND"); return; }
    g_updateMI = mx_meth(k, "Update", 0);
    if (!g_updateMI) { mlog(@"LuaSvr.Update NOT FOUND"); return; }
    if (!mx_layout_probe(g_updateMI)) return;

    uint8_t *b = (uint8_t *)g_updateMI;
    void **slot = (void **)(b + g_mi.ptrOff);
    g_updateOrig = (void (*)(void *, void *))(*slot);
    if (!mx_ptr_plausible((uintptr_t)g_updateOrig)) {
        mlog(@"LuaSvr.Update methodPointer implausible: %p", (void *)g_updateOrig);
        return;
    }
    *slot = (void *)mx_update_replacement;
    mlog(@"LuaSvr.Update IMP swapped: %p -> %p", (void *)g_updateOrig, (void *)mx_update_replacement);
}

#pragma mark - ============ 全局加速应用 tick ============
static float g_speedTable[] = { 1.0f, 2.0f, 4.0f, 8.0f };
static int   g_speedIdx = 0;

static void mx_apply_speed(void) {
    float mul = g_speedTable[g_speedIdx];
    if (fabsf(mul - g_speedMul) < 0.0001f) return;
    g_speedMul = mul;
    mx_time_apply(mul);
    mlog(@"timeScale -> %g", mul);
}
