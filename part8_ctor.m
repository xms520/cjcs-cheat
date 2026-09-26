
#pragma mark - ============ ctor：延迟初始化链（等 Unity 起来）============
static int g_ctorStage = 0;

static void mx_stage(void) {
    @autoreleasepool {
        @try {
            switch (g_ctorStage) {
            case 0: {
                g_ctorStage = 1;
                mlog(@"ctor: pid=%d bid=%@", getpid(), [[NSBundle mainBundle] bundleIdentifier] ?: @"?");
                mx_syms_load();
                mlog(@"sym: %u symbols indexed", g_symCount);
                if (!mx_il2cpp_load()) { mlog(@"stage1: il2cpp API missing -> UI only"); break; }
                mx_time_warmup();
                mx_install_lua_hook();
                break;
            }
            case 1:
                g_ctorStage = 2;
                if (!mx_time_warmup_ok()) { mx_time_warmup(); }
                mx_install_lua_hook();
                mx_apply_speed();
                break;
            default: {
                g_ctorStage = 3;
                extern int g_luaInjected;
                extern void mx_dump_found(void);
                mlog(@"stage3: luaInjected=%d timeSet=%p timeGet=%p",
                     g_luaInjected, g_timeSetScale, g_timeGetScale);
                if (g_luaInjected) mx_dump_found();
                // 确保加速被持续应用（LuaSvr tween 可能改回 timeScale）
                mx_apply_speed();
                if (g_luaInjected) g_ctorStage = 99;  // 停止重试
                break;
            }
            }
        } @catch (NSException *e) {
            mlog(@"stage exc: %@ %@", e.name, e.reason);
        }
    }
}

static int mx_time_warmup_ok(void) { return g_timeSetScale != NULL; }

#pragma mark - 导出 Lua 自发现结果（下次精确定位用）
static void mx_dump_found(void) {
    if (!g_L || !L.getglobal || !L.tolstring) return;
    L.getglobal(g_L, "__CJCS_FOUND");
    if (L.type(g_L, -1) != 5) { L.settop(g_L, -L.gettop(g_L)); return; }
    // 表里有 n 个字符串元素，逐个取
    NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/cjcs_lua_found.txt"];
    NSMutableString *out = [NSMutableString string];
    extern int (*lua_rawgeti_p)(lua_State *, int, long long);
    extern int (*lua_rawlen_p)(lua_State *);
    if (!lua_rawgeti_p || !lua_rawlen_p) { mlog(@"dump: rawgeti/rawlen missing"); return; }
    int n = lua_rawlen_p(g_L);
    for (int i = 1; i <= n && i < 800; i++) {
        lua_rawgeti_p(g_L, -1, i);
        size_t len = 0;
        const char *s = L.tolstring(g_L, -1, &len);
        if (s) [out appendFormat:@"%s\n", s];
        L.settop(g_L, -1);
    }
    L.settop(g_L, -L.gettop(g_L));
    if (out.length) {
        [out writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
        mlog(@"lua found dumped: %lu bytes -> Documents/cjcs_lua_found.txt", (unsigned long)out.length);
    }
}

#pragma mark - UI tick（1s）
static void mx_ui_tick(void) { @autoreleasepool { @try { mx_build_window(); } @catch (NSException *e) {} } }

__attribute__((constructor)) static void cjcs_ctor(void) {
    @autoreleasepool {
        mlog(@"================ CJCCheat v1 boot ================");
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0*NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            mx_stage();
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0*NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                mx_stage();
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0*NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                    mx_stage();
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(8.0*NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                        mx_stage();
                        mx_build_window();
                        [NSTimer scheduledTimerWithTimeInterval:1.0 repeats:YES block:^(NSTimer *t){ mx_ui_tick(); }];
                        [NSTimer scheduledTimerWithTimeInterval:1.0 repeats:YES block:^(NSTimer *t){
                            [[CJBox shared] keepTick];
                        }];
                    });
                });
            });
        });
    }
}
