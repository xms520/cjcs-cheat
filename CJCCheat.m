// CJCCheat.m — 创界传说（com.whbios.slds）悬浮助手 v1（arm64, TrollFools 注入）
// ============================================================================
// 功能：无敌 / 秒杀 / 全局加速（战斗内）
//
// 【引擎档案（本机逆向实证）】
//   Unity 2021.3.14f1 + IL2CPP（Obfuz 混淆，符号名全被替换）
//   Frameworks/UnityFramework.framework/UnityFramework  149MB, Mach-O arm64
//   ├─ il2cpp_* API 共 249 个符号，但 **全部 N_PEXT 未导出** → dlsym 必失败
//   │  → 本 dylib 走「内存 Mach-O 符号表扫描」定位（见 mx_sym_find）
//   └─ SLua（Lua 5.3.4）+ 393 个 lua* 符号，同样未导出
//
//   ⭐ 游戏业务逻辑全在 Lua 层（不是 C#！）：
//      Assembly-CSharp 只有 1357 个壳类（GameEntry/SDK/SLuaWrap 等），
//      真正的战斗逻辑在 Data/Raw/*.ast 里的 1004 个 .lua：
//        Fight/LocalGame.lua      Fight/ServerGame.lua    Fight/GameInterface.lua
//        Game/GUnit/GUnitAttrCmp.lua   Game/GSpell/GSpellDamage.lua
//      .ast = 拼接的 UnityFS bundle 包；bundle 头/索引明文，
//      唯独每个 .lua 的 payload 被逐文件加密（size%16 随机、无压缩指纹、
//      MD5/AES/XXTEA/RC4/ChaCha 全部爆破失败）→ 静态解密不可行，
//      必须在【运行时】从已解密的内存/Lua state 入手。
//
// 【hack 架构】
//  阶段1 native：内存符号表解析 il2cpp_* → il2cpp 反射（类/方法/字段）
//               + Lua C API 直连（不依赖 SLua C# 包装类，更稳）
//  阶段2 native：挂 SLua.LuaSvr::Update（每帧调 Lua 全局 Update）——Lua 已初始化后才命中
//               → 在该 hook 内跑 luaL_loadbufferx + lua_pcallk 注入我们的 Lua 代码
//  阶段3 Lua  ：自发现式 hook——遍历 package.loaded 找含伤害/血量/时间缩放字段的模块，
//               包其函数；全局加速走 UnityEngine.Time（C# 层，与 Lua 无关，native 侧直接干）
//
// 【全局加速走 native（与 Lua 解密无关，本版可直接生效）】
//   Time_Get_Custom_PropDeltaTime / UnscaledDeltaTime / FixedDeltaTime
//   → 乘倍率；TimeManager::SetTimeScale 同步内部状态
//   ⚠️ 用「thunk 热替换函数指针」而非内联 patch：无需 mprotect 改代码段，arm64 安全
// ============================================================================
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <sys/mman.h>
#import <unistd.h>
#import <stdio.h>
#import <stdarg.h>
#import <string.h>
#import <stdint.h>

// UnityFramework __TEXT 段大小（本机逆向实证：vmaddr=0 size=0x593c000）
// 用途：判断某个函数指针是否落在 Unity 代码段内（methodPointer 合理性校验）
#define kUnityTextSize 0x593c000

// ============ 全局开关状态（唯一一处定义，供 LuaSvr hook / 面板 / 加速 tick 共享）============
volatile int g_inv      = 0;   // 无敌
volatile int g_oneshot  = 0;   // 秒杀
int          g_speedIdx = 0;   // 加速档位（0=OFF 1=x2 2=x4 3=x8）
static const float g_speedTable[4] = { 1.0f, 2.0f, 4.0f, 8.0f };
static float       g_speedMul = 1.0f;

#pragma mark - 日志（Documents/cjcs.log，可直接导出）
static FILE *g_log = NULL;
static void mlog(NSString *fmt, ...) NS_FORMAT_FUNCTION(1, 2);
static void mlog(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[CJCS] %@", s);
    if (!g_log) {
        NSString *p = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/cjcs.log"];
        g_log = fopen(p.UTF8String, "a");
    }
    if (g_log) { fprintf(g_log, "[CJCS] %s\n", s.UTF8String); fflush(g_log); }
}

#pragma mark - 内嵌头像（用户上传图 → 256x256 JPEG q85 = 14081B → base64 4 段）
static NSString * const kAvatarB64 =
@"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"
@"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"
@"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"
@"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"
;

static UIImage *mx_avatar(void) {
    static UIImage *img = nil;
    if (img) return img;
    NSData *d = [[NSData alloc] initWithBase64EncodedString:kAvatarB64 options:0];
    if (d) img = [UIImage imageWithData:d];
    return img;
}

static UIColor *mx_c(int r, int g, int b, CGFloat a) {
    return [UIColor colorWithRed:r/255.0 green:g/255.0 blue:b/255.0 alpha:a];
}

#pragma mark - ============ 内存 Mach-O 符号定位 ============
// UnityFramework 的 il2cpp_*/lua* 符号全部是 N_PEXT（私有外部），
// 不在 LC_DYLD_EXPORTS_TRIE 里 → dlsym/RTLD_DEFAULT 都拿不到。
// 唯一可靠方式：把 UnityFramework 的 Mach-O 从 __LINKEDIT 里把
// LC_SYMTAB 的 nlist 全表读出来，自己建名字→地址表。
//
// 地址换算：__TEXT 段 fileoff == vmaddr == 0（实测），
// 而 nlist.n_value 是**未加 slide 的链接期地址** → 运行时地址 = n_value + slide。

typedef struct { const char *name; uintptr_t addr; } mx_sym_t;

static mx_sym_t      *g_syms       = NULL;   // 扁平表（strdup 的名字，常驻）
static uint32_t       g_symCount   = 0;
static int32_t       *g_hashBucket = NULL;   // 开放寻址：bucket -> sym index
static uint32_t       g_hashMask   = 0;
static uintptr_t      g_slide      = 0;
static int            g_symsReady  = 0;

static uint32_t mx_hash(const char *s) {
    uint32_t h = 5381;
    while (*s) h = ((h << 5) + h) + (unsigned char)(*s++);
    return h;
}

// 找到 UnityFramework 的 mach_header（主镜像或已加载的 framework）
static const struct mach_header_64 *mx_unity_header(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (!nm) continue;
        if (strstr(nm, "UnityFramework")) {
            const struct mach_header *h = _dyld_get_image_header(i);
            if (h && h->magic == MH_MAGIC_64) {
                g_slide = (uintptr_t)_dyld_get_image_vmaddr_slide(i);
                return (const struct mach_header_64 *)h;
            }
        }
    }
    // 兜底：主镜像（有些包把 UnityFramework 静态链进主二进制）
    const struct mach_header *h0 = _dyld_get_image_header(0);
    if (h0 && h0->magic == MH_MAGIC_64) {
        g_slide = (uintptr_t)_dyld_get_image_vmaddr_slide(0);
        return (const struct mach_header_64 *)h0;
    }
    return NULL;
}

static void mx_syms_load(void) {
    if (g_symsReady) return;
    g_symsReady = 1;

    const struct mach_header_64 *mh = mx_unity_header();
    if (!mh) { mlog(@"sym: UnityFramework mach_header NOT FOUND"); return; }

    const struct load_command *lc = (const struct load_command *)((const char *)mh + sizeof(struct mach_header_64));
    const struct symtab_command *st = NULL;
    uintptr_t linkedit_delta = 0;
    int haveLE = 0;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (lc->cmd == LC_SYMTAB) st = (const struct symtab_command *)lc;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
            if (!strcmp(sg->segname, "__LINKEDIT")) {
                linkedit_delta = (uintptr_t)(sg->vmaddr - sg->fileoff);
                haveLE = 1;
            }
        }
        lc = (const struct load_command *)((const char *)lc + lc->cmdsize);
    }
    if (!st || !haveLE) { mlog(@"sym: LC_SYMTAB/__LINKEDIT NOT FOUND"); return; }

    // ⚠️ 关键：mh 是 _dyld_get_image_header 返回的【运行时】地址（= __TEXT.vmaddr(0) + slide），
    //    已经含 slide。所以运行时地址 = mh + linkedit_delta + fileoff，
    //    ★ 绝不能再 + slide（旧版这里双重加 slide → 指针飞出映射区 → SIGSEGV KERN_INVALID_ADDRESS）★
    const struct nlist_64 *nl    = (const struct nlist_64 *)((uintptr_t)mh + linkedit_delta + st->symoff);
    const char            *strtb = (const char *)((uintptr_t)mh + linkedit_delta + st->stroff);
    mlog(@"sym: mh=%p slide=%#lx LE_delta=%#lx symoff=%u nsyms=%u stroff=%u strsize=%u",
         mh, (unsigned long)g_slide, (unsigned long)linkedit_delta,
         st->symoff, st->nsyms, st->stroff, st->strsize);
    mlog(@"sym: nlist=%p strtab=%p", nl, strtb);

    // 第一遍：只计数（避免 477826 * 16B ≈ 7.6MB 的大块 calloc）
    uint32_t keep = 0;
    for (uint32_t i = 0; i < st->nsyms; i++) {
        uint64_t v = nl[i].n_value;
        if (!v) continue;
        uint32_t sx = nl[i].n_un.n_strx;
        if (sx >= st->strsize) continue;                 // 名字越界保护
        const char *nm = strtb + sx;
        if (nm[0] != '_') continue;
        if (!strncmp(nm, "_il2cpp_", 8)) keep++;
        else if (!strncmp(nm, "_lua", 4)) keep++;
        else if (!strncmp(nm, "__ZN11TimeManager", 17)) keep++;
        else if (!strncmp(nm, "__Z", 3) && strstr(nm, "Time_Get_Custom_Prop")) keep++;
        else if (!strncmp(nm, "__Z", 3) && strstr(nm, "Time_Set_Custom_Prop")) keep++;
    }
    mlog(@"sym: pass1 raw=%u kept=%u", st->nsyms, keep);
    if (!keep) { mlog(@"sym: 0 symbols matched -> abort"); return; }

    // 第二遍：精确分配 + 填充
    g_syms = (mx_sym_t *)calloc(keep, sizeof(mx_sym_t));
    if (!g_syms) { mlog(@"sym: calloc failed"); return; }
    for (uint32_t i = 0; i < st->nsyms && g_symCount < keep; i++) {
        uint64_t v = nl[i].n_value;
        if (!v) continue;
        uint32_t sx = nl[i].n_un.n_strx;
        if (sx >= st->strsize) continue;
        const char *nm = strtb + sx;
        if (nm[0] != '_') continue;
        int keepIt = 0;
        if (!strncmp(nm, "_il2cpp_", 8)) keepIt = 1;
        else if (!strncmp(nm, "_lua", 4)) keepIt = 1;
        else if (!strncmp(nm, "__ZN11TimeManager", 17)) keepIt = 1;
        else if (!strncmp(nm, "__Z", 3) && strstr(nm, "Time_Get_Custom_Prop")) keepIt = 1;
        else if (!strncmp(nm, "__Z", 3) && strstr(nm, "Time_Set_Custom_Prop")) keepIt = 1;
        if (!keepIt) continue;
        g_syms[g_symCount].name = strdup(nm);
        g_syms[g_symCount].addr = (uintptr_t)(v + g_slide);   // n_value 是链接期地址，这里才需要 + slide
        if (g_syms[g_symCount].name) g_symCount++;
    }
    mlog(@"sym: table built, %u symbols (slide=%#lx)", g_symCount, (unsigned long)g_slide);
    if (!g_symCount) return;

    uint32_t cap = 1; while (cap < g_symCount * 2) cap <<= 1;
    g_hashBucket = (int32_t *)malloc(cap * sizeof(int32_t));
    if (!g_hashBucket) { mlog(@"sym: hash malloc failed"); return; }
    for (uint32_t i = 0; i < cap; i++) g_hashBucket[i] = -1;
    g_hashMask = cap - 1;
    for (uint32_t i = 0; i < g_symCount; i++) {
        uint32_t b = mx_hash(g_syms[i].name) & g_hashMask;
        while (g_hashBucket[b] != -1) b = (b + 1) & g_hashMask;
        g_hashBucket[b] = (int32_t)i;
    }
    mlog(@"sym: hash ready (cap=%u)", cap);
}

static void *mx_sym_find(const char *name) {
    if (!g_hashBucket) return NULL;
    uint32_t b = mx_hash(name) & g_hashMask;
    while (g_hashBucket[b] != -1) {
        const char *n = g_syms[g_hashBucket[b]].name;
        if (!strcmp(n, name)) return (void *)g_syms[g_hashBucket[b]].addr;
        b = (b + 1) & g_hashMask;
    }
    return NULL;
}

#pragma mark - ============ 函数指针热替换（代替内联 patch）============
// ⚠️ 为什么不做内联 hook：arm64 函数序言常含 ADRP/ADD 等 PC 相对指令，
//    覆写前几条指令极易踩雷；且代码段需 mprotect + 清 icache（iOS 上风险高）。
// 方案：只替换【我们目标函数的 IMP 指针】——C# MethodInfo->methodPointer
//       或 Lua 的 C 函数表项，都是数据段里的函数指针，写它 = 零风险。

typedef struct { void *target; void *replacement; void *orig; } mx_hook_t;
static mx_hook_t g_hooks[256];
static int       g_hookCount = 0;


#pragma mark - ============ il2cpp 反射（全部来自内存符号表）============
typedef void* Il2CppDomain;
typedef void* Il2CppImage;
typedef void* Il2CppClass;
typedef void* Il2CppMethodInfo;
typedef void* Il2CppFieldInfo;
typedef void* Il2CppObject;
typedef void* Il2CppString;
typedef void* Il2CppType;

typedef struct {
    Il2CppDomain      (*domain_get)(void);
    Il2CppImage*      (*domain_get_assemblies)(Il2CppDomain, size_t *);
    Il2CppImage       (*assembly_get_image)(void *);
    void*             (*domain_assembly_open)(Il2CppDomain, const char *);
    Il2CppClass*      (*class_from_name)(Il2CppImage, const char *, const char *);
    Il2CppMethodInfo* (*class_get_method_from_name)(Il2CppClass *, const char *, int);
    Il2CppMethodInfo* (*class_get_methods)(Il2CppClass *, void **);
    Il2CppFieldInfo*  (*class_get_field_from_name)(Il2CppClass *, const char *);
    Il2CppFieldInfo*  (*class_get_fields)(Il2CppClass *, void **);
    Il2CppClass*      (*class_get_parent)(Il2CppClass *);
    const char*       (*class_get_name)(Il2CppClass *);
    const char*       (*class_get_namespace)(Il2CppClass *);
    const char*       (*method_get_name)(Il2CppMethodInfo *);
    int               (*method_get_param_count)(Il2CppMethodInfo *);
    const char*       (*field_get_name)(Il2CppFieldInfo *);
    size_t            (*field_get_offset)(Il2CppFieldInfo *);
    void              (*field_get_value)(Il2CppObject *, Il2CppFieldInfo *, void *);
    void              (*field_set_value)(Il2CppObject *, Il2CppFieldInfo *, void *);
    void              (*field_static_get_value)(Il2CppFieldInfo *, void *);
    void              (*field_static_set_value)(Il2CppFieldInfo *, void *);
    Il2CppObject*     (*runtime_invoke)(Il2CppMethodInfo *, void *, void **, void **);
    Il2CppString*     (*string_new)(const char *);
    Il2CppObject*     (*object_new)(Il2CppClass *);
    void*             (*thread_attach)(Il2CppDomain);
    void*             (*thread_current)(void);
    void              (*gc_disable)(void);
    size_t            (*image_get_class_count)(Il2CppImage);
    Il2CppClass*      (*image_get_class)(Il2CppImage, size_t);
    const char*       (*image_get_name)(Il2CppImage);
    const char*       (*image_get_filename)(Il2CppImage);
    void*             (*class_get_static_field_data)(Il2CppClass *);
    void              (*class_init)(Il2CppClass *);
} mx_il2cpp_t;

static mx_il2cpp_t I;

static int mx_il2cpp_load(void) {
    static int ok = -1;
    if (ok >= 0) return ok;
    ok = 0;
    struct { const char *n; void **p; } t[] = {
        {"_il2cpp_domain_get",                 (void **)&I.domain_get},
        {"_il2cpp_domain_get_assemblies",      (void **)&I.domain_get_assemblies},
        {"_il2cpp_assembly_get_image",         (void **)&I.assembly_get_image},
        {"_il2cpp_domain_assembly_open",       (void **)&I.domain_assembly_open},
        {"_il2cpp_class_from_name",            (void **)&I.class_from_name},
        {"_il2cpp_class_get_method_from_name", (void **)&I.class_get_method_from_name},
        {"_il2cpp_class_get_methods",          (void **)&I.class_get_methods},
        {"_il2cpp_class_get_field_from_name",  (void **)&I.class_get_field_from_name},
        {"_il2cpp_class_get_fields",           (void **)&I.class_get_fields},
        {"_il2cpp_class_get_parent",           (void **)&I.class_get_parent},
        {"_il2cpp_class_get_name",             (void **)&I.class_get_name},
        {"_il2cpp_class_get_namespace",        (void **)&I.class_get_namespace},
        {"_il2cpp_method_get_name",            (void **)&I.method_get_name},
        {"_il2cpp_method_get_param_count",     (void **)&I.method_get_param_count},
        {"_il2cpp_field_get_name",             (void **)&I.field_get_name},
        {"_il2cpp_field_get_offset",           (void **)&I.field_get_offset},
        {"_il2cpp_field_get_value",            (void **)&I.field_get_value},
        {"_il2cpp_field_set_value",            (void **)&I.field_set_value},
        {"_il2cpp_field_static_get_value",     (void **)&I.field_static_get_value},
        {"_il2cpp_field_static_set_value",     (void **)&I.field_static_set_value},
        {"_il2cpp_runtime_invoke",             (void **)&I.runtime_invoke},
        {"_il2cpp_string_new",                 (void **)&I.string_new},
        {"_il2cpp_object_new",                 (void **)&I.object_new},
        {"_il2cpp_thread_attach",              (void **)&I.thread_attach},
        {"_il2cpp_thread_current",             (void **)&I.thread_current},
        {"_il2cpp_gc_disable",                 (void **)&I.gc_disable},
        {"_il2cpp_image_get_class_count",      (void **)&I.image_get_class_count},
        {"_il2cpp_image_get_name",             (void **)&I.image_get_name},
        {"_il2cpp_image_get_filename",         (void **)&I.image_get_filename},
        {"_il2cpp_image_get_class",            (void **)&I.image_get_class},
        {"_il2cpp_class_get_static_field_data",(void **)&I.class_get_static_field_data},
        {"_il2cpp_class_init",                 (void **)&I.class_init},
    };
    int miss = 0;
    for (size_t i = 0; i < sizeof(t)/sizeof(t[0]); i++) {
        *t[i].p = mx_sym_find(t[i].n);
        if (!*t[i].p) { mlog(@"il2cpp: MISSING %s", t[i].n); miss++; }
    }
    if (miss) { mlog(@"il2cpp: %d/%zu missing -> abort", miss, sizeof(t)/sizeof(t[0])); return 0; }
    ok = 1;
    mlog(@"il2cpp: %zu API resolved from in-memory symtab", sizeof(t)/sizeof(t[0]));
    return 1;
}


// 找类：先扫全部 image（Obfuz 下 image 顺序不保证），再按名打开
static Il2CppClass *mx_find_class(const char *ns, const char *name) {
    if (!mx_il2cpp_load()) return NULL;
    Il2CppDomain dom = I.domain_get();
    size_t n = 0;
    Il2CppImage *imgs = (Il2CppImage *)I.domain_get_assemblies(dom, &n);
    if (imgs) {
        for (size_t i = 0; i < n; i++) {
            if (!imgs[i]) continue;
            Il2CppClass *c = I.class_from_name(imgs[i], ns, name);
            if (c) return c;
        }
    }
    return NULL;
}

#pragma mark - ============ il2cpp 类/方法/字段 精确定位 ============
static Il2CppImage mx_image_by_name(const char *want) {
    if (!I.domain_get || !I.domain_get_assemblies || !I.image_get_name) return NULL;
    Il2CppDomain dom = I.domain_get();
    size_t n = 0;
    Il2CppImage *imgs = (Il2CppImage *)I.domain_get_assemblies(dom, &n);
    if (!imgs) return NULL;
    for (size_t i = 0; i < n; i++) {
        if (!imgs[i]) continue;
        Il2CppImage im = (Il2CppImage)imgs[i];
        const char *nm = I.image_get_name(im);
        if (nm && !strcmp(nm, want)) return im;
    }
    return NULL;
}

// Obfuz 下 image 遍历顺序不定，这里全 image 扫（并缓存结果）
static Il2CppClass *mx_class(const char *ns, const char *name) {
    if (!mx_il2cpp_load()) return NULL;
    Il2CppDomain dom = I.domain_get();
    size_t n = 0;
    Il2CppImage *imgs = (Il2CppImage *)I.domain_get_assemblies(dom, &n);
    if (imgs) {
        for (size_t i = 0; i < n; i++) {
            if (!imgs[i]) continue;
            Il2CppClass *c = I.class_from_name((Il2CppImage)imgs[i], ns, name);
            if (c) return c;
        }
    }
    return NULL;
}

static Il2CppMethodInfo *mx_meth(Il2CppClass *k, const char *name, int argc) {
    if (!k || !I.class_get_method_from_name) return NULL;
    Il2CppMethodInfo *m = I.class_get_method_from_name(k, name, argc);
    if (m) return m;
    // 迭代器兜底（Obfuz 偶发名字命中失败）
    if (I.class_get_methods && I.method_get_name && I.method_get_param_count) {
        void *it = NULL;
        Il2CppMethodInfo *mm;
        int guard = 0;
        while ((mm = I.class_get_methods(k, &it)) != NULL && guard++ < 4096) {
            const char *mn = I.method_get_name(mm);
            if (mn && !strcmp(mn, name) && I.method_get_param_count(mm) == argc) return mm;
        }
    }
    return NULL;
}

static size_t mx_field_off(Il2CppClass *k, const char *name, Il2CppFieldInfo **out) {
    if (!k || !I.class_get_field_from_name) return (size_t)-1;
    Il2CppFieldInfo *f = I.class_get_field_from_name(k, name);
    if (!f) {
        // 迭代器兜底
        void *it = NULL; Il2CppFieldInfo *ff; int guard = 0;
        while ((ff = I.class_get_fields(k, &it)) != NULL && guard++ < 8192) {
            const char *fn = I.field_get_name(ff);
            if (fn && !strcmp(fn, name)) { f = ff; break; }
        }
    }
    if (!f) return (size_t)-1;
    if (out) *out = f;
    return I.field_get_offset(f);
}

#pragma mark - ============ MethodInfo 布局自探测 ============
// ⚠️ 不同 il2cpp 版本 MethodInfo 布局不同（2022+ 多了 virtualMethodPointer）。
// 用「name 字段里必须是 'Update'」来唯一确定布局，而不是硬编码偏移。
typedef struct {
    int      ptrOff;    // methodPointer 偏移
    int      nameOff;   // name 偏移
    int      klassOff;  // klass 偏移
} mx_mi_layout_t;
static mx_mi_layout_t g_mi = { -1, -1, -1 };

static int mx_ptr_plausible(uintptr_t p) {
    if (p < 0x1000) return 0;
    const struct mach_header_64 *mh = mx_unity_header();
    if (!mh) return 0;
    uintptr_t base = (uintptr_t)mh;
    return (p >= base && p < base + kUnityTextSize);
}

static int mx_layout_probe(Il2CppMethodInfo *mi) {
    if (!mi) return 0;
    uint8_t *b = (uint8_t *)mi;
    // 候选：ptrOff ∈ {0, 8}, nameOff ∈ {8,16,24,32}, klassOff ∈ {16,24,32,40}
    static const int po[] = {0, 8};
    static const int no[] = {8, 16, 24, 32};
    static const int ko[] = {16, 24, 32, 40};
    for (int a = 0; a < 2; a++) {
        for (int c = 0; c < 4; c++) {
            uintptr_t np = *(uintptr_t *)(b + no[c]);
            if (!mx_ptr_plausible(np)) continue;
            if (strcmp((const char *)np, "Update")) continue;
            for (int d = 0; d < 4; d++) {
                uintptr_t kp = *(uintptr_t *)(b + ko[d]);
                if (kp < 0x100000000ULL) continue;
                // name 命中即确认
                g_mi.ptrOff = po[a]; g_mi.nameOff = no[c]; g_mi.klassOff = ko[d];
                mlog(@"mi layout: ptr=%d name=%d klass=%d (ptr=%p)",
                     po[a], no[c], ko[d], (void *)*(uintptr_t *)(b + po[a]));
                return 1;
            }
        }
    }
    // 打原始字节，便于下一版精确修正
    char hex[3 * 64 + 1]; hex[0] = 0;
    for (int i = 0; i < 64; i++) snprintf(hex + i*3, 4, "%02x ", b[i]);
    mlog(@"mi layout FAILED, raw64=%s", hex);
    return 0;
}

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
    int            (*rawgeti)(lua_State *, int, long long);
    unsigned long long (*rawlen)(lua_State *, int);
    void           (*pushlightuserdata)(lua_State *, void *);
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
        {"_lua_rawgeti",      (void **)&L.rawgeti},
        {"_lua_rawlen",       (void **)&L.rawlen},
    };
    int miss = 0;
    for (size_t i = 0; i < sizeof(t)/sizeof(t[0]); i++) {
        *t[i].p = mx_sym_find(t[i].n);
        if (!*t[i].p) { mlog(@"lua: MISSING %s", t[i].n); miss++; }
    }
    if (miss) return 0;
    ok = 1;
    mlog(@"lua: 17/17 C API resolved");
    return 1;
}

#pragma mark - ============ 全局加速（纯 il2cpp 反射：Time.timeScale）============
// 不用内联 patch，不碰 C++ 私有方法。直接 invoke 官方托管 API:
//   UnityEngine.Time.set_timeScale(float)  —— 引擎与托管侧统一变速，Lua 动画/渲染全覆盖
static Il2CppMethodInfo *g_timeSetScale = NULL;
static Il2CppMethodInfo *g_timeGetScale = NULL;
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
"local WRAPPED = setmetatable({}, { __mode = 'k' })\n"
"local wrapped = 0\n"
"local function wrapFn(tbl, key, path, kind)\n"
"  local ok, f = pcall(function() return tbl[key] end)\n"
"  if not ok or type(f) ~= 'function' then return end\n"
"  if WRAPPED[f] then return end\n"
"  WRAPPED[f] = true\n"
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

static void mx_apply_speed(void) {
    float mul = g_speedTable[g_speedIdx];
    if (fabsf(mul - g_speedMul) < 0.0001f) return;
    g_speedMul = mul;
    mx_time_apply(mul);
    mlog(@"timeScale -> %g", mul);
}

#pragma mark - ============ 前置声明 ============
static void  mx_build_window(void);
static void  mx_apply_speed(void);
static void  mx_time_warmup(void);
static void  mx_time_apply(float mul);
static void  mx_install_lua_hook(void);
static void  mx_syms_load(void);
static void *mx_sym_find(const char *name);
static int   mx_il2cpp_load(void);
static int   mx_lua_load(void);
static Il2CppClass *mx_class(const char *ns, const char *name);
static Il2CppMethodInfo *mx_meth(Il2CppClass *k, const char *name, int argc);
static size_t mx_field_off(Il2CppClass *k, const char *name, Il2CppFieldInfo **out);
static int   mx_layout_probe(Il2CppMethodInfo *mi);
static int   mx_ptr_plausible(uintptr_t p);
static const struct mach_header_64 *mx_unity_header(void);
static void  mx_dump_found(void);

// 面板开关状态（part6 的 LuaSvr hook 与 part7 的面板都要读）

#pragma mark - ============ 悬浮 UI（独立 window + 穿透，Unity 系实证方案）============
#define BALL_SIZE 58.0
#define PANEL_W   250.0
#define PANEL_H   168.0

static UIWindow *g_win   = nil;
static UIView   *g_ball  = nil;
static UIView   *g_panel = nil;


@interface CJPassthrough : UIView @end
@implementation CJPassthrough
- (UIView *)hitTest:(CGPoint)p withEvent:(UIEvent *)e {
    UIView *v = [super hitTest:p withEvent:e];
    return (v == self) ? nil : v;   // 空白区放行 → 触摸穿透到游戏
}
@end

// 让 window 的 root view 真正是一个 CJPassthrough（否则穿透失效）
@interface CJRootVC : UIViewController @end
@implementation CJRootVC
- (void)loadView {
    self.view = [[CJPassthrough alloc] initWithFrame:[UIScreen mainScreen].bounds];
    self.view.backgroundColor = [UIColor clearColor];
}
@end

static UIView *mx_ball_view(CGFloat size) {
    UIView *v = [[UIView alloc] initWithFrame:CGRectMake(0, 0, size, size)];

    // 抖音同款 conic 彩虹环
    CAGradientLayer *g = [CAGradientLayer layer];
    g.type = kCAGradientLayerConic;
    g.colors = @[(id)mx_c(0, 217, 217, 1).CGColor,
                 (id)mx_c(90, 90, 255, 1).CGColor,
                 (id)mx_c(255, 38, 38, 1).CGColor,
                 (id)mx_c(255, 140, 0, 1).CGColor,
                 (id)mx_c(0, 217, 217, 1).CGColor];
    g.locations = @[@0.0, @0.25, @0.5, @0.75, @1.0];
    g.frame = v.bounds;

    CAShapeLayer *mask = [CAShapeLayer layer];
    UIBezierPath *bp = [UIBezierPath bezierPathWithOvalInRect:v.bounds];
    [bp appendPath:[UIBezierPath bezierPathWithOvalInRect:CGRectInset(v.bounds, size*0.08, size*0.08)]];
    mask.path = bp.CGPath;
    mask.fillRule = kCAFillRuleEvenOdd;
    g.mask = mask;
    [v.layer addSublayer:g];

    UIImageView *iv = [[UIImageView alloc] initWithFrame:CGRectInset(v.bounds, size*0.10, size*0.10)];
    iv.image = mx_avatar();
    iv.contentMode = UIViewContentModeScaleAspectFill;
    iv.layer.cornerRadius = iv.bounds.size.width / 2.0;
    iv.layer.masksToBounds = YES;
    iv.userInteractionEnabled = NO;
    [v addSubview:iv];
    v.userInteractionEnabled = NO;   // 点击交给外层 g_ball
    return v;
}

@interface CJBox : NSObject
+ (instancetype)shared;
- (void)ballTap;
- (void)ballDrag:(UIPanGestureRecognizer *)g;
- (void)panelDrag:(UIPanGestureRecognizer *)g;
- (void)keepTick;
@end

static CJBox *g_box = nil;

@implementation CJBox
+ (instancetype)shared { if (!g_box) g_box = [CJBox new]; return g_box; }

- (void)ballTap {
    if (!g_panel) { mlog(@"panel: nil"); return; }
    g_panel.hidden = !g_panel.hidden;
    if (!g_panel.hidden) {
        // 面板贴着球弹出，自动避屏边
        UIView *root = g_panel.superview;
        CGRect b = root.bounds;
        CGFloat x = g_ball.center.x - BALL_SIZE/2 - PANEL_W;
        if (x < 6) x = g_ball.center.x + BALL_SIZE/2 + 6;
        if (x + PANEL_W > b.size.width - 6) x = b.size.width - PANEL_W - 6;
        CGFloat y = g_ball.center.y - PANEL_H/2;
        y = MIN(MAX(y, 8), b.size.height - PANEL_H - 8);
        g_panel.frame = CGRectMake(x, y, PANEL_W, PANEL_H);
        [root bringSubviewToFront:g_panel];
    }
    mlog(@"panel toggled hidden=%d", g_panel.hidden);
}

- (void)ballDrag:(UIPanGestureRecognizer *)g {
    UIView *v = g.view;
    CGPoint t = [g translationInView:v.superview];
    CGPoint nc = CGPointMake(v.center.x + t.x, v.center.y + t.y);
    CGRect b = v.superview.bounds;
    nc.x = MIN(MAX(nc.x, BALL_SIZE/2 + 4), b.size.width  - BALL_SIZE/2 - 4);
    nc.y = MIN(MAX(nc.y, BALL_SIZE/2 + 4), b.size.height - BALL_SIZE/2 - 4);
    v.center = nc;
    [g setTranslation:CGPointZero inView:v.superview];
}

- (void)panelDrag:(UIPanGestureRecognizer *)g {
    UIView *v = g.view;
    CGPoint t = [g translationInView:v.superview];
    CGPoint nc = CGPointMake(v.center.x + t.x, v.center.y + t.y);
    CGRect b = v.superview.bounds;
    nc.x = MIN(MAX(nc.x, PANEL_W/2), b.size.width  - PANEL_W/2);
    nc.y = MIN(MAX(nc.y, PANEL_H/2), b.size.height - PANEL_H/2);
    v.center = nc;
    [g setTranslation:CGPointZero inView:v.superview];
}

- (void)keepTick {
    @autoreleasepool {
        @try {
            if (!g_win || !g_win.rootViewController.view || g_ball.superview == nil) {
                mlog(@"overlay lost, rebuild");
                mx_build_window();
            }
            mx_apply_speed();
        } @catch (NSException *e) { mlog(@"keepTick exc %@", e.name); }
    }
}
@end

// --- 三个开关按钮 ---
static UIButton *mx_btn(NSString *t, id target, SEL a, CGFloat y) {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeCustom];
    b.frame = CGRectMake(12, y, PANEL_W - 24, 38);
    b.backgroundColor = mx_c(255, 255, 255, 0.10);
    b.layer.cornerRadius = 9;
    b.layer.borderWidth = 1;
    b.layer.borderColor = mx_c(255, 255, 255, 0.18).CGColor;
    [b setTitle:t forState:UIControlStateNormal];
    [b setTitleColor:mx_c(235, 235, 235, 1) forState:UIControlStateNormal];
    b.titleLabel.font = [UIFont boldSystemFontOfSize:15];
    [b addTarget:target action:a forControlEvents:UIControlEventTouchUpInside];
    return b;
}

@interface CJPanel : UIView
- (void)toggleInv;
- (void)toggleOne;
- (void)toggleSpd;
- (void)refresh;
- (void)close;
@end
@implementation CJPanel
- (void)toggleInv  { g_inv = !g_inv;      [self refresh]; mlog(@"flag invincible=%d", g_inv); }
- (void)toggleOne  { g_oneshot = !g_oneshot; [self refresh]; mlog(@"flag oneshot=%d", g_oneshot); }
- (void)toggleSpd  { g_speedIdx = (g_speedIdx + 1) % 4; [self refresh];
                     mlog(@"flag speedIdx=%d", g_speedIdx); }
- (void)refresh {
    static const char *sp[4] = { "OFF", "x2", "x4", "x8" };
    UIButton *b1 = (UIButton *)[self viewWithTag:101];
    UIButton *b2 = (UIButton *)[self viewWithTag:102];
    UIButton *b3 = (UIButton *)[self viewWithTag:103];
    [b1 setTitle:[NSString stringWithFormat:@"无敌  %@", g_inv ? @"ON" : @"OFF"] forState:UIControlStateNormal];
    [b2 setTitle:[NSString stringWithFormat:@"秒杀  %@", g_oneshot ? @"ON" : @"OFF"] forState:UIControlStateNormal];
    [b3 setTitle:[NSString stringWithFormat:@"加速  %s", sp[g_speedIdx]] forState:UIControlStateNormal];
    b1.backgroundColor = g_inv     ? mx_c(0, 190, 120, 0.45) : mx_c(255,255,255,0.10);
    b2.backgroundColor = g_oneshot ? mx_c(0, 190, 120, 0.45) : mx_c(255,255,255,0.10);
    b3.backgroundColor = g_speedIdx ? mx_c(0, 140, 255, 0.45) : mx_c(255,255,255,0.10);
}
- (void)close { self.hidden = YES; }
@end

static void mx_build_panel(void) {
    CJPanel *p = [[CJPanel alloc] initWithFrame:CGRectMake(20, 120, PANEL_W, PANEL_H)];
    p.backgroundColor = mx_c(22, 24, 30, 0.94);
    p.layer.cornerRadius = 14;
    p.layer.borderWidth = 1;
    p.layer.borderColor = mx_c(255, 255, 255, 0.13).CGColor;
    p.layer.shadowColor = [UIColor blackColor].CGColor;
    p.layer.shadowOpacity = 0.5; p.layer.shadowRadius = 8; p.layer.shadowOffset = CGSizeMake(0,3);

    UIView *head = mx_ball_view(36);
    head.frame = CGRectMake(12, 10, 36, 36);
    [p addSubview:head];

    UILabel *t = [[UILabel alloc] initWithFrame:CGRectMake(56, 12, PANEL_W - 90, 22)];
    t.text = @"✦ 昆哥儿科技 ✦";
    t.textColor = mx_c(255, 205, 90, 1);
    t.font = [UIFont boldSystemFontOfSize:16];
    [p addSubview:t];
    UILabel *sub = [[UILabel alloc] initWithFrame:CGRectMake(56, 32, PANEL_W - 90, 16)];
    sub.text = @"创界传说 · 悬浮助手";
    sub.textColor = mx_c(160, 165, 175, 1);
    sub.font = [UIFont systemFontOfSize:10];
    [p addSubview:sub];

    UIButton *x = [UIButton buttonWithType:UIButtonTypeCustom];
    x.frame = CGRectMake(PANEL_W - 34, 8, 26, 26);
    x.layer.cornerRadius = 13;
    x.backgroundColor = mx_c(255, 255, 255, 0.10);
    [x setTitle:@"✕" forState:UIControlStateNormal];
    [x addTarget:p action:@selector(close) forControlEvents:UIControlEventTouchUpInside];
    [p addSubview:x];

    UIButton *b1 = mx_btn(@"无敌  OFF", p, @selector(toggleInv), 54);  b1.tag = 101; [p addSubview:b1];
    UIButton *b2 = mx_btn(@"秒杀  OFF", p, @selector(toggleOne), 98);  b2.tag = 102; [p addSubview:b2];
    UIButton *b3 = mx_btn(@"加速  OFF", p, @selector(toggleSpd), 138); b3.tag = 103; [p addSubview:b3];

    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:[CJBox shared] action:@selector(panelDrag:)];
    [p addGestureRecognizer:pan];
    [p refresh];
    g_panel = p;
}

static void mx_build_window(void) {
    if (g_win && g_win.rootViewController.view && g_ball.superview) { return; }
    if (g_win) { g_win.hidden = YES; g_win = nil; g_ball = nil; g_panel = nil; }

    g_win = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    g_win.windowLevel = CGFLOAT_MAX;
    g_win.rootViewController = [CJRootVC new];
    g_win.backgroundColor = [UIColor clearColor];
    g_win.hidden = NO;

    CJPassthrough *root = (CJPassthrough *)g_win.rootViewController.view;

    g_ball = [[UIView alloc] initWithFrame:CGRectMake(0, 0, BALL_SIZE, BALL_SIZE)];
    g_ball.center = CGPointMake(root.bounds.size.width - BALL_SIZE/2 - 18, 150);
    UIView *bv = mx_ball_view(BALL_SIZE);
    bv.frame = g_ball.bounds;
    [g_ball addSubview:bv];
    g_ball.layer.shadowColor = [UIColor blackColor].CGColor;
    g_ball.layer.shadowOpacity = 0.4; g_ball.layer.shadowRadius = 4;
    g_ball.layer.shadowOffset = CGSizeMake(0, 2);
    [root addSubview:g_ball];

    UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc] initWithTarget:[CJBox shared] action:@selector(ballTap)];
    [g_ball addGestureRecognizer:tap];
    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:[CJBox shared] action:@selector(ballDrag:)];
    [g_ball addGestureRecognizer:pan];

    mx_build_panel();
    g_panel.hidden = YES;
    [root addSubview:g_panel];

    mlog(@"overlay built (%.0fx%.0f)", root.bounds.size.width, root.bounds.size.height);
}

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
                if (!g_timeSetScale) mx_time_warmup();
                mx_install_lua_hook();
                mx_apply_speed();
                break;
            default: {
                g_ctorStage = 3;
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


#pragma mark - 导出 Lua 自发现结果（下次精确定位用）
static void mx_dump_found(void) {
    if (!g_L || !L.getglobal || !L.tolstring) return;
    L.getglobal(g_L, "__CJCS_FOUND");
    if (L.type(g_L, -1) != 5) { L.settop(g_L, -L.gettop(g_L)); return; }
    // 表里有 n 个字符串元素，逐个取
    NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/cjcs_lua_found.txt"];
    NSMutableString *out = [NSMutableString string];
    if (!L.rawgeti || !L.rawlen) { mlog(@"dump: rawgeti/rawlen missing"); return; }
    int n = (int)L.rawlen(g_L, -1);
    for (int i = 1; i <= n && i < 800; i++) {
        L.rawgeti(g_L, -1, i);
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

static void cjcs_boot(void);

__attribute__((constructor)) static void cjcs_ctor(void) { cjcs_boot(); }

// 双保险：ObjC +load 在 dylib 被 dyld 载入时必定执行（不依赖 __mod_init_func / __init_offsets）
@interface MXLoader : NSObject @end
@implementation MXLoader
+ (void)load { cjcs_boot(); }
@end

static void cjcs_boot(void) {
    static int booted = 0;
    if (booted) return;      // 两个入口只跑一次
    booted = 1;
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
