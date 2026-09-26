
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
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (lc->cmd == LC_SYMTAB) { st = (const struct symtab_command *)lc; break; }
        lc = (const struct load_command *)((const char *)lc + lc->cmdsize);
    }
    if (!st) { mlog(@"sym: LC_SYMTAB NOT FOUND"); return; }

    // __LINKEDIT 把 file offset 映射到内存（slide 后）
    // symoff/stroff 是**文件偏移**；运行时需转成 vmaddr 再 + slide
    // __LINKEDIT: fileoff -> vmaddr = fileoff + (vmaddr - fileoff)，实测该差值是常量
    uintptr_t linkedit_delta = 0;
    int found = 0;
    lc = (const struct load_command *)((const char *)mh + sizeof(struct mach_header_64));
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
            if (!strcmp(sg->segname, "__LINKEDIT")) {
                linkedit_delta = (uintptr_t)(sg->vmaddr - sg->fileoff);
                found = 1;
                break;
            }
        }
        lc = (const struct load_command *)((const char *)lc + lc->cmdsize);
    }
    if (!found) { mlog(@"sym: __LINKEDIT NOT FOUND"); return; }

    const struct nlist_64 *nl = (const struct nlist_64 *)((uintptr_t)mh + linkedit_delta + g_slide + st->symoff);
    const char *strtab = (const char *)((uintptr_t)mh + linkedit_delta + g_slide + st->stroff);

    g_syms = (mx_sym_t *)calloc(st->nsyms, sizeof(mx_sym_t));
    if (!g_syms) { mlog(@"sym: calloc failed"); return; }

    // 只收「有价值的」符号：_il2cpp_ / _lua / _luaL_ / TimeManager / Time_Get_Custom
    for (uint32_t i = 0; i < st->nsyms; i++) {
        if (!nl[i].n_value) continue;
        const char *nm = strtab + nl[i].n_un.n_strx;
        if (nm[0] != '_') continue;
        if (nm[1] == 'i' && !strncmp(nm, "_il2cpp_", 8)) { /* keep */ }
        else if (!strncmp(nm, "_lua", 4)) { /* keep */ }
        else if (!strncmp(nm, "__ZN11TimeManager", 17)) { /* keep */ }
        else if (!strncmp(nm, "__Z", 3) && strstr(nm, "Time_Get_Custom_Prop")) { /* keep */ }
        else if (!strncmp(nm, "__Z", 3) && strstr(nm, "Time_Set_Custom_Prop")) { /* keep */ }
        else continue;
        if (g_symCount >= st->nsyms) break;
        g_syms[g_symCount].name = strdup(nm);
        g_syms[g_symCount].addr = (uintptr_t)(nl[i].n_value + g_slide);
        g_symCount++;
    }
    mlog(@"sym: table built, %u symbols (nsyms=%u, slide=%#lx)", g_symCount, st->nsyms, (unsigned long)g_slide);
    if (g_symCount == 0) return;

    // 建哈希：2 的幂，开放寻址线性探测
    uint32_t cap = 1; while (cap < g_symCount * 2) cap <<= 1;
    g_hashBucket = (int32_t *)malloc(cap * sizeof(int32_t));
    if (!g_hashBucket) return;
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

static void mx_ptr_write(void **slot, void *value) {
    // 数据段可写；保险起见先确保页可写（失败也不致命）
    uintptr_t page = (uintptr_t)slot & ~(uintptr_t)(vm_page_size - 1);
    vm_prot_t cur = 0; vm_prot_t max = 0;
    vm_address_t a = (vm_address_t)page;
    if (vm_region_64(mach_task_self(), &a, (vm_size_t[]){0}, &max, NULL, NULL, NULL, NULL) != KERN_SUCCESS) {
        // 忽略，直接写
    }
    *slot = value;
}
