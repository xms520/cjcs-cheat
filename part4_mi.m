
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
    uintptr_t base = 0; size_t sz = 0;
    // 只需落在 UnityFramework __TEXT 内：slide .. slide+0x593c000
    extern const struct mach_header_64 *mx_unity_header(void);
    const struct mach_header_64 *mh = mx_unity_header();
    if (!mh) return 0;
    base = (uintptr_t)mh;
    // 用已知代码段大小粗判
    sz = 0x593c000;
    return (p >= base && p < base + sz);
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
