
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
    mlog(@"il2cpp: 30/30 API resolved from in-memory symtab");
    return 1;
}

// 取程序集 image（按名字）
static Il2CppImage mx_image_named(const char *asmName) {
    if (!I.domain_get || !I.domain_get_assemblies) return NULL;
    Il2CppDomain dom = I.domain_get();
    size_t n = 0;
    Il2CppImage *imgs = (Il2CppImage *)I.domain_get_assemblies(dom, &n);
    if (!imgs) return NULL;
    for (size_t i = 0; i < n; i++) {
        if (!imgs[i]) continue;
        const char *nm = I.class_get_name ? NULL : NULL;
        (void)nm;
        // il2cpp_assembly_get_image 拿到的是 image，名字要靠 il2cpp_image_get_name
        // 这里用 domain_assembly_open 更直接（按名打开）
    }
    return NULL;
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
