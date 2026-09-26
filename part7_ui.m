
#pragma mark - ============ 悬浮 UI（独立 window + 穿透，Unity 系实证方案）============
#define BALL_SIZE 58.0
#define PANEL_W   250.0
#define PANEL_H   168.0

static UIWindow *g_win   = nil;
static UIView   *g_ball  = nil;
static UIView   *g_panel = nil;

volatile int g_inv = 0, g_oneshot = 0;

@interface CJPassthrough : UIView @end
@implementation CJPassthrough
- (UIView *)hitTest:(CGPoint)p withEvent:(UIEvent *)e {
    UIView *v = [super hitTest:p withEvent:e];
    return (v == self) ? nil : v;   // 空白区放行 → 触摸穿透到游戏
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
                extern void mx_build_window(void);
                mx_build_window();
            }
            extern void mx_apply_speed(void);
            mx_apply_speed();
        } @catch (NSException *e) { mlog(@"keepTick exc %@", e.name); }
    }
}
@end

// --- 三个开关按钮 ---
static UIButton *mx_btn(NSString *t, SEL a, CGFloat y) {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeCustom];
    b.frame = CGRectMake(12, y, PANEL_W - 24, 38);
    b.backgroundColor = mx_c(255, 255, 255, 0.10);
    b.layer.cornerRadius = 9;
    b.layer.borderWidth = 1;
    b.layer.borderColor = mx_c(255, 255, 255, 0.18).CGColor;
    [b setTitle:t forState:UIControlStateNormal];
    [b setTitleColor:mx_c(235, 235, 235, 1) forState:UIControlStateNormal];
    b.titleLabel.font = [UIFont boldSystemFontOfSize:15];
    [b addTarget:[CJBox shared] action:a forControlEvents:UIControlEventTouchUpInside];
    return b;
}

@interface CJPanel : UIView @end
@implementation CJPanel
- (void)toggleInv  { g_inv = !g_inv;      [self refresh]; mlog(@"flag invincible=%d", g_inv); }
- (void)toggleOne  { g_oneshot = !g_oneshot; [self refresh]; mlog(@"flag oneshot=%d", g_oneshot); }
- (void)toggleSpd  { extern int g_speedIdx; g_speedIdx = (g_speedIdx + 1) % 4; [self refresh];
                     mlog(@"flag speedIdx=%d", g_speedIdx); }
- (void)refresh {
    extern int g_speedIdx;
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

    UIButton *b1 = mx_btn(@"无敌  OFF", @selector(toggleInv), 54);  b1.tag = 101; [p addSubview:b1];
    UIButton *b2 = mx_btn(@"秒杀  OFF", @selector(toggleOne), 98);  b2.tag = 102; [p addSubview:b2];
    UIButton *b3 = mx_btn(@"加速  OFF", @selector(toggleSpd), 138); b3.tag = 103; [p addSubview:b3];

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
    g_win.rootViewController = [UIViewController new];
    g_win.backgroundColor = [UIColor clearColor];
    g_win.hidden = NO;

    CJPassthrough *root = (CJPassthrough *)g_win.rootViewController.view;
    root.backgroundColor = [UIColor clearColor];

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
