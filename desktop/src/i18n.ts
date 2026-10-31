// SPDX-License-Identifier: Apache-2.0
// UI copy: zh-CN (default) and complete English. Honesty rules (CONTRACTS §14) apply:
// no "verified" compatibility claims, no "first", experimental features labelled, and the
// product is stated to be not yet independently audited.

export type Lang = "zh-CN" | "en";

const zh = {
  appName: "AI 通行证",
  tagline: "让人少操心每一个密码，让 AI 在授权范围内使用账号。",
  notAudited: "本产品尚未经过独立安全审计。",
  // nav
  navOverview: "总览", navAccounts: "账号", navConnections: "AI 连接", navExecutors: "执行设备", navActivity: "活动", navSettings: "设置",
  lockNow: "立即锁定", pendingApprovals: "待处理",
  // common
  save: "保存", cancel: "取消", close: "关闭", confirm: "确认", back: "返回", next: "下一步", delete: "删除", edit: "编辑", add: "添加", retry: "重试",
  copy: "复制", copied: "已复制，{s} 秒后自动清除剪贴板；已要求系统不记入剪贴板历史与云同步（个别剪贴板工具可能不遵守）", loading: "正在加载…", none: "暂无", search: "搜索", refresh: "刷新", done: "完成",
  yes: "是", no: "否", optional: "可选", required: "必填", status: "状态", details: "详情", actions: "操作", experimental: "实验性",
  // status vocabulary
  stAvailable: "可用", stReauth: "需要重新登录", stConflict: "同步冲突", stDeviceOffline: "设备离线", stExecutorOffline: "执行设备离线",
  stPending: "待处理", stRevoked: "已撤销", stPartialRevoke: "部分撤销失败", stImported: "已导入", stVerified: "已验证", stNeedsAction: "需要处理",
  // unlock
  unlockTitle: "解锁 AI 通行证", unlockHint: "输入本机解锁密码。它保护这台电脑上的设备密钥，不会上传。",
  unlockPassword: "本机解锁密码", unlock: "解锁", forgotPassword: "忘记解锁密码？请用恢复密钥在本机重新加入账号库。",
  // onboarding
  obWelcome: "欢迎使用 AI 通行证", obChoose: "这台电脑还没有账号库。",
  obCreate: "新建账号库", obCreateDesc: "在这台电脑上创建，之后可以绑定手机。",
  obJoin: "加入已有账号库", obJoinDesc: "账号库已在手机或另一台电脑上？显示二维码，由那台设备确认。",
  obDeviceName: "设备名称", obPassword: "本机解锁密码（至少 8 位）", obPassword2: "再次输入", obPasswordMismatch: "两次输入的密码不一致",
  obPasswordNote: "解锁密码只保护本机保存的设备密钥；它不是恢复材料。",
  obStorage: "选择存储位置", obStorageNote: "存储只保存加密后的数据。使用前会做一次读写能力测试，未通过的位置只能用于备份。",
  stLocal: "本机文件夹", stLocalDesc: "例如放在你自己的同步盘目录中。", stOfficial: "官方同步", stOfficialDesc: "需要 AI 通行证账户与订阅；服务端只保存密文。",
  stS3: "S3 兼容存储", stS3Desc: "你自己的存储桶（AWS S3、R2、MinIO 等）。", stSelfhost: "自托管节点", stSelfhostDesc: "你自己的 aipass-node 服务器。",
  folder: "文件夹路径", endpoint: "端点地址", region: "区域", bucket: "存储桶", prefix: "前缀", accessKey: "Access Key ID", secretKey: "Secret Access Key", pathStyle: "路径样式寻址",
  nodeUrl: "节点地址", enrollToken: "注册令牌", runTest: "测试存储", testing: "正在测试…",
  capOk: "可同步：读、写、列举、条件写入均通过。", capBackup: "仅可备份：条件写入未通过，不能作为同步存储。",
  obCreating: "正在创建账号库…", obRecoveryTitle: "保存恢复密钥", obRecoveryDesc: "这是找回账号库的唯一材料。请抄写或保存恢复包，并妥善保管；丢失所有设备且没有恢复密钥时，任何人都无法恢复数据。",
  saveKit: "保存恢复包文件", kitSaved: "恢复包已保存到：{p}", obRecoveryOnce: "恢复密钥只显示这一次。",
  obVerifyTitle: "验证恢复密钥", obVerifyDesc: "请输入你保存的恢复密钥，确认它可用。", verify: "验证", verifyFail: "恢复密钥不匹配，请检查后重试。",
  obFirstActions: "接下来可以做三件事", actImport: "导入账号", actImportDesc: "从浏览器或其他密码管理器导入 CSV。",
  actConnect: "连接 AI", actConnectDesc: "让 Codex、Claude Code、Cursor 等通过本机接入桥使用授权资源。", actPhone: "绑定手机", actPhoneDesc: "把审批转到手机处理，丢失电脑也能撤销。",
  skipForNow: "稍后再说", relayUrl: "中继地址", relayHint: "用于配对与手机审批的中继服务（官方云或你的自托管节点）。",
  // overview
  ovTitle: "总览", ovExceptions: "需要处理", ovAllGood: "一切正常。", ovVault: "账号库", ovItems: "账号数", ovLastSync: "上次同步", ovNever: "从未",
  ovSyncNow: "立即同步", ovNode: "本机执行设备", ovNodeRunning: "运行中", ovNodeStopped: "未启动", ovRecentActivity: "最近活动",
  // accounts
  acTitle: "账号", acAdd: "添加账号", acEmpty: "还没有账号。可以导入 CSV，或手动添加。", acNoProject: "未归入项目", acImport: "导入 CSV", acConflicts: "冲突",
  fTitle: "名称", fUsername: "用户名", fPassword: "密码 / Key", fUrls: "网址（每行一个）", fNotes: "备注", fTotp: "两步验证密钥或 otpauth:// 链接", fProject: "项目", fTags: "标签（逗号分隔）", fKind: "类型",
  keepSecret: "留空则保留现有密码", clearSecret: "删除密码", clearTotp: "删除两步验证",
  kLogin: "网站登录", kApiKey: "API Key", kDatabase: "数据库", kOauth: "OAuth 令牌", kSsh: "SSH 密钥", kNote: "安全笔记", kStorage: "存储凭证",
  reveal: "查看原始密码", hide: "隐藏", autoHide: "{s} 秒后自动隐藏", copyPassword: "复制密码", copyUsername: "复制用户名", copyTotp: "复制验证码",
  totpCode: "验证码", deleteConfirm: "删除“{t}”？删除会同步到其他设备。",
  genTitle: "生成密码", genLength: "长度", genLower: "小写字母", genUpper: "大写字母", genDigits: "数字", genSymbols: "符号", genAmbiguous: "排除易混淆字符", genEach: "每类至少一个",
  genGenerate: "生成", genUse: "使用此密码", genReady: "已生成 {n} 位密码（不在界面显示，可复制或直接保存）。",
  impTitle: "导入 CSV", impRisk: "CSV 文件是明文。导入完成后请删除原文件，并清空回收站。文件内容只在本机 Rust 进程中读取，不进入界面。",
  impFormat: "来源格式", impPick: "选择 CSV 文件并导入", impResult: "已导入 {i} 个，重复 {d} 个，跳过 {s} 个。",
  cfTitle: "同步冲突", cfDesc: "两台设备产生了不同版本。请选择当前有效的版本；选择前，该账号不会用于自动填充和 AI 授权。", cfKeep: "保留此版本", cfCurrent: "当前版本", cfSecretDiffers: "密码不同",
  // reauth
  reauthTitle: "重新验证", reauthDesc: "查看原始密码和导出需要再次输入本机解锁密码。", reauthAgentWarn: "如果有 AI Agent 正在观察或操作这台电脑的屏幕，请不要在此显示密码。",
  // connections
  cnTitle: "AI 连接", cnHosts: "本机 AI 工具", cnDetect: "重新检测", cnInstalled: "已安装", cnNotInstalled: "未检测到", cnHasEntry: "已配置",
  cnConnect: "连接", cnRemove: "移除配置", cnPreview: "配置预览", cnPreviewDesc: "只会新增或修改名为 aipass 的条目；写入前自动备份原文件。配置中不含任何密码或 Key。",
  cnApply: "确认写入", cnApplied: "已写入。备份：{b}", cnScope: "范围", cnUser: "用户", cnProject: "项目", cnProjectDir: "项目目录（绝对路径）",
  cnAllowed: "允许访问的项目", cnAllProjects: "全部项目", cnConnections: "已连接的 AI 应用", cnPairPending: "等待确认的绑定",
  cnPairCode: "绑定码", cnPairCompare: "请确认 AI 工具中显示的绑定码与此一致。", cnApprove: "确认绑定", cnDeny: "拒绝",
  cnPause: "暂停", cnResume: "恢复", cnRevokeAll: "停止全部访问", cnRemoveConn: "删除连接", cnRemote: "远程接入（ChatGPT、Claude 连接器）",
  cnRemoteNote: "远程接入经官方网关转发到你的执行设备。官方网关会看到请求与结果内容，并非端到端盲转发。", cnNoTool: "当前宿主无工具入口",
  // executors
  exTitle: "执行设备", exLocal: "本机执行设备", exProtection: "保护等级", exCompatible: "兼容连接", exIsolated: "隔离执行",
  exCompatibleDesc: "本机执行设备与 AI 工具运行在同一个用户环境中：能防止正常工具链直接拿到凭证，但不能抵抗同一用户下的任意代码、调试或整机接管。",
  exIsolatedDesc: "隔离执行需要独立主机或经验证的受限虚拟机，由服务器运维方确认；本机执行设备不属于隔离执行。",
  exSocket: "接入桥地址", exResources: "资源", exAddResource: "添加资源", exPaired: "已配对的服务器", exPairServer: "配对服务器",
  rAlias: "资源别名（AI 可见）", rService: "服务", rConnector: "连接器", rEnv: "环境", rTest: "测试", rProd: "生产", rConfig: "连接器配置（JSON，不含密码）", rEntry: "凭证所在账号",
  // activity
  avTitle: "活动", avApprovals: "待审批", avOperations: "操作记录", avGrants: "授权", avAudit: "审计日志", avVerify: "校验审计链",
  avAuditOk: "审计链完整（{n} 条）。", avAuditBad: "审计链校验失败：{r}", avRevoke: "撤销", avLevels: "撤销级别",
  lvStop: "停止访问", lvEnd: "结束会话", lvUpstream: "上游撤销", avReport: "撤销报告",
  // approval
  apTitle: "访问请求", apRequester: "请求方", apVerified: "已核验身份", apUnverified: "身份未核验", apResource: "资源", apOperation: "操作", apData: "数据",
  apExcluded: "不含", apScope: "范围", apLimits: "额度", apDuration: "期限", apLocation: "执行位置", apRecipients: "结果接收方",
  apAllowOnce: "允许本次", apNarrow: "选择较小权限", apDeny: "拒绝", apToPhone: "转到手机处理", apConfirmPw: "本机解锁密码（每次批准都需要）", apConfirmPwDesc: "批准前必须重新输入解锁密码，避免能操作这台电脑的 AI Agent 自己点击批准。", apToPhoneDesc: "如果有 AI Agent 能观察或操作这台电脑，建议在手机上处理。请求会保留，直到批准、拒绝或过期。",
  apExpiresIn: "{s} 秒后过期", apExpired: "请求已过期", apRows: "最多 {n} 行", apMinutes: "最长 {n} 分钟", apTask: "本次任务",
  apRecipientsDefault: "本次连接的 AI 应用及其模型服务", apNoAutoApprove: "无人处理时不会自动批准。", apUnlockFirst: "先解锁账号库才能批准。",
  // pairing
  pTitle: "绑定手机", pModeShow: "这台电脑显示二维码", pModePaste: "粘贴手机上的配对链接",
  pShowDesc: "适用于账号库在手机上、这台电脑要加入。", pPasteDesc: "适用于账号库在这台电脑上，要把手机加入。在手机 App 中选择“添加此设备”，复制显示的 aipass://pair 链接。",
  pLink: "配对链接", pStart: "开始配对", pWaiting: "等待另一台设备…", pSas: "请确认两台设备显示相同的 6 位码",
  pSasMatch: "两边一致，确认加入", pSasMismatch: "不一致，取消", pCodeOnOther: "或输入另一台设备上显示的代码", pDone: "配对完成。", pFailed: "配对失败：{e}",
  pShareStorage: "同时共享存储凭证（S3 等）", pNoVaultNote: "扫码本身不会授予访问；必须在可信设备上确认安全码。",
  // settings
  sTitle: "设置", sStorage: "存储与迁移", sMigrate: "迁移到新位置", sMigrateDesc: "先验证新位置并完整复制、校验后才切换；旧位置的数据保留。",
  sCloud: "云账户与订阅", sEmail: "邮箱", sPassword: "密码", sLogin: "登录", sLogout: "退出登录", sCloudNote: "订阅账户与账号库分离：账户密码不能解密任何账号库。许可证失效只会停用付费功能，不影响解锁、导出、恢复和撤销。",
  sPlan: "套餐", sLicense: "许可证", sActivate: "在此设备激活", sLicValid: "有效", sLicInvalid: "未激活或已失效",
  sExport: "导出", sExportEnc: "加密导出（.aipassx）", sExportCsv: "明文 CSV 导出", sExportPassword: "导出文件密码（至少 10 位）",
  sCsvWarn: "明文 CSV 包含所有密码。仅在迁移到其他工具时使用，用完立即删除。",
  sRecovery: "恢复材料", sRecoveryVerified: "恢复密钥已验证", sRecoveryNotVerified: "恢复材料未验证", sReplaceKey: "更换恢复密钥",
  sDevices: "设备", sThisDevice: "本机", sRevokeDevice: "撤销此设备", sRevokeNote: "撤销会轮换账号库密钥。被撤销设备曾经看到的密码仍需要逐个更换。",
  sLanguage: "语言", sAbout: "关于", sVersion: "版本", sBrowser: "浏览器扩展", sExtId: "扩展 ID", sInstallHost: "安装本机连接组件",
  sLinkNode: "关联本机执行设备到云账户", sLinked: "已关联。", sTunnelStart: "启动远程接入", sTunnelStop: "停止远程接入", sTunnelState: "远程接入状态",
  sAutoLock: "自动锁定（秒，0 表示不自动锁定）", sClipboard: "剪贴板自动清除（秒）", sSaved: "已保存。", sRelay: "中继地址（手机审批）", sCloudUrl: "云服务地址",
  // exceptions (§11.5)
  exc_push_title: "手机没收到推送", exc_push_body: "通知未送达不代表任务已批准。", exc_push_next: "打开手机 App 拉取；超时的任务请重新发起。",
  exc_executor_title: "执行器离线", exc_executor_body: "账号库存在，但没有在线设备可执行。", exc_executor_next: "开启这台电脑的执行设备，或选择已配对的服务器。",
  exc_site_title: "网站变化", exc_site_body: "当前自动化适配器无法可靠定位登录流程。", exc_site_next: "请你接管，本次自动填充已停止。",
  exc_signup_title: "注册结果不确定", exc_signup_body: "已保存候选账号，尚未确认网站结果。", exc_signup_next: "先核对账号是否已存在，避免重复注册。",
  exc_revoke_title: "撤销部分失败", exc_revoke_body: "代理访问已停止，上游会话仍待处理。", exc_revoke_next: "查看失败的服务，并按提示手动处理。",
  exc_conflict_title: "新旧密码冲突", exc_conflict_body: "两台设备产生了不同版本。", exc_conflict_next: "在可信客户端选择并验证当前有效版本。",
  exc_recovery_title: "恢复材料未验证", exc_recovery_body: "当前设备丢失后，可能无法找回账号库。", exc_recovery_next: "完成恢复检查。",
  exc_host_title: "当前宿主无工具入口", exc_host_body: "这个版本不能直接连接。", exc_host_next: "改用标准协议可接入的宿主，或使用 SDK 路线。",
  goHandle: "处理异常",
};

type Dict = Record<keyof typeof zh, string>;

const en: Dict = {
  appName: "AI Pass",
  tagline: "Fewer passwords to worry about; AI uses accounts only within the scope you approve.",
  notAudited: "This product has not yet been independently security audited.",
  navOverview: "Overview", navAccounts: "Accounts", navConnections: "AI connections", navExecutors: "Executors", navActivity: "Activity", navSettings: "Settings",
  lockNow: "Lock now", pendingApprovals: "Pending",
  save: "Save", cancel: "Cancel", close: "Close", confirm: "Confirm", back: "Back", next: "Next", delete: "Delete", edit: "Edit", add: "Add", retry: "Retry",
  copy: "Copy", copied: "Copied; the clipboard is cleared in {s} s and the value is marked to stay out of clipboard history and cloud sync (some clipboard tools may ignore this)", loading: "Loading…", none: "None", search: "Search", refresh: "Refresh", done: "Done",
  yes: "Yes", no: "No", optional: "Optional", required: "Required", status: "Status", details: "Details", actions: "Actions", experimental: "Experimental",
  stAvailable: "Available", stReauth: "Sign-in needed", stConflict: "Sync conflict", stDeviceOffline: "Device offline", stExecutorOffline: "Executor offline",
  stPending: "Pending", stRevoked: "Revoked", stPartialRevoke: "Partially revoked", stImported: "Imported", stVerified: "Verified", stNeedsAction: "Needs action",
  unlockTitle: "Unlock AI Pass", unlockHint: "Enter the local unlock password. It protects this computer's device key and is never uploaded.",
  unlockPassword: "Local unlock password", unlock: "Unlock", forgotPassword: "Forgot it? Re-join the vault on this computer with your recovery key.",
  obWelcome: "Welcome to AI Pass", obChoose: "There is no vault on this computer yet.",
  obCreate: "Create a vault", obCreateDesc: "Create it on this computer; you can add your phone later.",
  obJoin: "Join an existing vault", obJoinDesc: "Vault already on your phone or another computer? Show a QR code and confirm on that device.",
  obDeviceName: "Device name", obPassword: "Local unlock password (8+ characters)", obPassword2: "Repeat", obPasswordMismatch: "The passwords do not match",
  obPasswordNote: "The unlock password only protects the device key stored on this computer; it is not recovery material.",
  obStorage: "Choose storage", obStorageNote: "Storage only holds encrypted data. A read/write capability test runs first; locations that fail can only be used for backups.",
  stLocal: "Local folder", stLocalDesc: "For example inside your own synced folder.", stOfficial: "Official sync", stOfficialDesc: "Needs an AI Pass account and subscription; the service stores ciphertext only.",
  stS3: "S3-compatible", stS3Desc: "Your own bucket (AWS S3, R2, MinIO, …).", stSelfhost: "Self-hosted node", stSelfhostDesc: "Your own aipass-node server.",
  folder: "Folder path", endpoint: "Endpoint", region: "Region", bucket: "Bucket", prefix: "Prefix", accessKey: "Access key ID", secretKey: "Secret access key", pathStyle: "Path-style addressing",
  nodeUrl: "Node URL", enrollToken: "Enrolment token", runTest: "Test storage", testing: "Testing…",
  capOk: "Sync-capable: read, write, list and conditional writes passed.", capBackup: "Backup only: conditional writes failed, so it cannot be used for sync.",
  obCreating: "Creating the vault…", obRecoveryTitle: "Save your recovery key", obRecoveryDesc: "This is the only material that can recover the vault. Write it down or save the recovery kit and keep it safe; if you lose all devices and this key, nobody can recover the data.",
  saveKit: "Save recovery kit file", kitSaved: "Recovery kit saved to: {p}", obRecoveryOnce: "The recovery key is shown only this once.",
  obVerifyTitle: "Verify the recovery key", obVerifyDesc: "Type the recovery key you saved to confirm it works.", verify: "Verify", verifyFail: "The recovery key does not match. Check it and try again.",
  obFirstActions: "Three things to do next", actImport: "Import accounts", actImportDesc: "Import a CSV from your browser or another password manager.",
  actConnect: "Connect AI", actConnectDesc: "Let Codex, Claude Code, Cursor and others use approved resources through the local bridge.", actPhone: "Add your phone", actPhoneDesc: "Approve on your phone, and revoke even if this computer is lost.",
  skipForNow: "Later", relayUrl: "Relay URL", relayHint: "Relay used for pairing and phone approvals (official cloud or your self-hosted node).",
  ovTitle: "Overview", ovExceptions: "Needs attention", ovAllGood: "All good.", ovVault: "Vault", ovItems: "Accounts", ovLastSync: "Last sync", ovNever: "Never",
  ovSyncNow: "Sync now", ovNode: "Local executor", ovNodeRunning: "Running", ovNodeStopped: "Not started", ovRecentActivity: "Recent activity",
  acTitle: "Accounts", acAdd: "Add account", acEmpty: "No accounts yet. Import a CSV or add one manually.", acNoProject: "No project", acImport: "Import CSV", acConflicts: "Conflicts",
  fTitle: "Title", fUsername: "Username", fPassword: "Password / key", fUrls: "URLs (one per line)", fNotes: "Notes", fTotp: "2FA secret or otpauth:// link", fProject: "Project", fTags: "Tags (comma-separated)", fKind: "Type",
  keepSecret: "Leave empty to keep the current password", clearSecret: "Remove password", clearTotp: "Remove 2FA",
  kLogin: "Website login", kApiKey: "API key", kDatabase: "Database", kOauth: "OAuth token", kSsh: "SSH key", kNote: "Secure note", kStorage: "Storage credential",
  reveal: "Show raw password", hide: "Hide", autoHide: "Hides automatically in {s} s", copyPassword: "Copy password", copyUsername: "Copy username", copyTotp: "Copy code",
  totpCode: "Code", deleteConfirm: "Delete “{t}”? The deletion syncs to your other devices.",
  genTitle: "Generate password", genLength: "Length", genLower: "Lowercase", genUpper: "Uppercase", genDigits: "Digits", genSymbols: "Symbols", genAmbiguous: "Exclude look-alike characters", genEach: "At least one of each",
  genGenerate: "Generate", genUse: "Use this password", genReady: "Generated a {n}-character password (not shown; copy it or save directly).",
  impTitle: "Import CSV", impRisk: "CSV files are plaintext. Delete the file and empty the trash after importing. The file is read only by the local Rust process and never reaches the UI.",
  impFormat: "Source format", impPick: "Choose a CSV file and import", impResult: "Imported {i}, duplicates {d}, skipped {s}.",
  cfTitle: "Sync conflicts", cfDesc: "Two devices produced different versions. Choose the version that is currently valid; until then the account is not used for autofill or AI access.", cfKeep: "Keep this version", cfCurrent: "Current", cfSecretDiffers: "Password differs",
  reauthTitle: "Re-authenticate", reauthDesc: "Showing raw passwords and exporting require the local unlock password again.", reauthAgentWarn: "If an AI agent can watch or control this computer's screen, do not reveal passwords here.",
  cnTitle: "AI connections", cnHosts: "AI tools on this computer", cnDetect: "Detect again", cnInstalled: "Installed", cnNotInstalled: "Not detected", cnHasEntry: "Configured",
  cnConnect: "Connect", cnRemove: "Remove config", cnPreview: "Configuration preview", cnPreviewDesc: "Only the entry named aipass is added or changed; the original file is backed up first. The configuration contains no passwords or keys.",
  cnApply: "Write configuration", cnApplied: "Written. Backup: {b}", cnScope: "Scope", cnUser: "User", cnProject: "Project", cnProjectDir: "Project directory (absolute path)",
  cnAllowed: "Projects it may access", cnAllProjects: "All projects", cnConnections: "Connected AI apps", cnPairPending: "Waiting for confirmation",
  cnPairCode: "Pairing code", cnPairCompare: "Check that the AI tool shows the same pairing code.", cnApprove: "Confirm", cnDeny: "Deny",
  cnPause: "Pause", cnResume: "Resume", cnRevokeAll: "Stop all access", cnRemoveConn: "Remove connection", cnRemote: "Remote access (ChatGPT, Claude connector)",
  cnRemoteNote: "Remote access goes through the official gateway to your executor. The gateway sees request and result content; it is not an end-to-end blind relay.", cnNoTool: "This host has no tool entry point",
  exTitle: "Executors", exLocal: "This computer", exProtection: "Protection level", exCompatible: "Compatible", exIsolated: "Isolated",
  exCompatibleDesc: "The local executor runs in the same user session as your AI tools: it keeps credentials out of the normal tool chain, but cannot resist arbitrary code, debugging or full takeover by the same user.",
  exIsolatedDesc: "Isolated execution needs a separate host or a verified restricted VM, attested by the server operator; the local executor is not isolated.",
  exSocket: "Bridge endpoint", exResources: "Resources", exAddResource: "Add resource", exPaired: "Paired servers", exPairServer: "Pair a server",
  rAlias: "Resource alias (visible to AI)", rService: "Service", rConnector: "Connector", rEnv: "Environment", rTest: "Test", rProd: "Production", rConfig: "Connector config (JSON, no passwords)", rEntry: "Account holding the credential",
  avTitle: "Activity", avApprovals: "Approvals", avOperations: "Operations", avGrants: "Grants", avAudit: "Audit log", avVerify: "Verify audit chain",
  avAuditOk: "Audit chain intact ({n} events).", avAuditBad: "Audit chain check failed: {r}", avRevoke: "Revoke", avLevels: "Revocation level",
  lvStop: "Stop access", lvEnd: "End sessions", lvUpstream: "Revoke upstream", avReport: "Revocation report",
  apTitle: "Access request", apRequester: "Requester", apVerified: "Identity verified", apUnverified: "Identity not verified", apResource: "Resource", apOperation: "Operation", apData: "Data",
  apExcluded: "Excludes", apScope: "Scope", apLimits: "Limits", apDuration: "Duration", apLocation: "Runs on", apRecipients: "Results go to",
  apAllowOnce: "Allow this time", apNarrow: "Choose narrower access", apDeny: "Deny", apToPhone: "Handle on phone", apConfirmPw: "Local unlock password (required for every approval)", apConfirmPwDesc: "Re-enter the unlock password to approve, so an AI agent that can operate this computer cannot click Approve by itself.", apToPhoneDesc: "If an AI agent can watch or control this computer, handle it on your phone. The request stays until approved, denied or expired.",
  apExpiresIn: "Expires in {s} s", apExpired: "The request expired", apRows: "Up to {n} rows", apMinutes: "Up to {n} minutes", apTask: "This task",
  apRecipientsDefault: "The AI app of this connection and its model provider", apNoAutoApprove: "Nothing is approved automatically if nobody responds.", apUnlockFirst: "Unlock the vault to approve.",
  pTitle: "Add your phone", pModeShow: "Show a QR code on this computer", pModePaste: "Paste the link from your phone",
  pShowDesc: "Use this when the vault is on your phone and this computer should join.", pPasteDesc: "Use this when the vault is on this computer and your phone should join. In the phone app choose “Add this device” and copy the aipass://pair link.",
  pLink: "Pairing link", pStart: "Start pairing", pWaiting: "Waiting for the other device…", pSas: "Check that both devices show the same 6-digit code",
  pSasMatch: "They match — add it", pSasMismatch: "They differ — cancel", pCodeOnOther: "Or type the code shown on the other device", pDone: "Pairing complete.", pFailed: "Pairing failed: {e}",
  pShareStorage: "Also share the storage credential (S3 etc.)", pNoVaultNote: "Scanning alone grants nothing; the code must be confirmed on a trusted device.",
  sTitle: "Settings", sStorage: "Storage & migration", sMigrate: "Migrate to a new location", sMigrateDesc: "The new location is tested, fully copied and verified before switching; the old copy is kept.",
  sCloud: "Cloud account & subscription", sEmail: "E-mail", sPassword: "Password", sLogin: "Sign in", sLogout: "Sign out", sCloudNote: "The subscription account is separate from the vault: its password cannot decrypt any vault. An invalid licence only disables premium features; unlock, export, recovery and revocation keep working.",
  sPlan: "Plan", sLicense: "Licence", sActivate: "Activate on this device", sLicValid: "Valid", sLicInvalid: "Not activated or invalid",
  sExport: "Export", sExportEnc: "Encrypted export (.aipassx)", sExportCsv: "Plaintext CSV export", sExportPassword: "Export file password (10+ characters)",
  sCsvWarn: "A plaintext CSV contains every password. Use it only to move to another tool and delete it right after.",
  sRecovery: "Recovery", sRecoveryVerified: "Recovery key verified", sRecoveryNotVerified: "Recovery material not verified", sReplaceKey: "Replace recovery key",
  sDevices: "Devices", sThisDevice: "This device", sRevokeDevice: "Revoke this device", sRevokeNote: "Revoking rotates the vault key. Passwords the revoked device has seen still need to be changed one by one.",
  sLanguage: "Language", sAbout: "About", sVersion: "Version", sBrowser: "Browser extension", sExtId: "Extension ID", sInstallHost: "Install the local connector",
  sLinkNode: "Link this computer's executor to the cloud account", sLinked: "Linked.", sTunnelStart: "Start remote access", sTunnelStop: "Stop remote access", sTunnelState: "Remote access",
  sAutoLock: "Auto-lock (seconds, 0 = never)", sClipboard: "Clipboard auto-clear (seconds)", sSaved: "Saved.", sRelay: "Relay URL (phone approvals)", sCloudUrl: "Cloud URL",
  exc_push_title: "Phone did not get the notification", exc_push_body: "A missing notification never means the task was approved.", exc_push_next: "Open the phone app to fetch it; start timed-out tasks again.",
  exc_executor_title: "Executor offline", exc_executor_body: "The vault exists, but no online device can execute.", exc_executor_next: "Start this computer's executor or choose a paired server.",
  exc_site_title: "Website changed", exc_site_body: "The automation adapter cannot reliably find the sign-in flow.", exc_site_next: "Take over; this autofill was stopped.",
  exc_signup_title: "Sign-up result uncertain", exc_signup_body: "A candidate account was saved, but the site's result is not confirmed.", exc_signup_next: "Check whether the account exists before trying again.",
  exc_revoke_title: "Revocation partly failed", exc_revoke_body: "Proxy access stopped, but upstream sessions are still pending.", exc_revoke_next: "See which services failed and handle them manually.",
  exc_conflict_title: "Conflicting passwords", exc_conflict_body: "Two devices produced different versions.", exc_conflict_next: "Choose and verify the valid version on a trusted client.",
  exc_recovery_title: "Recovery material not verified", exc_recovery_body: "If this device is lost you may not be able to recover the vault.", exc_recovery_next: "Complete the recovery check.",
  exc_host_title: "This host has no tool entry point", exc_host_body: "This version cannot connect directly.", exc_host_next: "Use a host that supports the standard protocol, or the SDK route.",
  goHandle: "Handle",
};

export type Key = keyof typeof zh;
export const dictionaries: Record<Lang, Dict> = { "zh-CN": zh, en };

export function translate(lang: Lang, key: Key, vars?: Record<string, string | number>): string {
  let s = dictionaries[lang][key] ?? dictionaries["zh-CN"][key] ?? key;
  if (vars) for (const [k, v] of Object.entries(vars)) s = s.split(`{${k}}`).join(String(v));
  return s;
}

/** Pick zh/en from a `{zh, en}` object coming from Rust. */
export function loc(lang: Lang, m: { zh: string; en: string } | undefined | null): string {
  if (!m) return "";
  return lang === "en" ? m.en : m.zh;
}
